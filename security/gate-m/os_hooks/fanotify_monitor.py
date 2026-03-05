"""fanotify_monitor.py — Linux fanotify FAN_OPEN_PERM filesystem monitor.

Uses fanotify(2) with FAN_OPEN_PERM to intercept filesystem opens BEFORE
they succeed in the kernel.  When an AI agent process attempts to open a
file outside the allowed scope, the kernel holds the open() syscall until
this process returns FAN_ALLOW or FAN_DENY.

Requirements:
  - Linux kernel ≥ 2.6.36
  - CAP_SYS_ADMIN capability (or run as root)
  - Python cffi or ctypes (stdlib)

If requirements are not met, Monitor degrades to NullMonitor behaviour
and logs a clear warning — it does NOT raise at import time.

Design:
  The monitor runs a background thread that reads fanotify events.
  Per-event verdict logic:
    1. Is the path inside allowed_paths?         → FAN_ALLOW
    2. Is it a write to a path outside scope?    → FAN_DENY + on_violation callback
    3. Read of a forbidden path?                 → FAN_DENY + on_violation callback
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import struct
import threading
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# fanotify constants (from linux/fanotify.h)
# ---------------------------------------------------------------------------
FAN_CLASS_CONTENT     = 0x00000004
FAN_CLOEXEC           = 0x00000001
FAN_NONBLOCK          = 0x00000002
FAN_OPEN_PERM         = 0x00010000
FAN_ACCESS_PERM       = 0x00020000
FAN_ALLOW             = 0x01
FAN_DENY              = 0x02
FAN_MARK_ADD          = 0x00000001
FAN_MARK_FILESYSTEM   = 0x00000100
AT_FDCWD              = -100

# fanotify_event_metadata layout (fixed-size kernel struct)
# struct fanotify_event_metadata {
#   __u32 event_len;
#   __u8  vers;
#   __u8  reserved;
#   __u16 metadata_len;
#   __aligned_u64 mask;
#   __s32 fd;
#   __s32 pid;
# };
_META_FMT  = "=IbbHqii"
_META_SIZE = struct.calcsize(_META_FMT)

# fanotify_response
_RESP_FMT  = "=ii"
_RESP_SIZE = struct.calcsize(_RESP_FMT)


def _libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c")
    return ctypes.CDLL(name, use_errno=True)


def _fanotify_init(flags: int, event_f_flags: int) -> int:
    """Wrapper around fanotify_init(2) syscall via libc."""
    libc = _libc()
    # syscall number 300 on x86_64 for fanotify_init
    result = libc.syscall(300, ctypes.c_uint(flags), ctypes.c_uint(event_f_flags))
    if result < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return result


def _fanotify_mark(fd: int, flags: int, mask: int, dirfd: int, pathname: str) -> int:
    libc = _libc()
    # syscall 301 on x86_64
    result = libc.syscall(
        301,
        ctypes.c_int(fd),
        ctypes.c_uint(flags),
        ctypes.c_ulonglong(mask),
        ctypes.c_int(dirfd),
        ctypes.c_char_p(pathname.encode()),
    )
    if result < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return result


def _resolve_fd_path(event_fd: int) -> str:
    """Resolve /proc/self/fd/<n> to the real path."""
    try:
        return os.readlink(f"/proc/self/fd/{event_fd}")
    except OSError:
        return f"<unknown fd={event_fd}>"


class Monitor:
    """
    fanotify FAN_OPEN_PERM monitor.

    Args:
        allowed_paths:  List of directory prefixes that are permitted.
        on_violation:   Callback(violation_type, path) triggered on deny.
        watch_path:     Filesystem root to watch (default: "/").
    """

    def __init__(
        self,
        allowed_paths: list[str],
        on_violation: Callable[[str, str], None],
        watch_path: str = "/",
    ) -> None:
        self._allowed = [str(Path(p).resolve()) for p in allowed_paths]
        self._on_violation = on_violation
        self._watch_path = watch_path
        self._fan_fd: int = -1
        self._thread: threading.Thread | None = None
        self._running = False
        self._available = False
        self._check_availability()

    def _check_availability(self) -> None:
        if os.getuid() != 0:
            logger.warning(
                "fanotify_monitor: requires root / CAP_SYS_ADMIN — monitor disabled. "
                "Consider using inotify_monitor for unprivileged monitoring."
            )
            return
        try:
            # Test that fanotify_init works
            fd = _fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY)
            os.close(fd)
            self._available = True
        except (OSError, AttributeError) as exc:
            logger.warning("fanotify_monitor: fanotify_init failed (%s) — monitor disabled", exc)

    def start(self) -> None:
        if not self._available:
            logger.warning("fanotify_monitor: start() called but monitor is disabled — no-op")
            return

        self._fan_fd = _fanotify_init(
            FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
            os.O_RDONLY | os.O_LARGEFILE,
        )
        _fanotify_mark(
            self._fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            FAN_OPEN_PERM | FAN_ACCESS_PERM,
            AT_FDCWD,
            self._watch_path,
        )
        self._running = True
        self._thread = threading.Thread(target=self._event_loop, daemon=True, name="gate-m.fanotify")
        self._thread.start()
        logger.info("fanotify_monitor: started watching %s", self._watch_path)

    def stop(self) -> None:
        self._running = False
        if self._fan_fd >= 0:
            try:
                os.close(self._fan_fd)
            except OSError:
                pass
            self._fan_fd = -1
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("fanotify_monitor: stopped")

    @property
    def is_running(self) -> bool:
        return self._running and self._available

    def _event_loop(self) -> None:
        while self._running:
            try:
                raw = os.read(self._fan_fd, 4096)
            except BlockingIOError:
                continue
            except OSError:
                break

            offset = 0
            while offset + _META_SIZE <= len(raw):
                fields = struct.unpack_from(_META_FMT, raw, offset)
                event_len, vers, _, meta_len, mask, event_fd, pid = fields
                offset += max(event_len, _META_SIZE)

                if event_fd < 0:
                    continue

                path = _resolve_fd_path(event_fd)
                verdict = self._evaluate(path, mask)

                # Send verdict back to kernel
                try:
                    resp = struct.pack(_RESP_FMT, event_fd, verdict)
                    os.write(self._fan_fd, resp)
                except OSError:
                    pass
                finally:
                    try:
                        os.close(event_fd)
                    except OSError:
                        pass

    def _evaluate(self, path: str, mask: int) -> int:
        """Return FAN_ALLOW or FAN_DENY for this path+mask combination."""
        is_write = bool(mask & FAN_OPEN_PERM)
        allowed = any(path.startswith(p) for p in self._allowed)

        if not allowed:
            vtype = "fanotify_write_denied" if is_write else "fanotify_read_denied"
            self._on_violation(vtype, path)
            return FAN_DENY

        return FAN_ALLOW
