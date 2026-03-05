"""inotify_monitor.py — Linux inotify filesystem monitor for GATE-M.

Uses inotify-simple (no root required) to watch for filesystem writes by
AI agent processes.  Unlike fanotify, inotify is POST-HOC — it cannot
prevent a write, but it can immediately detect and report it, triggering
a GATEKernel rollback.

Requirements:
  - Linux kernel ≥ 2.6.13
  - inotify-simple Python package: pip install inotify-simple

When inotify-simple is not installed, Monitor degrades to a sys.addaudithook
based in-process watcher (catches Python-level opens only).

Events monitored:
  IN_CREATE    — new file created under watched directory
  IN_MODIFY    — existing file modified  
  IN_MOVED_TO  — file moved into watched directory
  IN_DELETE    — file deleted (for must_not_change enforcement)
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

# inotify event flags
_IN_CREATE    = 0x00000100
_IN_MODIFY    = 0x00000002
_IN_MOVED_TO  = 0x00000080
_IN_DELETE    = 0x00000200
_IN_CLOSE_WRITE = 0x00000008
_WATCH_MASK   = _IN_CREATE | _IN_MODIFY | _IN_MOVED_TO | _IN_DELETE | _IN_CLOSE_WRITE

try:
    import inotify_simple  # type: ignore
    _INOTIFY_AVAILABLE = True
except ImportError:
    _INOTIFY_AVAILABLE = False
    logger.warning(
        "inotify_monitor: inotify-simple not installed. "
        "Falling back to sys.addaudithook (in-process only). "
        "Install with: pip install inotify-simple"
    )


class Monitor:
    """
    inotify-based filesystem monitor.

    Args:
        allowed_paths:       List of directory paths that are permitted.
        on_violation:        Callback(violation_type: str, path: str).
        watch_dirs:          Extra directories to watch beyond allowed_paths.
        protected_files:     Specific files that must not be modified or deleted.
        recursive:           Watch subdirectories too (default: True).
    """

    def __init__(
        self,
        allowed_paths: list[str],
        on_violation: Callable[[str, str], None],
        watch_dirs: list[str] | None = None,
        protected_files: list[str] | None = None,
        recursive: bool = True,
    ) -> None:
        self._allowed = {str(Path(p).resolve()) for p in allowed_paths}
        self._on_violation = on_violation
        self._protected = {str(Path(f).resolve()) for f in (protected_files or [])}
        self._recursive = recursive
        self._watch_dirs = list(watch_dirs or allowed_paths)
        self._running = False
        self._thread: threading.Thread | None = None
        self._inotify: object | None = None
        self._wd_to_path: dict[int, str] = {}

    def start(self) -> None:
        if not _INOTIFY_AVAILABLE:
            logger.warning(
                "inotify_monitor: inotify-simple unavailable — "
                "falling back to audit hook (in-process coverage only)"
            )
            self._install_audit_hook()
            self._running = True
            return

        self._inotify = inotify_simple.INotify()  # type: ignore
        for directory in self._watch_dirs:
            self._add_watch_recursive(directory) if self._recursive else self._add_watch(directory)

        self._running = True
        self._thread = threading.Thread(target=self._event_loop, daemon=True, name="gate-m.inotify")
        self._thread.start()
        logger.info("inotify_monitor: started watching %s", self._watch_dirs)

    def stop(self) -> None:
        self._running = False
        if self._inotify is not None:
            try:
                self._inotify.close()  # type: ignore
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("inotify_monitor: stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── inotify helpers ──────────────────────────────────────────────────

    def _add_watch(self, directory: str) -> None:
        if not os.path.isdir(directory):
            return
        wd = self._inotify.add_watch(directory, _WATCH_MASK)  # type: ignore
        self._wd_to_path[wd] = directory

    def _add_watch_recursive(self, root: str) -> None:
        self._add_watch(root)
        if not os.path.isdir(root):
            return
        for dirpath, dirnames, _ in os.walk(root):
            for d in dirnames:
                self._add_watch(os.path.join(dirpath, d))

    def _event_loop(self) -> None:
        while self._running:
            try:
                events = self._inotify.read(timeout=500)  # type: ignore
            except Exception:
                break

            for event in events:
                if not event.name:
                    continue
                parent_dir = self._wd_to_path.get(event.wd, "")
                full_path = os.path.join(parent_dir, event.name)
                abs_path  = str(Path(full_path).resolve())
                self._evaluate(abs_path, event.mask)

    def _evaluate(self, abs_path: str, mask: int) -> None:
        # Protected file deleted or modified
        if abs_path in self._protected:
            if mask & (_IN_DELETE | _IN_MODIFY | _IN_CLOSE_WRITE):
                self._on_violation("inotify_protected_file_tampered", abs_path)
            return

        # Write to path outside allowed scope
        in_scope = any(abs_path.startswith(a) for a in self._allowed)
        if not in_scope and (mask & (_IN_CREATE | _IN_MODIFY | _IN_MOVED_TO | _IN_CLOSE_WRITE)):
            self._on_violation("inotify_out_of_scope_write", abs_path)

    # ── Audit hook fallback (in-process, no root, no inotify-simple) ────

    def _install_audit_hook(self) -> None:
        allowed = self._allowed
        protected = self._protected
        on_violation = self._on_violation

        def _hook(event: str, args: tuple) -> None:
            if event not in ("open", "builtins.open"):
                return
            try:
                path_arg = str(args[0]) if args else ""
                flags = args[1] if len(args) > 1 else 0
                abs_path = str(Path(path_arg).resolve()) if path_arg else ""

                if not abs_path:
                    return

                # Check protected files
                if abs_path in protected:
                    is_write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
                    if is_write:
                        on_violation("audit_hook_protected_file_write", abs_path)
                    return

                # Check scope
                in_scope = any(abs_path.startswith(a) for a in allowed)
                if not in_scope:
                    is_write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
                    if is_write:
                        on_violation("audit_hook_out_of_scope_write", abs_path)
            except Exception:
                pass

        sys.addaudithook(_hook)
        logger.info("inotify_monitor: audit hook installed (in-process coverage only)")
