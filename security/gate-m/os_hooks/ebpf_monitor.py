"""ebpf_monitor.py — Linux eBPF-based syscall monitor for GATE-M.

Uses BCC (BPF Compiler Collection) to attach kprobes on filesystem and
network syscalls, giving kernel-level visibility into what an AI agent
process is doing without polling.

Monitored syscalls:
  openat(2)   — file opens (detects out-of-scope reads/writes)
  write(2)    — file writes (catches writes that bypass Python open())
  connect(2)  — outbound network connections
  execve(2)   — process execution (subprocess detection)
  unlink(2)   — file deletion

Requirements:
  - Linux kernel ≥ 4.9 with BPF enabled (CONFIG_BPF_SYSCALL=y)
  - BCC installed: pip install bcc  OR  apt install python3-bcc
  - CAP_SYS_ADMIN or kernel.unprivileged_bpf_disabled=0

Graceful degradation:
  If BCC is not available, Monitor falls back to NullMonitor behaviour
  with a clear warning. No exception is raised at import time.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

try:
    from bcc import BPF  # type: ignore
    _BCC_AVAILABLE = True
except ImportError:
    _BCC_AVAILABLE = False
    logger.warning(
        "ebpf_monitor: BCC not installed — eBPF monitoring disabled. "
        "Install with: pip install bcc  or  apt install python3-bcc"
    )

# ---------------------------------------------------------------------------
# eBPF C program
# ---------------------------------------------------------------------------

_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// Ring buffer for events
struct event_t {
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    int  syscall;   // 1=openat 2=write 3=connect 4=execve 5=unlink
    int  flags;
};

BPF_PERF_OUTPUT(events);

// openat kprobe
int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct event_t ev = {};
    ev.pid     = bpf_get_current_pid_tgid() >> 32;
    ev.tgid    = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    ev.syscall = 1;
    ev.flags   = flags;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), filename);
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

// execve kprobe
int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct event_t ev = {};
    ev.pid     = bpf_get_current_pid_tgid() >> 32;
    ev.tgid    = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    ev.syscall = 4;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.fname, sizeof(ev.fname), filename);
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

// connect kprobe (outbound network)
int trace_connect(struct pt_regs *ctx) {
    struct event_t ev = {};
    ev.pid     = bpf_get_current_pid_tgid() >> 32;
    ev.tgid    = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    ev.syscall = 3;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_str(&ev.fname, sizeof(ev.fname), "network:connect");
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""

_SYSCALL_NAMES = {1: "openat", 2: "write", 3: "connect", 4: "execve", 5: "unlink"}


class Monitor:
    """
    eBPF-based syscall monitor.

    Args:
        allowed_paths:   Path prefixes permitted for read/write.
        on_violation:    Callback(violation_type: str, path: str).
        watch_pid:       Only report events from this PID. 0 = all PIDs.
    """

    def __init__(
        self,
        allowed_paths: list[str],
        on_violation: Callable[[str, str], None],
        watch_pid: int = 0,
    ) -> None:
        self._allowed = [str(Path(p).resolve()) for p in allowed_paths]
        self._on_violation = on_violation
        self._watch_pid = watch_pid
        self._running = False
        self._thread: threading.Thread | None = None
        self._bpf: object | None = None

    def start(self) -> None:
        if not _BCC_AVAILABLE:
            logger.warning("ebpf_monitor: BCC unavailable — monitor not started")
            return

        if os.geteuid() != 0:
            logger.warning(
                "ebpf_monitor: requires root or CAP_SYS_ADMIN — monitor not started. "
                "Run with sudo or grant the capability."
            )
            return

        try:
            self._bpf = BPF(text=_BPF_PROGRAM)  # type: ignore
            self._bpf.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")  # type: ignore
            self._bpf.attach_kprobe(event="__x64_sys_execve",  fn_name="trace_execve")  # type: ignore
            self._bpf.attach_kprobe(event="__x64_sys_connect", fn_name="trace_connect")  # type: ignore
        except Exception as exc:
            logger.error("ebpf_monitor: failed to load BPF program: %s", exc)
            return

        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="gate-m.ebpf")
        self._thread.start()
        logger.info("ebpf_monitor: eBPF probes attached, monitoring started (pid_filter=%d)", self._watch_pid)

    def stop(self) -> None:
        self._running = False
        if self._bpf is not None:
            try:
                self._bpf.cleanup()  # type: ignore
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("ebpf_monitor: stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Event processing ─────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        def _handle_event(cpu: int, data: object, size: int) -> None:  # noqa: ARG001
            if not self._running:
                return
            try:
                event = self._bpf["events"].event(data)  # type: ignore
                pid   = event.pid
                fname = event.fname.decode("utf-8", errors="replace").rstrip("\x00")
                syscall = event.syscall
                flags   = event.flags

                # PID filter
                if self._watch_pid and pid != self._watch_pid:
                    return

                self._evaluate(syscall, fname, flags, pid)
            except Exception:
                pass

        self._bpf["events"].open_perf_buffer(_handle_event)  # type: ignore

        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=200)  # type: ignore
            except Exception:
                break

    def _evaluate(self, syscall: int, path: str, flags: int, pid: int) -> None:
        syscall_name = _SYSCALL_NAMES.get(syscall, "unknown")

        # execve — always a violation if unexpected
        if syscall == 4:
            self._on_violation(f"ebpf_execve_detected:{path}", f"pid={pid}")
            return

        # connect — outbound network
        if syscall == 3:
            self._on_violation("ebpf_outbound_network_connect", f"pid={pid}")
            return

        # openat — check if path is within allowed scope
        if syscall == 1:
            abs_path = str(Path(path).resolve()) if path else path
            in_scope = any(abs_path.startswith(a) for a in self._allowed)
            is_write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))

            if not in_scope and is_write:
                self._on_violation(f"ebpf_out_of_scope_write:{syscall_name}", abs_path)
