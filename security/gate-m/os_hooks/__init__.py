"""os_hooks — optional OS-level filesystem monitoring for GATE-M.

Three monitoring backends, all DISABLED by default.
Enable by importing the specific monitor and calling .start().

  fanotify_monitor  — Linux fanotify FAN_OPEN_PERM (requires CAP_SYS_ADMIN)
  inotify_monitor   — Linux inotify via inotify-simple (no root required)
  ebpf_monitor      — Linux eBPF via BCC (requires kernel ≥ 4.9 + BCC installed)

On Windows or when the underlying kernel facility is unavailable, each monitor
degrades to a no-op stub that logs a warning at import time.

Usage:
    from security.gate_m.os_hooks import get_monitor

    mon = get_monitor("inotify", allowed_paths=["/app/src/"],
                      on_violation=lambda t, p: print(f"VIOLATION {t}: {p}"))
    mon.start()
    # ... agent runs ...
    mon.stop()
"""

from __future__ import annotations

import logging
import sys
from typing import Callable, Optional

logger = logging.getLogger(__name__)

MonitorFactory = Callable[..., object]

_REGISTRY: dict[str, str] = {
    "fanotify": "security.gate_m.os_hooks.fanotify_monitor",
    "inotify":  "security.gate_m.os_hooks.inotify_monitor",
    "ebpf":     "security.gate_m.os_hooks.ebpf_monitor",
}


def get_monitor(
    backend: str,
    allowed_paths: list[str],
    on_violation: Callable[[str, str], None],
    **kwargs: object,
) -> object:
    """
    Factory function. Returns a monitor instance for the named backend.
    Falls back to NullMonitor if the backend is unavailable.
    """
    if sys.platform != "linux":
        logger.warning(
            "os_hooks: backend %r requires Linux — using NullMonitor on %s",
            backend, sys.platform,
        )
        return NullMonitor(backend)

    module_path = _REGISTRY.get(backend)
    if module_path is None:
        raise ValueError(f"Unknown os_hooks backend: {backend!r}. Choose from: {list(_REGISTRY)}")

    try:
        import importlib
        mod = importlib.import_module(module_path)
        return mod.Monitor(  # type: ignore[attr-defined]
            allowed_paths=allowed_paths,
            on_violation=on_violation,
            **kwargs,
        )
    except (ImportError, AttributeError) as exc:
        logger.warning("os_hooks: backend %r unavailable (%s) — using NullMonitor", backend, exc)
        return NullMonitor(backend)


class NullMonitor:
    """No-op stub used when the real monitor is unavailable."""

    def __init__(self, backend: str) -> None:
        self.backend = backend

    def start(self) -> None:
        logger.debug("NullMonitor(%s).start() — no-op", self.backend)

    def stop(self) -> None:
        logger.debug("NullMonitor(%s).stop() — no-op", self.backend)

    @property
    def is_running(self) -> bool:
        return False
