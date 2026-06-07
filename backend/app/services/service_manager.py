"""systemd service inspection & control for key host services."""
from __future__ import annotations

import re

from . import runner

# Services Sentinel is allowed to inspect/control (security-relevant set).
MANAGED = [
    "ufw",
    "fail2ban",
    "ssh",
    "sshd",
    "auditd",
    "apparmor",
    "unattended-upgrades",
    "clamav-daemon",
    "cron",
    "systemd-journald",
    "docker",
]


def _is_active(name: str) -> str:
    res = runner.run_host_read(["systemctl", "is-active", name])
    return res.output.strip() or res.error.strip() or "unknown"


def _is_enabled(name: str) -> str:
    res = runner.run_host_read(["systemctl", "is-enabled", name])
    return res.output.strip() or "disabled"


def overview() -> list[dict]:
    out = []
    for name in MANAGED:
        active = _is_active(name)
        if active in ("unknown",) and "could not be found" in active.lower():
            continue
        out.append(
            {
                "name": name,
                "active": active,
                "enabled": _is_enabled(name),
                "running": active == "active",
            }
        )
    return out


def control(name: str, action: str) -> runner.CommandResult:
    if name not in MANAGED:
        return runner.CommandResult(False, error=f"'{name}' is not a managed service")
    if action not in ("start", "stop", "restart", "enable", "disable"):
        return runner.CommandResult(False, error="invalid action")
    if not re.match(r"^[\w@.\-]+$", name):
        return runner.CommandResult(False, error="invalid service name")
    return runner.run_control(["systemctl", action, name])
