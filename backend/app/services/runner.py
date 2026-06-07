"""Safe command execution.

Two concerns are handled here:

1. *Whether* host control is even allowed (ALLOW_HOST_COMMANDS). When false,
   every control call returns a clear "disabled" result instead of running.

2. *How* a command reaches the host. When running as a privileged container
   with ``pid: host`` we wrap commands in ``nsenter`` so they execute in the
   host's namespaces (so ``ufw``/``systemctl`` affect the host, not the
   container). Read-only inspection commands run directly.

An allow-list of executables is enforced — Sentinel never runs an arbitrary
string from the network. Arguments are passed as a list (no shell), so there
is no shell-injection surface.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from ..config import settings

# Executables Sentinel is permitted to invoke. Anything else is refused.
ALLOWED_BINARIES = {
    "ufw",
    "fail2ban-client",
    "systemctl",
    "journalctl",
    "apt-get",
    "apt",
    "unattended-upgrade",
    "lynis",
    "rkhunter",
    "clamscan",
    "freshclam",
    "aa-status",
    "auditctl",
    "ausearch",
    "ss",
    "who",
    "last",
    "lastb",
    "uname",
    "uptime",
}


@dataclass
class CommandResult:
    success: bool
    output: str = ""
    error: str = ""
    returncode: int = 0


def _wrap_for_host(cmd: list[str]) -> list[str]:
    """Prefix a command so it runs in the host namespaces when appropriate."""
    if settings.use_nsenter and shutil.which("nsenter"):
        # Enter the mount/uts/ipc/net/pid namespaces of host PID 1.
        return ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", *cmd]
    return cmd


def run_read(cmd: list[str], timeout: int = 20) -> CommandResult:
    """Run a read-only inspection command (no host-control gate)."""
    return _run(cmd, timeout=timeout, host=False)


def run_host_read(cmd: list[str], timeout: int = 20) -> CommandResult:
    """Run a read-only command that must observe host state (e.g. ufw status)."""
    return _run(cmd, timeout=timeout, host=True)


def run_control(cmd: list[str], timeout: int = 60) -> CommandResult:
    """Run a state-changing host command. Gated by ALLOW_HOST_COMMANDS."""
    if not settings.allow_host_commands:
        return CommandResult(
            success=False,
            error=(
                "Host control is disabled. Set ALLOW_HOST_COMMANDS=true and run "
                "the backend privileged (see docs/SECURITY.md) to enable."
            ),
            returncode=126,
        )
    return _run(cmd, timeout=timeout, host=True)


def _run(cmd: list[str], timeout: int, host: bool) -> CommandResult:
    if not cmd:
        return CommandResult(False, error="empty command", returncode=2)
    if cmd[0] not in ALLOWED_BINARIES:
        return CommandResult(
            False, error=f"binary '{cmd[0]}' is not in the allow-list", returncode=126
        )

    final = _wrap_for_host(cmd) if host else cmd
    try:
        proc = subprocess.run(
            final,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            success=proc.returncode == 0,
            output=proc.stdout.strip(),
            error=proc.stderr.strip(),
            returncode=proc.returncode,
        )
    except FileNotFoundError:
        return CommandResult(
            False,
            error=f"'{cmd[0]}' not found. Is the host tool installed / is the "
            "container privileged with pid:host?",
            returncode=127,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(False, error="command timed out", returncode=124)
    except Exception as exc:  # noqa: BLE001 - surface any runner failure safely
        return CommandResult(False, error=str(exc), returncode=1)
