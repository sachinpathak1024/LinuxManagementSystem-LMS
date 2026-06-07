"""UFW (Uncomplicated Firewall) integration."""
from __future__ import annotations

import re

from . import runner


def status() -> dict:
    """Parse `ufw status verbose` into a structured object."""
    res = runner.run_host_read(["ufw", "status", "verbose"])
    if not res.success:
        return {"enabled": False, "available": False, "error": res.error, "rules": []}

    text = res.output
    enabled = "Status: active" in text
    default = ""
    m = re.search(r"Default:\s*(.+)", text)
    if m:
        default = m.group(1).strip()

    rules = []
    in_rules = False
    for line in text.splitlines():
        if line.startswith("To") and "Action" in line:
            in_rules = True
            continue
        if in_rules and line.strip() and not line.startswith("--"):
            # Columns are whitespace-separated: To  Action  From
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 3:
                rules.append({"to": parts[0], "action": parts[1], "from": parts[2]})
    return {"enabled": enabled, "available": True, "default": default, "rules": rules}


def enable() -> runner.CommandResult:
    return runner.run_control(["ufw", "--force", "enable"])


def disable() -> runner.CommandResult:
    return runner.run_control(["ufw", "disable"])


def reload() -> runner.CommandResult:
    return runner.run_control(["ufw", "reload"])


def set_default_deny() -> runner.CommandResult:
    return runner.run_control(["ufw", "default", "deny", "incoming"])


def add_rule(
    port: int,
    protocol: str = "tcp",
    action: str = "allow",
    from_ip: str | None = None,
    comment: str | None = None,
) -> runner.CommandResult:
    if action not in ("allow", "deny", "reject", "limit"):
        return runner.CommandResult(False, error="invalid action")
    if protocol not in ("tcp", "udp"):
        return runner.CommandResult(False, error="invalid protocol")
    if not (0 < port < 65536):
        return runner.CommandResult(False, error="invalid port")

    cmd = ["ufw", action]
    if from_ip:
        # validate it loosely (IP or CIDR)
        if not re.match(r"^[0-9a-fA-F:.\/]+$", from_ip):
            return runner.CommandResult(False, error="invalid source address")
        cmd += ["from", from_ip, "to", "any", "port", str(port), "proto", protocol]
    else:
        cmd += [f"{port}/{protocol}"]
    if comment:
        safe = re.sub(r"[^\w .\-]", "", comment)[:64]
        cmd += ["comment", safe]
    return runner.run_control(cmd)


def delete_rule(number: int) -> runner.CommandResult:
    return runner.run_control(["ufw", "--force", "delete", str(int(number))])
