"""fail2ban integration — jails, banned IPs, ban/unban."""
from __future__ import annotations

import re

from . import runner


def available() -> bool:
    return runner.run_host_read(["fail2ban-client", "ping"]).success


def jails() -> list[str]:
    res = runner.run_host_read(["fail2ban-client", "status"])
    if not res.success:
        return []
    m = re.search(r"Jail list:\s*(.+)", res.output)
    if not m:
        return []
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def jail_status(jail: str) -> dict:
    if not re.match(r"^[\w\-]+$", jail):
        return {"error": "invalid jail name"}
    res = runner.run_host_read(["fail2ban-client", "status", jail])
    if not res.success:
        return {"error": res.error}
    out = res.output
    banned = []
    total_failed = total_banned = 0
    m = re.search(r"Banned IP list:\s*(.*)", out)
    if m:
        banned = [ip for ip in m.group(1).split() if ip]
    mf = re.search(r"Total failed:\s*(\d+)", out)
    mb = re.search(r"Total banned:\s*(\d+)", out)
    if mf:
        total_failed = int(mf.group(1))
    if mb:
        total_banned = int(mb.group(1))
    return {
        "jail": jail,
        "banned_ips": banned,
        "currently_banned": len(banned),
        "total_failed": total_failed,
        "total_banned": total_banned,
    }


def overview() -> dict:
    if not available():
        return {"available": False, "jails": []}
    data = [jail_status(j) for j in jails()]
    return {"available": True, "jails": data}


def ban(jail: str, ip: str) -> runner.CommandResult:
    if not re.match(r"^[\w\-]+$", jail) or not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return runner.CommandResult(False, error="invalid jail or ip")
    return runner.run_control(["fail2ban-client", "set", jail, "banip", ip])


def unban(jail: str, ip: str) -> runner.CommandResult:
    if not re.match(r"^[\w\-]+$", jail) or not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return runner.CommandResult(False, error="invalid jail or ip")
    return runner.run_control(["fail2ban-client", "set", jail, "unbanip", ip])
