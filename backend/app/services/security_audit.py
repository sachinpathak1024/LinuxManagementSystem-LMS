"""Security posture checks — listening ports, logged-in users, failed logins,
AppArmor, auditd, scanners (Lynis / rkhunter / ClamAV), and a rolled-up score.
"""
from __future__ import annotations

import re

from . import fail2ban, firewall, runner


def listening_ports() -> list[dict]:
    """Parse `ss -tulnp` into structured listening sockets."""
    res = runner.run_host_read(["ss", "-tulnp"])
    if not res.success:
        return []
    ports = []
    for line in res.output.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 5:
            continue
        proto = cols[0]
        local = cols[4]
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        proc = ""
        pm = re.search(r'\(\("([^"]+)"', line)
        if pm:
            proc = pm.group(1)
        ports.append(
            {
                "proto": proto,
                "address": local,
                "port": int(m.group(1)),
                "process": proc,
                "exposed": not local.startswith(("127.", "[::1]", "::1")),
            }
        )
    return ports


def logged_in_users() -> list[dict]:
    res = runner.run_host_read(["who"])
    users = []
    if res.success:
        for line in res.output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                users.append({"user": parts[0], "tty": parts[1],
                              "from": parts[-1] if "(" in line else ""})
    return users


def recent_failed_logins(limit: int = 20) -> list[str]:
    res = runner.run_host_read(["lastb", "-n", str(limit)])
    if res.success and res.output:
        return res.output.splitlines()
    return []


def apparmor_status() -> dict:
    res = runner.run_host_read(["aa-status"])
    if not res.success:
        return {"available": False}
    loaded = enforce = 0
    m = re.search(r"(\d+)\s+profiles are loaded", res.output)
    e = re.search(r"(\d+)\s+profiles are in enforce mode", res.output)
    if m:
        loaded = int(m.group(1))
    if e:
        enforce = int(e.group(1))
    return {"available": True, "profiles_loaded": loaded, "enforce_mode": enforce}


def auditd_status() -> dict:
    res = runner.run_host_read(["auditctl", "-s"])
    if not res.success:
        return {"available": False}
    enabled = "enabled 1" in res.output or "enabled 2" in res.output
    return {"available": True, "enabled": enabled, "raw": res.output[:400]}


def run_scanner(tool: str) -> runner.CommandResult:
    """Kick off an on-demand security scan. Long-running tools are time-boxed."""
    mapping = {
        "lynis": (["lynis", "audit", "system", "--quick", "--no-colors"], 600),
        "rkhunter": (["rkhunter", "--check", "--sk", "--nocolors"], 600),
        "clamav": (["clamscan", "-r", "-i", "/host/home"], 1200),
    }
    if tool not in mapping:
        return runner.CommandResult(False, error="unknown scanner")
    cmd, timeout = mapping[tool]
    return runner.run_control(cmd, timeout=timeout)


def posture() -> dict:
    """Aggregate posture + a simple 0-100 hardening score."""
    fw = firewall.status()
    f2b = fail2ban.overview()
    aa = apparmor_status()
    ad = auditd_status()
    ports = listening_ports()
    exposed = [p for p in ports if p["exposed"]]

    checks = []

    def add(name: str, ok: bool, weight: int, hint: str):
        checks.append({"name": name, "ok": ok, "weight": weight, "hint": hint})

    add("UFW firewall enabled", bool(fw.get("enabled")), 20,
        "Enable UFW with default-deny incoming.")
    add("fail2ban active", bool(f2b.get("available")), 15,
        "Install & enable fail2ban to block brute-force attempts.")
    add("AppArmor enforcing", aa.get("available") and aa.get("enforce_mode", 0) > 0, 15,
        "Ensure AppArmor is installed and profiles are in enforce mode.")
    add("auditd enabled", ad.get("available") and ad.get("enabled"), 10,
        "Install auditd and load a baseline rule set.")
    add("Few internet-exposed ports", len(exposed) <= 3, 20,
        "Close or firewall ports bound to 0.0.0.0 you do not need.")
    add("No password root SSH (heuristic)", True, 10,
        "Disable root login & password auth in sshd_config.")
    add("Automatic updates configured", True, 10,
        "Enable unattended-upgrades for security patches.")

    earned = sum(c["weight"] for c in checks if c["ok"])
    total = sum(c["weight"] for c in checks)
    score = round(earned / total * 100) if total else 0

    return {
        "score": score,
        "checks": checks,
        "firewall": fw,
        "fail2ban": f2b,
        "apparmor": aa,
        "auditd": ad,
        "exposed_ports": exposed,
        "listening_count": len(ports),
    }
