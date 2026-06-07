"""APT package / update management."""
from __future__ import annotations

import re

from . import runner


def update_index() -> runner.CommandResult:
    return runner.run_control(["apt-get", "update"], timeout=180)


def upgradable() -> dict:
    res = runner.run_host_read(["apt", "list", "--upgradable"], timeout=60)
    if not res.success:
        return {"available": False, "count": 0, "security_count": 0, "packages": []}
    pkgs = []
    security = 0
    for line in res.output.splitlines():
        if "/" not in line or line.startswith("Listing"):
            continue
        name = line.split("/")[0]
        is_sec = "security" in line.lower()
        if is_sec:
            security += 1
        pkgs.append({"name": name, "security": is_sec})
    return {
        "available": True,
        "count": len(pkgs),
        "security_count": security,
        "packages": pkgs[:200],
    }


def upgrade_security_only() -> runner.CommandResult:
    """Apply security updates non-interactively via unattended-upgrade."""
    return runner.run_control(["unattended-upgrade", "-v"], timeout=1800)


def upgrade_all() -> runner.CommandResult:
    return runner.run_control(
        ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"],
        timeout=1800,
    )


def reboot_required() -> bool:
    # The host file is visible under the mounted root, checked by the runner host read.
    res = runner.run_host_read(["uname", "-r"])
    return bool(res.success) and False  # placeholder; real flag read in router via host fs
