"""Host resource monitoring via psutil.

With ``pid: host`` and the host ``/proc`` mounted, psutil reports host-wide
CPU/memory/processes. Network counters are read from the host ``/proc/net/dev``
when available so rates reflect the real machine, not the container.
"""
from __future__ import annotations

import os
import time

import psutil

from ..config import settings

_prev_net: dict[str, float] | None = None  # {ts, sent, recv}


def _host_net_bytes() -> tuple[int, int] | None:
    """Total bytes (sent, recv) across host interfaces from /host/proc/net/dev."""
    path = os.path.join(settings.host_proc, "net", "dev")
    if not os.path.exists(path):
        return None
    sent = recv = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh.readlines()[2:]:
                iface, _, data = line.partition(":")
                iface = iface.strip()
                if iface in ("lo", ""):
                    continue
                fields = data.split()
                if len(fields) >= 9:
                    recv += int(fields[0])
                    sent += int(fields[8])
        return sent, recv
    except (OSError, ValueError):
        return None


def sample() -> dict:
    """Return a single point-in-time snapshot of host resource usage."""
    global _prev_net

    cpu = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage(settings.host_root if os.path.isdir(settings.host_root) else "/")
    try:
        load1 = os.getloadavg()[0]
    except (OSError, AttributeError):
        load1 = 0.0

    # Network rate
    now = time.time()
    net = _host_net_bytes()
    if net is None:
        io = psutil.net_io_counters()
        net = (io.bytes_sent, io.bytes_recv)
    sent_bps = recv_bps = 0.0
    if _prev_net is not None:
        dt = max(now - _prev_net["ts"], 1e-6)
        sent_bps = max(0.0, (net[0] - _prev_net["sent"]) / dt)
        recv_bps = max(0.0, (net[1] - _prev_net["recv"]) / dt)
    _prev_net = {"ts": now, "sent": net[0], "recv": net[1]}

    return {
        "cpu_percent": round(cpu, 1),
        "mem_percent": round(vm.percent, 1),
        "swap_percent": round(swap.percent, 1),
        "disk_percent": round(disk.percent, 1),
        "load1": round(load1, 2),
        "net_sent_bps": round(sent_bps, 1),
        "net_recv_bps": round(recv_bps, 1),
        "process_count": len(psutil.pids()),
    }


def cpu_count() -> int:
    return psutil.cpu_count(logical=True) or 1


def detailed() -> dict:
    """Richer snapshot for the system tab (per-core, memory breakdown, etc.)."""
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append(
                {
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "percent": usage.percent,
                    "total_gb": round(usage.total / 1e9, 1),
                    "used_gb": round(usage.used / 1e9, 1),
                }
            )
        except (PermissionError, OSError):
            continue

    boot = psutil.boot_time()
    return {
        "cpu_percent_per_core": psutil.cpu_percent(interval=0.3, percpu=True),
        "cpu_count": cpu_count(),
        "memory": {
            "total_gb": round(vm.total / 1e9, 2),
            "used_gb": round(vm.used / 1e9, 2),
            "available_gb": round(vm.available / 1e9, 2),
            "percent": vm.percent,
        },
        "swap": {"total_gb": round(swap.total / 1e9, 2), "percent": swap.percent},
        "disks": disks,
        "boot_time": boot,
        "uptime_seconds": int(time.time() - boot),
    }


def top_processes(limit: int = 15) -> list[dict]:
    """Top processes by CPU then memory."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            procs.append(
                {
                    "pid": info["pid"],
                    "name": info["name"] or "?",
                    "user": info["username"] or "?",
                    "cpu": round(info["cpu_percent"] or 0.0, 1),
                    "mem": round(info["memory_percent"] or 0.0, 1),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: (x["cpu"], x["mem"]), reverse=True)
    return procs[:limit]
