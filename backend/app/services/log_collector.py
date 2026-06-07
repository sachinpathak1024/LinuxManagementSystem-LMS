"""Read & parse host log files into structured security events.

Log files are read read-only from the mounted host log dir. The collector
tracks a byte offset per file so each scan only parses *new* lines (tail).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ..config import settings

# byte offset already consumed, per file
_offsets: dict[str, int] = {}

IP_RE = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})"


@dataclass
class ParsedEvent:
    source: str
    severity: str
    category: str
    message: str
    host_ip: str | None
    raw: str


def _logpath(name: str) -> str:
    return os.path.join(settings.host_log_dir, name)


def _tail_new_lines(path: str, max_bytes: int = 512_000) -> list[str]:
    if not os.path.exists(path):
        return []
    try:
        size = os.path.getsize(path)
        start = _offsets.get(path, max(0, size - max_bytes))
        # File rotated / truncated -> restart from beginning
        if start > size:
            start = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(start)
            data = fh.read()
            _offsets[path] = fh.tell()
        return data.splitlines()
    except (OSError, PermissionError):
        return []


def _parse_auth(line: str) -> ParsedEvent | None:
    low = line.lower()
    ip = None
    m = re.search(IP_RE, line)
    if m:
        ip = m.group(1)

    if "failed password" in low or "authentication failure" in low:
        return ParsedEvent("auth", "medium", "ssh_fail",
                           "Failed SSH/login attempt", ip, line)
    if "invalid user" in low:
        return ParsedEvent("auth", "medium", "ssh_invalid_user",
                           "Login attempt for invalid user", ip, line)
    if "accepted password" in low or "accepted publickey" in low:
        return ParsedEvent("auth", "info", "login_success",
                           "Successful login", ip, line)
    if "sudo:" in low and "command=" in low:
        return ParsedEvent("auth", "low", "sudo",
                           "sudo command executed", ip, line)
    if "session opened for user root" in low:
        return ParsedEvent("auth", "low", "root_session",
                           "Root session opened", ip, line)
    return None


def _parse_ufw(line: str) -> ParsedEvent | None:
    if "[UFW BLOCK]" in line:
        ip = None
        m = re.search(r"SRC=" + IP_RE, line)
        if m:
            ip = m.group(1)
        return ParsedEvent("ufw", "low", "port_block",
                           "Firewall blocked inbound packet", ip, line)
    if "[UFW AUDIT]" in line:
        return ParsedEvent("ufw", "info", "ufw_audit", "UFW audit", None, line)
    return None


def _parse_syslog(line: str) -> ParsedEvent | None:
    low = line.lower()
    if "segfault" in low:
        return ParsedEvent("system", "medium", "segfault", "Process segfault", None, line)
    if "oom-killer" in low or "out of memory" in low:
        return ParsedEvent("system", "high", "oom", "Out-of-memory killer invoked", None, line)
    if "i/o error" in low or "ext4-fs error" in low:
        return ParsedEvent("system", "high", "disk_error", "Disk / filesystem error", None, line)
    return None


# (filename, parser) — first existing file in each pair is used
SOURCES = [
    ("auth.log", _parse_auth),       # Debian/Ubuntu
    ("secure", _parse_auth),         # RHEL family (if present)
    ("ufw.log", _parse_ufw),
    ("syslog", _parse_syslog),
    ("kern.log", _parse_syslog),
]


def collect() -> list[ParsedEvent]:
    """Parse all new lines from known log files into events."""
    events: list[ParsedEvent] = []
    for name, parser in SOURCES:
        path = _logpath(name)
        for line in _tail_new_lines(path):
            ev = parser(line)
            if ev:
                events.append(ev)
    return events


def list_log_files() -> list[dict]:
    """List readable host log files with size, for the Logs tab."""
    out = []
    d = settings.host_log_dir
    if not os.path.isdir(d):
        return out
    try:
        for entry in sorted(os.listdir(d)):
            p = os.path.join(d, entry)
            if os.path.isfile(p):
                try:
                    out.append({"name": entry, "size_kb": round(os.path.getsize(p) / 1024, 1)})
                except OSError:
                    continue
    except OSError:
        pass
    return out


def tail_file(name: str, lines: int = 200) -> list[str]:
    """Return the last N lines of a named host log file (read-only)."""
    # prevent path traversal — only a bare filename within the log dir
    if "/" in name or ".." in name:
        return ["(invalid file name)"]
    path = _logpath(name)
    if not os.path.exists(path):
        return ["(file not found)"]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.readlines()[-lines:]
    except (OSError, PermissionError) as exc:
        return [f"(cannot read: {exc})"]
