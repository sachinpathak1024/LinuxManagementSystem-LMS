"""Background collectors — sample metrics, ingest log events, raise alerts.

Run by APScheduler from app startup. All DB writes use short-lived sessions.
Metric samples are also broadcast live over the WebSocket hub.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from .config import settings
from .database import SessionLocal
from .models import Alert, Event, MetricSample
from .services import log_collector, system_monitor
from .websocket import hub

log = logging.getLogger("sentinel.collectors")

# de-dupe alert spam: remember last time we raised a given alert key
_last_alert: dict[str, datetime] = {}
_ALERT_COOLDOWN = timedelta(minutes=10)

# The main event loop, captured at startup. Collector jobs run in worker
# threads, so broadcasts must be scheduled back onto this loop thread-safely.
_main_loop: asyncio.AbstractEventLoop | None = None


def set_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _main_loop
    _main_loop = loop


def _broadcast(payload: dict) -> None:
    if _main_loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(hub.broadcast(payload), _main_loop)
    except RuntimeError:
        pass


def _maybe_alert(db, key: str, title: str, severity: str, detail: str) -> None:
    now = datetime.now(timezone.utc)
    last = _last_alert.get(key)
    if last and now - last < _ALERT_COOLDOWN:
        return
    _last_alert[key] = now
    db.add(Alert(title=title, severity=severity, detail=detail))


def sample_metrics() -> None:
    """Take one resource sample, persist it, check thresholds, broadcast."""
    data = system_monitor.sample()
    db = SessionLocal()
    try:
        db.add(MetricSample(**data))

        cores = system_monitor.cpu_count()
        if data["cpu_percent"] >= settings.alert_cpu_percent:
            _maybe_alert(db, "cpu", f"High CPU usage ({data['cpu_percent']}%)",
                         "medium", "CPU above threshold.")
        if data["mem_percent"] >= settings.alert_mem_percent:
            _maybe_alert(db, "mem", f"High memory usage ({data['mem_percent']}%)",
                         "medium", "Memory above threshold.")
        if data["disk_percent"] >= settings.alert_disk_percent:
            _maybe_alert(db, "disk", f"Low disk space ({data['disk_percent']}% used)",
                         "high", "Disk usage above threshold.")
        if cores and data["load1"] / cores >= settings.alert_load_per_core:
            _maybe_alert(db, "load", f"High load average ({data['load1']})",
                         "medium", "Load per core above threshold.")
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("metric sampling failed")
    finally:
        db.close()

    _broadcast({"type": "metric", "data": data})


# Security categories that should also raise an alert when first seen in a burst
_BURST_KEYS = {"ssh_fail", "ssh_invalid_user"}
_burst_counter: dict[str, int] = {}


def ingest_events() -> None:
    """Parse new log lines into Event rows, alert on brute-force bursts."""
    parsed = log_collector.collect()
    if not parsed:
        return
    db = SessionLocal()
    try:
        for ev in parsed:
            db.add(
                Event(
                    source=ev.source,
                    severity=ev.severity,
                    category=ev.category,
                    message=ev.message,
                    host_ip=ev.host_ip,
                    raw=ev.raw[:2000] if ev.raw else None,
                )
            )
            if ev.category in _BURST_KEYS:
                _burst_counter[ev.category] = _burst_counter.get(ev.category, 0) + 1
                if _burst_counter[ev.category] >= 10:
                    _maybe_alert(
                        db, f"burst:{ev.category}",
                        "Possible SSH brute-force in progress",
                        "high",
                        f"{_burst_counter[ev.category]} failed/invalid login lines "
                        "since last reset.",
                    )
                    _burst_counter[ev.category] = 0
        db.commit()
        _broadcast({"type": "events", "count": len(parsed)})
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("event ingest failed")
    finally:
        db.close()


def prune_old_data() -> None:
    """Keep the DB bounded — drop metric samples older than 7 days."""
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        db.query(MetricSample).filter(MetricSample.ts < cutoff).delete()
        ev_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        db.query(Event).filter(Event.ts < ev_cutoff).delete()
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
    finally:
        db.close()
