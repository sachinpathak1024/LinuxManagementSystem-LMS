"""System monitoring endpoints (metrics, processes, host info)."""
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user
from ..models import MetricSample
from ..schemas import MetricOut
from ..services import system_monitor

router = APIRouter(prefix="/api/system", tags=["system"], dependencies=[Depends(get_current_user)])


@router.get("/live")
def live():
    """Instant snapshot (not stored)."""
    return system_monitor.sample()


@router.get("/detailed")
def detailed():
    return system_monitor.detailed()


@router.get("/processes")
def processes(limit: int = Query(15, le=100)):
    return system_monitor.top_processes(limit)


@router.get("/host")
def host_info():
    osr = {}
    path = os.path.join(settings.host_root, "etc", "os-release")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if "=" in line:
                        k, _, v = line.partition("=")
                        osr[k.strip()] = v.strip().strip('"')
        except OSError:
            pass
    return {
        "os": osr.get("PRETTY_NAME", "unknown"),
        "version": osr.get("VERSION", ""),
        "hostname": os.uname().nodename if hasattr(os, "uname") else "",
        "kernel": os.uname().release if hasattr(os, "uname") else "",
    }


@router.get("/history", response_model=list[MetricOut])
def history(minutes: int = Query(60, le=1440), db: Session = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = (
        db.query(MetricSample)
        .filter(MetricSample.ts >= since)
        .order_by(MetricSample.ts.asc())
        .all()
    )
    return rows
