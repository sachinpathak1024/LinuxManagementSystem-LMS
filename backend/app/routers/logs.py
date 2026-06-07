"""Event / log browsing endpoints."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Event
from ..schemas import EventOut
from ..services import log_collector

router = APIRouter(prefix="/api/logs", tags=["logs"], dependencies=[Depends(get_current_user)])


@router.get("/events", response_model=list[EventOut])
def events(
    severity: str | None = None,
    source: str | None = None,
    minutes: int = Query(1440, le=10080),
    limit: int = Query(200, le=1000),
    db: Session = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    q = db.query(Event).filter(Event.ts >= since)
    if severity:
        q = q.filter(Event.severity == severity)
    if source:
        q = q.filter(Event.source == source)
    return q.order_by(Event.ts.desc()).limit(limit).all()


@router.get("/events/summary")
def summary(minutes: int = Query(1440, le=10080), db: Session = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = db.query(Event).filter(Event.ts >= since).all()
    by_sev: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for r in rows:
        by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
        by_source[r.source] = by_source.get(r.source, 0) + 1
    return {"total": len(rows), "by_severity": by_sev, "by_source": by_source}


@router.get("/files")
def files():
    return log_collector.list_log_files()


@router.get("/files/{name}")
def tail(name: str, lines: int = Query(200, le=2000)):
    return {"name": name, "lines": log_collector.tail_file(name, lines)}
