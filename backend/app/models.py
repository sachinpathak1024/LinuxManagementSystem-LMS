"""Database models — users, metrics, events, alerts, audit log."""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="admin")  # admin | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MetricSample(Base):
    """A point-in-time snapshot of host resource usage."""

    __tablename__ = "metric_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    cpu_percent: Mapped[float] = mapped_column(Float)
    mem_percent: Mapped[float] = mapped_column(Float)
    swap_percent: Mapped[float] = mapped_column(Float, default=0.0)
    disk_percent: Mapped[float] = mapped_column(Float)
    load1: Mapped[float] = mapped_column(Float, default=0.0)
    net_sent_bps: Mapped[float] = mapped_column(Float, default=0.0)
    net_recv_bps: Mapped[float] = mapped_column(Float, default=0.0)
    process_count: Mapped[int] = mapped_column(Integer, default=0)


Index("ix_metric_ts_desc", MetricSample.ts.desc())


class Event(Base):
    """A security / system event parsed from logs or detected by a scan."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)   # auth, ufw, fail2ban, system, scan
    severity: Mapped[str] = mapped_column(String(16), index=True)  # info, low, medium, high, critical
    category: Mapped[str] = mapped_column(String(48), index=True)  # ssh_fail, ban, port_block, ...
    message: Mapped[str] = mapped_column(Text)
    host_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)


Index("ix_event_ts_desc", Event.ts.desc())


class Alert(Base):
    """A raised alert (threshold breach or correlated security signal)."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    title: Mapped[str] = mapped_column(String(160))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuditLog(Base):
    """Every privileged/control action performed THROUGH Sentinel."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str] = mapped_column(Text, default="")
