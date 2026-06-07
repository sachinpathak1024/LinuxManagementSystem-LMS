"""Pydantic request/response schemas."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    is_active: bool
    last_login: datetime | None = None


class MetricOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    ts: datetime
    cpu_percent: float
    mem_percent: float
    swap_percent: float
    disk_percent: float
    load1: float
    net_sent_bps: float
    net_recv_bps: float
    process_count: int


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime
    source: str
    severity: str
    category: str
    message: str
    host_ip: str | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime
    title: str
    severity: str
    detail: str
    acknowledged: bool
    acknowledged_by: str | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime
    username: str
    action: str
    target: str
    success: bool
    detail: str


class FirewallRule(BaseModel):
    to: str
    action: str
    from_: str = "Anywhere"


class FirewallRuleRequest(BaseModel):
    port: int
    protocol: str = "tcp"   # tcp | udp
    action: str = "allow"   # allow | deny
    from_ip: str | None = None
    comment: str | None = None


class ActionResult(BaseModel):
    success: bool
    output: str = ""
    error: str = ""
