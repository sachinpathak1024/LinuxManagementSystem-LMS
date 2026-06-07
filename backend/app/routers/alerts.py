"""Alert + audit-log endpoints."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, require_admin
from ..models import Alert, AuditLog, User
from ..schemas import AlertOut, AuditOut

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts", response_model=list[AlertOut], dependencies=[Depends(get_current_user)])
def alerts(
    only_open: bool = False,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    if only_open:
        q = q.filter(Alert.acknowledged.is_(False))
    return q.order_by(Alert.ts.desc()).limit(limit).all()


@router.post("/alerts/{alert_id}/ack", response_model=AlertOut)
def ack(alert_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = db.get(Alert, alert_id)
    if not alert:
        from fastapi import HTTPException

        raise HTTPException(404, "alert not found")
    alert.acknowledged = True
    alert.acknowledged_by = user.username
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/audit", response_model=list[AuditOut], dependencies=[Depends(require_admin)])
def audit_log(limit: int = Query(200, le=1000), db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.ts.desc()).limit(limit).all()
