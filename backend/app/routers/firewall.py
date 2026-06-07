"""UFW firewall management endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import audit
from ..database import get_db
from ..deps import get_current_user, require_admin
from ..models import User
from ..schemas import ActionResult, FirewallRuleRequest
from ..services import firewall

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


@router.get("/status", dependencies=[Depends(get_current_user)])
def status():
    return firewall.status()


@router.post("/enable", response_model=ActionResult)
def enable(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = firewall.enable()
    audit.record(db, user.username, "firewall.enable", success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output, error=r.error)


@router.post("/disable", response_model=ActionResult)
def disable(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = firewall.disable()
    audit.record(db, user.username, "firewall.disable", success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output, error=r.error)


@router.post("/default-deny", response_model=ActionResult)
def default_deny(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = firewall.set_default_deny()
    audit.record(db, user.username, "firewall.default_deny", success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output, error=r.error)


@router.post("/rule", response_model=ActionResult)
def add_rule(
    req: FirewallRuleRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    r = firewall.add_rule(req.port, req.protocol, req.action, req.from_ip, req.comment)
    audit.record(
        db, user.username, "firewall.add_rule",
        target=f"{req.action} {req.port}/{req.protocol}", success=r.success, detail=r.error,
    )
    return ActionResult(success=r.success, output=r.output, error=r.error)


@router.delete("/rule/{number}", response_model=ActionResult)
def delete_rule(number: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = firewall.delete_rule(number)
    audit.record(db, user.username, "firewall.delete_rule", target=str(number),
                 success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output, error=r.error)
