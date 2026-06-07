"""Security posture + fail2ban + scanners."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import audit
from ..database import get_db
from ..deps import get_current_user, require_admin
from ..models import User
from ..schemas import ActionResult
from ..services import fail2ban, security_audit

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/posture", dependencies=[Depends(get_current_user)])
def posture():
    return security_audit.posture()


@router.get("/ports", dependencies=[Depends(get_current_user)])
def ports():
    return security_audit.listening_ports()


@router.get("/sessions", dependencies=[Depends(get_current_user)])
def sessions():
    return {
        "logged_in": security_audit.logged_in_users(),
        "failed_logins": security_audit.recent_failed_logins(),
    }


@router.get("/fail2ban", dependencies=[Depends(get_current_user)])
def f2b():
    return fail2ban.overview()


@router.post("/fail2ban/{jail}/ban/{ip}", response_model=ActionResult)
def ban(jail: str, ip: str, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = fail2ban.ban(jail, ip)
    audit.record(db, user.username, "fail2ban.ban", target=f"{jail}:{ip}",
                 success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output, error=r.error)


@router.post("/fail2ban/{jail}/unban/{ip}", response_model=ActionResult)
def unban(jail: str, ip: str, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = fail2ban.unban(jail, ip)
    audit.record(db, user.username, "fail2ban.unban", target=f"{jail}:{ip}",
                 success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output, error=r.error)


@router.post("/scan/{tool}", response_model=ActionResult)
def scan(tool: str, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = security_audit.run_scanner(tool)
    audit.record(db, user.username, "security.scan", target=tool,
                 success=r.success, detail=(r.error or "")[:500])
    return ActionResult(success=r.success, output=r.output[:8000], error=r.error)
