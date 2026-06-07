"""systemd service + package/update endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import audit
from ..database import get_db
from ..deps import get_current_user, require_admin
from ..models import User
from ..schemas import ActionResult
from ..services import package_manager, service_manager

router = APIRouter(prefix="/api/services", tags=["services"])


@router.get("", dependencies=[Depends(get_current_user)])
def list_services():
    return service_manager.overview()


@router.post("/{name}/{action}", response_model=ActionResult)
def control(name: str, action: str, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = service_manager.control(name, action)
    audit.record(db, user.username, "service.control", target=f"{name}:{action}",
                 success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output, error=r.error)


@router.get("/updates/available", dependencies=[Depends(get_current_user)])
def updates():
    return package_manager.upgradable()


@router.post("/updates/refresh", response_model=ActionResult)
def refresh(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = package_manager.update_index()
    audit.record(db, user.username, "packages.update_index", success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output[:4000], error=r.error)


@router.post("/updates/security", response_model=ActionResult)
def upgrade_security(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    r = package_manager.upgrade_security_only()
    audit.record(db, user.username, "packages.upgrade_security", success=r.success, detail=r.error)
    return ActionResult(success=r.success, output=r.output[:8000], error=r.error)
