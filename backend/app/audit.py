"""Helper to record privileged actions performed through Sentinel."""
from sqlalchemy.orm import Session

from .models import AuditLog


def record(
    db: Session,
    username: str,
    action: str,
    target: str = "",
    success: bool = True,
    detail: str = "",
) -> None:
    db.add(
        AuditLog(
            username=username,
            action=action,
            target=target[:255],
            success=success,
            detail=detail[:2000],
        )
    )
    db.commit()
