from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User


def log(db: Session, actor: User | str, action: str, target: str,
        detail: str | None = None, request: Request | None = None) -> None:
    """Add an audit entry to the current transaction (committed with the change)."""
    db.add(AuditLog(
        actor=actor if isinstance(actor, str) else actor.username,
        action=action, target=target[:255], detail=detail,
        client_ip=request.client.host if request and request.client else None))
