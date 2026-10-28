"""Authentication and authorisation dependencies."""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .db import get_db
from .models import Level, Role, SectionPermission, User
from .security import decode_access_token

_bearer = HTTPBearer(auto_error=False)
_UNAUTH = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"})


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
                 db: Session = Depends(get_db)) -> User:
    if creds is None:
        raise _UNAUTH
    payload = decode_access_token(creds.credentials)
    if payload is None:
        raise _UNAUTH
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active or user.token_version != payload["ver"]:
        raise _UNAUTH
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin only")
    return user


def check_section(db: Session, user: User, section_id: int, need: Level) -> None:
    """Raise 403 unless the user may access the section at the required level."""
    if user.role == Role.admin:
        return
    perm = db.query(SectionPermission).filter_by(user_id=user.id, section_id=section_id).first()
    if perm is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No access to this section")
    if need == Level.write:
        if user.role != Role.operator or perm.level != Level.write:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Write access required")


def readable_section_ids(db: Session, user: User) -> list[int] | None:
    """None means 'all sections' (admin)."""
    if user.role == Role.admin:
        return None
    rows = db.query(SectionPermission.section_id).filter_by(user_id=user.id).all()
    return [r[0] for r in rows]


def require_operator(user: User = Depends(current_user)) -> User:
    if user.role not in (Role.admin, Role.operator):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Operator role required")
    return user
