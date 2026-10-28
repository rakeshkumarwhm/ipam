
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import current_user
from ..ldap_auth import ldap_authenticate
from ..mailer import send_reset_email
from ..models import PasswordReset, Role, User
from ..schemas import ForgotIn, LoginIn, PasswordChange, ResetIn, TokenOut, UserOut
from ..security import (create_access_token, hash_password, throttle,
                        validate_password_strength, verify_password)

router = APIRouter(prefix="/api/auth", tags=["auth"])
_BAD = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    keys = (f"u:{body.username.lower()}", f"ip:{ip}")
    if throttle.blocked(*keys):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try later")

    user = db.query(User).filter(User.username == body.username).first()
    ok = False
    if user is None:
        verify_password(body.password, None)  # constant-ish time
        info = ldap_authenticate(body.username, body.password)
        if info:  # first LDAP login: provision as viewer (or admin via group)
            user = User(username=body.username, email=info["email"], auth_source="ldap",
                        role=Role.admin if info["is_admin"] else Role.viewer)
            db.add(user)
            ok = True
    elif user.is_active:
        if user.auth_source == "ldap":
            info = ldap_authenticate(user.username, body.password)
            ok = info is not None
            if ok:
                user.role = Role.admin if info["is_admin"] else (
                    Role.viewer if user.role == Role.admin else user.role)
        else:
            ok = verify_password(body.password, user.password_hash)

    if not ok:
        throttle.fail(*keys)
        audit.log(db, body.username[:64], "login_failed", "auth", request=request)
        db.commit()
        raise _BAD
    throttle.reset(*keys)
    audit.log(db, user, "login", "auth", request=request)
    db.commit()
    return TokenOut(access_token=create_access_token(user.id, user.token_version))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/logout", status_code=204)
def logout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.token_version += 1  # invalidates every issued token for this user
    audit.log(db, user, "logout", "auth", request=request)
    db.commit()


@router.post("/change-password", status_code=204)
def change_password(body: PasswordChange, request: Request,
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.auth_source != "local" or not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password incorrect")
    try:
        validate_password_strength(body.new_password)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    audit.log(db, user, "change_password", user.username, request=request)
    db.commit()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@router.post("/forgot-password", status_code=202)
def forgot_password(body: ForgotIn, request: Request, bg: BackgroundTasks,
                    db: Session = Depends(get_db)):
    """Always answers the same way, so it cannot be used to discover which e-mails exist.
    Sending happens in the background so response time does not leak it either."""
    cfg = get_settings()
    ip = request.client.host if request.client else "unknown"
    key = f"fp:{ip}"
    if throttle.blocked(key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try later")
    throttle.fail(key)
    user = db.query(User).filter(User.email.ilike(body.email), User.is_active.is_(True),
                                 User.auth_source == "local").first()
    if user:
        token = secrets.token_urlsafe(32)
        db.query(PasswordReset).filter_by(user_id=user.id).delete()  # one live token per user
        db.add(PasswordReset(
            user_id=user.id, token_hash=_hash_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=cfg.reset_token_minutes)))
        audit.log(db, user, "password_reset_requested", user.username, request=request)
        db.commit()
        link = f"{cfg.public_url.rstrip('/')}/#reset={token}"
        bg.add_task(send_reset_email, user.email, link, cfg.reset_token_minutes)
    return {"detail": "If the account exists, an e-mail has been sent."}


@router.post("/reset-password", status_code=204)
def reset_password(body: ResetIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    key = f"rp:{ip}"
    if throttle.blocked(key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try later")
    row = db.query(PasswordReset).filter_by(token_hash=_hash_token(body.token)).first()
    if row is None or _aware(row.expires_at) < datetime.now(timezone.utc):
        throttle.fail(key)
        raise HTTPException(400, "Reset link is invalid or has expired")
    try:
        validate_password_strength(body.new_password)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    user = db.get(User, row.user_id)
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1          # sign out every existing session
    db.delete(row)                   # single use
    audit.log(db, user, "password_reset_completed", user.username, request=request)
    db.commit()
