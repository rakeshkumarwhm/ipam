from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import require_admin
from ..models import Role, Section, SectionPermission, User
from ..schemas import PermIn, PermOut, UserIn, UserOut, UserUpdate
from ..security import hash_password, validate_password_strength

router = APIRouter(prefix="/api/users", tags=["users"])


def _check_pw(pw: str):
    try:
        validate_password_strength(pw)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserIn, request: Request, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    _check_pw(body.password)
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username exists")
    u = User(username=body.username, email=body.email, role=body.role,
             password_hash=hash_password(body.password))
    db.add(u)
    audit.log(db, admin, "create_user", body.username, f"role={body.role.value}", request)
    db.commit()
    return u


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, request: Request,
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "Not found")
    if u.id == admin.id and (body.is_active is False or (body.role and body.role != Role.admin)):
        raise HTTPException(400, "You cannot demote or disable yourself")
    if body.role is not None:
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.password:
        if u.auth_source != "local":
            raise HTTPException(400, "Password is managed by the directory")
        _check_pw(body.password)
        u.password_hash = hash_password(body.password)
    u.token_version += 1  # any change forces re-login
    audit.log(db, admin, "update_user", u.username,
              f"role={u.role.value} active={u.is_active}", request)
    db.commit()
    return u


@router.put("/sections/{section_id}/permissions", response_model=PermOut)
def set_permission(section_id: int, body: PermIn, request: Request,
                   admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not db.get(Section, section_id) or not db.get(User, body.user_id):
        raise HTTPException(404, "Not found")
    perm = db.query(SectionPermission).filter_by(
        user_id=body.user_id, section_id=section_id).first()
    if perm:
        perm.level = body.level
    else:
        perm = SectionPermission(user_id=body.user_id, section_id=section_id, level=body.level)
        db.add(perm)
    audit.log(db, admin, "set_permission", f"section:{section_id}",
              f"user={body.user_id} level={body.level.value}", request)
    db.commit()
    return perm


@router.delete("/sections/{section_id}/permissions/{user_id}", status_code=204)
def remove_permission(section_id: int, user_id: int, request: Request,
                      admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    db.query(SectionPermission).filter_by(user_id=user_id, section_id=section_id).delete()
    audit.log(db, admin, "remove_permission", f"section:{section_id}", f"user={user_id}", request)
    db.commit()



