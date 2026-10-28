from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import current_user, readable_section_ids, require_admin
from ..models import Section, User
from ..schemas import SectionIn, SectionOut

router = APIRouter(prefix="/api/sections", tags=["sections"])


@router.get("", response_model=list[SectionOut])
def list_sections(user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Section).order_by(Section.name)
    ids = readable_section_ids(db, user)
    if ids is not None:
        q = q.filter(Section.id.in_(ids))
    return q.all()


@router.post("", response_model=SectionOut, status_code=201)
def create_section(body: SectionIn, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    s = Section(**body.model_dump())
    db.add(s)
    audit.log(db, admin, "create_section", body.name, request=request)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Section name exists") from None
    return s


@router.put("/{section_id}", response_model=SectionOut)
def update_section(section_id: int, body: SectionIn, request: Request,
                   admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = db.get(Section, section_id)
    if not s:
        raise HTTPException(404, "Not found")
    s.name, s.description = body.name, body.description
    audit.log(db, admin, "update_section", s.name, request=request)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Section name exists") from None
    return s


@router.delete("/{section_id}", status_code=204)
def delete_section(section_id: int, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    s = db.get(Section, section_id)
    if not s:
        raise HTTPException(404, "Not found")
    audit.log(db, admin, "delete_section", s.name, f"subnets={len(s.subnets)}", request)
    db.delete(s)
    db.commit()
