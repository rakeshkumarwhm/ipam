from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin
from ..models import AuditLog, User
from ..schemas import AuditOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
               _: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()
