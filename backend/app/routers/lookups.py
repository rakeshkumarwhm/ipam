"""VLANs, VRFs and devices share the same simple CRUD shape."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import current_user, require_operator
from ..models import Device, User, Vlan, Vrf
from ..schemas import (DeviceIn, DeviceOut, VlanIn, VlanOut, VrfIn, VrfOut)


def make_router(path: str, model, schema_in, schema_out, label: str) -> APIRouter:
    r = APIRouter(prefix=f"/api/{path}", tags=[path])

    @r.get("", response_model=list[schema_out])
    def list_(_: User = Depends(current_user), db: Session = Depends(get_db)):
        return db.query(model).order_by(model.id).all()

    @r.post("", response_model=schema_out, status_code=201)
    def create(body: schema_in, request: Request, user: User = Depends(require_operator),
               db: Session = Depends(get_db)):
        obj = model(**body.model_dump())
        db.add(obj)
        audit.log(db, user, f"create_{label}", str(body.model_dump().get("name") or
                  body.model_dump().get("hostname")), request=request)
        _commit(db)
        return obj

    @r.put("/{obj_id}", response_model=schema_out)
    def update(obj_id: int, body: schema_in, request: Request,
               user: User = Depends(require_operator), db: Session = Depends(get_db)):
        obj = db.get(model, obj_id)
        if not obj:
            raise HTTPException(404, "Not found")
        for k, v in body.model_dump().items():
            setattr(obj, k, v)
        audit.log(db, user, f"update_{label}", f"{label}:{obj_id}", request=request)
        _commit(db)
        return obj

    @r.delete("/{obj_id}", status_code=204)
    def delete(obj_id: int, request: Request, user: User = Depends(require_operator),
               db: Session = Depends(get_db)):
        obj = db.get(model, obj_id)
        if not obj:
            raise HTTPException(404, "Not found")
        db.delete(obj)
        audit.log(db, user, f"delete_{label}", f"{label}:{obj_id}", request=request)
        db.commit()

    return r


def _commit(db: Session):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Duplicate or invalid reference") from None


vlans = make_router("vlans", Vlan, VlanIn, VlanOut, "vlan")
vrfs = make_router("vrfs", Vrf, VrfIn, VrfOut, "vrf")
devices = make_router("devices", Device, DeviceIn, DeviceOut, "device")
