import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, ipcalc, scanner
from ..config import get_settings
from ..db import get_db
from ..deps import check_section, current_user, readable_section_ids
from ..models import AddrStatus, Address, Device, Level, Section, Subnet, User, Vlan, Vrf
from ..schemas import AddressIn, AddressOut, SubnetIn, SubnetOut, SubnetUsage

router = APIRouter(prefix="/api", tags=["subnets"])
MAX_IMPORT_BYTES = 1_000_000
MAX_IMPORT_ROWS = 5000


def _usage(db: Session, s: Subnet) -> SubnetUsage:
    net = ipcalc.parse_network(s.cidr)
    used_ips = {a for (a,) in db.query(Address.ip).filter(Address.subnet_id == s.id)}
    total = ipcalc.usable_count(net)
    used = len(used_ips)
    return SubnetUsage(
        **SubnetOut.model_validate(s).model_dump(), total=total, used=used,
        free=max(total - used, 0), percent_used=round(100 * used / total, 1) if total else 0.0,
        next_free=ipcalc.next_free(net, used_ips))


def _subnet_or_404(db: Session, subnet_id: int) -> Subnet:
    s = db.get(Subnet, subnet_id)
    if not s:
        raise HTTPException(404, "Subnet not found")
    return s


def _validate_refs(db: Session, vrf_id, vlan_id):
    if vrf_id is not None and not db.get(Vrf, vrf_id):
        raise HTTPException(422, "Unknown VRF")
    if vlan_id is not None and not db.get(Vlan, vlan_id):
        raise HTTPException(422, "Unknown VLAN")


def _create_subnet(db: Session, body: SubnetIn) -> Subnet:
    try:
        net = ipcalc.parse_network(body.cidr)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    _validate_refs(db, body.vrf_id, body.vlan_id)
    # Overlap check against every subnet in the same VRF (None == global table).
    for other in db.query(Subnet.cidr).filter(Subnet.vrf_id == body.vrf_id):
        if ipcalc.overlaps(net, ipcalc.parse_network(other[0])):
            raise HTTPException(409, f"Overlaps existing subnet {other[0]}")
    s = Subnet(section_id=body.section_id, vrf_id=body.vrf_id, vlan_id=body.vlan_id,
               cidr=str(net), version=net.version, description=body.description)
    db.add(s)
    return s


@router.get("/subnets", response_model=list[SubnetUsage])
def list_subnets(section_id: int | None = None, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    q = db.query(Subnet).order_by(Subnet.version, Subnet.cidr)
    ids = readable_section_ids(db, user)
    if section_id is not None:
        check_section(db, user, section_id, Level.read)
        q = q.filter(Subnet.section_id == section_id)
    elif ids is not None:
        q = q.filter(Subnet.section_id.in_(ids))
    return [_usage(db, s) for s in q.all()]


@router.post("/subnets", response_model=SubnetOut, status_code=201)
def create_subnet(body: SubnetIn, request: Request, user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    if not db.get(Section, body.section_id):
        raise HTTPException(404, "Section not found")
    check_section(db, user, body.section_id, Level.write)
    s = _create_subnet(db, body)
    audit.log(db, user, "create_subnet", s.cidr, request=request)
    db.commit()
    return s


@router.get("/subnets/{subnet_id}", response_model=SubnetUsage)
def get_subnet(subnet_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _subnet_or_404(db, subnet_id)
    check_section(db, user, s.section_id, Level.read)
    return _usage(db, s)


@router.delete("/subnets/{subnet_id}", status_code=204)
def delete_subnet(subnet_id: int, request: Request, user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    s = _subnet_or_404(db, subnet_id)
    check_section(db, user, s.section_id, Level.write)
    audit.log(db, user, "delete_subnet", s.cidr, request=request)
    db.delete(s)
    db.commit()


# ---- addresses ------------------------------------------------------------------------

@router.get("/subnets/{subnet_id}/addresses", response_model=list[AddressOut])
def list_addresses(subnet_id: int, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    s = _subnet_or_404(db, subnet_id)
    check_section(db, user, s.section_id, Level.read)
    return db.query(Address).filter_by(subnet_id=subnet_id).order_by(Address.id).all()


@router.post("/subnets/{subnet_id}/addresses", response_model=AddressOut, status_code=201)
def add_address(subnet_id: int, body: AddressIn, request: Request,
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _subnet_or_404(db, subnet_id)
    check_section(db, user, s.section_id, Level.write)
    net = ipcalc.parse_network(s.cidr)
    try:
        ip = ipcalc.parse_ip(body.ip)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if not ipcalc.is_usable(net, ip):
        raise HTTPException(422, "Address is not a usable host address of this subnet")
    if body.device_id is not None and not db.get(Device, body.device_id):
        raise HTTPException(422, "Unknown device")
    a = Address(subnet_id=subnet_id, **{**body.model_dump(), "ip": str(ip)})
    db.add(a)
    audit.log(db, user, "add_address", f"{ip} in {s.cidr}", request=request)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Address already exists") from None
    return a


@router.put("/addresses/{addr_id}", response_model=AddressOut)
def update_address(addr_id: int, body: AddressIn, request: Request,
                   user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Address, addr_id)
    if not a:
        raise HTTPException(404, "Not found")
    check_section(db, user, a.subnet.section_id, Level.write)
    if str(ipcalc.parse_ip(body.ip)) != a.ip:
        raise HTTPException(422, "IP cannot be changed; delete and re-add")
    if body.device_id is not None and not db.get(Device, body.device_id):
        raise HTTPException(422, "Unknown device")
    for k in ("hostname", "mac", "status", "device_id", "description"):
        setattr(a, k, getattr(body, k))
    audit.log(db, user, "update_address", a.ip, request=request)
    db.commit()
    return a


@router.delete("/addresses/{addr_id}", status_code=204)
def delete_address(addr_id: int, request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    a = db.get(Address, addr_id)
    if not a:
        raise HTTPException(404, "Not found")
    check_section(db, user, a.subnet.section_id, Level.write)
    audit.log(db, user, "delete_address", a.ip, request=request)
    db.delete(a)
    db.commit()


# ---- search ---------------------------------------------------------------------------

@router.get("/search", response_model=list[AddressOut])
def search(q: str = Query(min_length=2, max_length=64), user: User = Depends(current_user),
           db: Session = Depends(get_db)):
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like = f"%{escaped}%"
    query = db.query(Address).join(Subnet).filter(
        Address.ip.ilike(like, escape="\\") | Address.hostname.ilike(like, escape="\\")
        | Address.mac.ilike(like, escape="\\") | Address.description.ilike(like, escape="\\"))
    ids = readable_section_ids(db, user)
    if ids is not None:
        query = query.filter(Subnet.section_id.in_(ids))
    return query.limit(200).all()


# ---- scanning -------------------------------------------------------------------------

@router.post("/subnets/{subnet_id}/scan")
def scan_subnet(subnet_id: int, request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    s = _subnet_or_404(db, subnet_id)
    check_section(db, user, s.section_id, Level.write)
    net = ipcalc.parse_network(s.cidr)
    if net.version != 4:
        raise HTTPException(422, "Only IPv4 subnets can be scanned")
    cfg = get_settings()
    try:
        result = scanner.scan(net, cfg.scan_max_hosts, cfg.scan_workers)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    now = datetime.now(timezone.utc)
    known = {a.ip: a for a in db.query(Address).filter_by(subnet_id=s.id)}
    new = 0
    for ip, alive in result.items():
        a = known.get(ip)
        if a is None and alive:
            db.add(Address(subnet_id=s.id, ip=ip, status=AddrStatus.online, last_seen=now,
                           description="discovered by scan"))
            new += 1
        elif a is not None and a.status != AddrStatus.reserved:
            a.status = AddrStatus.online if alive else AddrStatus.offline
            if alive:
                a.last_seen = now
    audit.log(db, user, "scan_subnet", s.cidr, f"alive={sum(result.values())} new={new}", request)
    db.commit()
    return {"scanned": len(result), "alive": sum(result.values()), "new": new}


# ---- CSV import -----------------------------------------------------------------------

@router.post("/sections/{section_id}/import")
async def import_subnets(section_id: int, file: UploadFile, request: Request,
                         user: User = Depends(current_user), db: Session = Depends(get_db)):
    """CSV columns: cidr,description[,vrf,vlan]. Header row required."""
    if not db.get(Section, section_id):
        raise HTTPException(404, "Section not found")
    check_section(db, user, section_id, Level.write)
    raw = await file.read(MAX_IMPORT_BYTES + 1)
    if len(raw) > MAX_IMPORT_BYTES:
        raise HTTPException(413, "File too large")
    try:
        rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    except (UnicodeDecodeError, csv.Error):
        raise HTTPException(422, "Not a valid UTF-8 CSV file") from None
    if len(rows) > MAX_IMPORT_ROWS:
        raise HTTPException(413, "Too many rows")
    vrfs = {v.name: v.id for v in db.query(Vrf)}
    vlans = {v.number: v.id for v in db.query(Vlan)}
    created, errors = 0, []
    for n, row in enumerate(rows, start=2):
        try:
            vlan_no = (row.get("vlan") or "").strip()
            body = SubnetIn(section_id=section_id, cidr=(row.get("cidr") or ""),
                            description=(row.get("description") or None),
                            vrf_id=vrfs.get((row.get("vrf") or "").strip()),
                            vlan_id=vlans.get(int(vlan_no)) if vlan_no.isdigit() else None)
            with db.begin_nested():
                _create_subnet(db, body)
            created += 1
        except (HTTPException, ValueError) as e:
            errors.append({"row": n, "error": getattr(e, "detail", str(e))})
    audit.log(db, user, "import_subnets", f"section:{section_id}",
              f"created={created} errors={len(errors)}", request)
    db.commit()
    return {"created": created, "errors": errors[:100]}


@router.get("/sections/{section_id}/export")
def export_subnets(section_id: int, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    from fastapi.responses import Response
    check_section(db, user, section_id, Level.read)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["cidr", "description"])
    for s in db.query(Subnet).filter_by(section_id=section_id).order_by(Subnet.cidr):
        w.writerow([_safe_cell(s.cidr), _safe_cell(s.description or "")])
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=subnets.csv"})


def _safe_cell(v: str) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
