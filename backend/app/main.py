import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from .config import get_settings
from .db import Base, init_engine
from .models import Role, User
from .security import hash_password, validate_password_strength
from .routers import audit_log, auth, lookups, sections, subnets, users

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create tables and, on a brand-new install, the first admin from the environment."""
    cfg = get_settings()
    engine = init_engine()
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        if db.query(User).count() == 0:
            if cfg.bootstrap_admin_user and cfg.bootstrap_admin_password:
                validate_password_strength(cfg.bootstrap_admin_password)
                db.add(User(username=cfg.bootstrap_admin_user, role=Role.admin,
                            password_hash=hash_password(cfg.bootstrap_admin_password)))
                db.commit()
                log.warning("Bootstrap admin %r created; remove IPAM_BOOTSTRAP_* from the environment.",
                            cfg.bootstrap_admin_user)
            else:
                log.warning("No users exist and no bootstrap admin configured.")
    yield


# Interactive docs are disabled; enable only in development if needed.
app = FastAPI(title="IPAM", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan)

_cors = get_settings().cors_origins
if _cors:
    app.add_middleware(CORSMiddleware, allow_origins=_cors, allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                       allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return resp


for r in (auth.router, users.router, sections.router, subnets.router, lookups.vlans,
          lookups.vrfs, lookups.devices, audit_log.router):
    app.include_router(r)


@app.get("/api/health")
def health():
    return {"status": "ok"}
