import os

os.environ.setdefault("IPAM_SECRET_KEY", "x" * 16 + "unit-test-key-0123456789abcdef")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Role, User
from app.security import hash_password, throttle

PW = "Str0ngPassw0rd!"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    with maker() as s:
        s.add_all([User(username="admin", password_hash=hash_password(PW), role=Role.admin),
                   User(username="op", password_hash=hash_password(PW), role=Role.operator),
                   User(username="view", password_hash=hash_password(PW), role=Role.viewer)])
        s.commit()
    yield maker
    engine.dispose()


@pytest.fixture()
def client(db_session):
    def _get_db():
        with db_session() as s:
            yield s
    app.dependency_overrides[get_db] = _get_db
    throttle._fails.clear()
    yield TestClient(app)
    app.dependency_overrides.clear()


def login(client, user="admin", password=PW) -> dict:
    r = client.post("/api/auth/login", json={"username": user, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
