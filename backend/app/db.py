from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_Session = None


def init_engine(url: str | None = None):
    global _engine, _Session
    _engine = create_engine(url or get_settings().sqlalchemy_url(), pool_pre_ping=True,
                           pool_recycle=1800)
    _Session = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_db() -> Iterator[Session]:
    if _Session is None:
        init_engine()
    db = _Session()
    try:
        yield db
    finally:
        db.close()
