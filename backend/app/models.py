import enum
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, Enum, ForeignKey, Integer, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"        # everything, incl. users
    operator = "operator"  # read/write on sections they are granted
    viewer = "viewer"      # read-only on sections they are granted


class Level(str, enum.Enum):
    read = "read"
    write = "write"


class AddrStatus(str, enum.Enum):
    used = "used"
    reserved = "reserved"
    online = "online"
    offline = "offline"
    dhcp = "dhcp"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255))  # null for LDAP users
    auth_source: Mapped[str] = mapped_column(String(16), default="local")
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)  # bump to revoke tokens
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Section(Base):
    __tablename__ = "sections"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    subnets: Mapped[list["Subnet"]] = relationship(back_populates="section", cascade="all, delete-orphan")


class SectionPermission(Base):
    __tablename__ = "section_permissions"
    __table_args__ = (UniqueConstraint("user_id", "section_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    section_id: Mapped[int] = mapped_column(ForeignKey("sections.id", ondelete="CASCADE"))
    level: Mapped[Level] = mapped_column(Enum(Level))


class Vrf(Base):
    __tablename__ = "vrfs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    rd: Mapped[str | None] = mapped_column(String(32))
    description: Mapped[str | None] = mapped_column(Text)


class Vlan(Base):
    __tablename__ = "vlans"
    __table_args__ = (UniqueConstraint("number", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    number: Mapped[int] = mapped_column(Integer)  # 1-4094
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True)
    device_type: Mapped[str] = mapped_column(String(64))  # firewall, load-balancer, vm, switch...
    location: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)


class Subnet(Base):
    __tablename__ = "subnets"
    __table_args__ = (UniqueConstraint("vrf_id", "cidr"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    section_id: Mapped[int] = mapped_column(ForeignKey("sections.id", ondelete="CASCADE"), index=True)
    vrf_id: Mapped[int | None] = mapped_column(ForeignKey("vrfs.id", ondelete="SET NULL"))
    vlan_id: Mapped[int | None] = mapped_column(ForeignKey("vlans.id", ondelete="SET NULL"))
    cidr: Mapped[str] = mapped_column(String(49))
    version: Mapped[int] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    section: Mapped[Section] = relationship(back_populates="subnets")
    addresses: Mapped[list["Address"]] = relationship(back_populates="subnet", cascade="all, delete-orphan")


class Address(Base):
    __tablename__ = "addresses"
    __table_args__ = (UniqueConstraint("subnet_id", "ip"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    subnet_id: Mapped[int] = mapped_column(ForeignKey("subnets.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    ip: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac: Mapped[str | None] = mapped_column(String(17))
    status: Mapped[AddrStatus] = mapped_column(Enum(AddrStatus), default=AddrStatus.used)
    description: Mapped[str | None] = mapped_column(Text)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    subnet: Mapped[Subnet] = relationship(back_populates="addresses")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str | None] = mapped_column(Text)
    client_ip: Mapped[str | None] = mapped_column(String(45))


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 of the token
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
