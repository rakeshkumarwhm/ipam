import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .models import AddrStatus, Level, Role

Name = Field(min_length=1, max_length=100)
Desc = Field(default=None, max_length=2000)
_MAC = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$")


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class ForgotIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    new_password: str = Field(max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._-]{3,64}$")
    email: EmailStr | None = None
    password: str = Field(max_length=128)
    role: Role = Role.viewer


class UserOut(ORM):
    id: int
    username: str
    email: str | None
    role: Role
    auth_source: str
    is_active: bool


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, max_length=128)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=128)
    new_password: str = Field(max_length=128)


class PermIn(BaseModel):
    user_id: int
    level: Level


class PermOut(ORM):
    user_id: int
    section_id: int
    level: Level


class SectionIn(BaseModel):
    name: str = Name
    description: str | None = Desc


class SectionOut(ORM, SectionIn):
    id: int


class VrfIn(BaseModel):
    name: str = Name
    rd: str | None = Field(default=None, max_length=32)
    description: str | None = Desc


class VrfOut(ORM, VrfIn):
    id: int


class VlanIn(BaseModel):
    number: int = Field(ge=1, le=4094)
    name: str = Name
    description: str | None = Desc


class VlanOut(ORM, VlanIn):
    id: int


class DeviceIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    device_type: str = Field(min_length=1, max_length=64)
    location: str | None = Field(default=None, max_length=255)
    description: str | None = Desc

    @field_validator("hostname")
    @classmethod
    def _h(cls, v):
        if not _HOST.match(v):
            raise ValueError("Invalid hostname")
        return v


class DeviceOut(ORM, DeviceIn):
    id: int


class SubnetIn(BaseModel):
    section_id: int
    cidr: str = Field(max_length=49)
    vrf_id: int | None = None
    vlan_id: int | None = None
    description: str | None = Desc


class SubnetOut(ORM):
    id: int
    section_id: int
    cidr: str
    version: int
    vrf_id: int | None
    vlan_id: int | None
    description: str | None


class SubnetUsage(SubnetOut):
    total: int
    used: int
    free: int
    percent_used: float
    next_free: str | None


class AddressIn(BaseModel):
    ip: str = Field(max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    mac: str | None = Field(default=None, max_length=17)
    status: AddrStatus = AddrStatus.used
    device_id: int | None = None
    description: str | None = Desc

    @field_validator("mac")
    @classmethod
    def _m(cls, v):
        if v and not _MAC.match(v):
            raise ValueError("Invalid MAC address")
        return v.lower().replace("-", ":") if v else v

    @field_validator("hostname")
    @classmethod
    def _h(cls, v):
        if v and not _HOST.match(v):
            raise ValueError("Invalid hostname")
        return v


class AddressOut(ORM):
    id: int
    subnet_id: int
    ip: str
    hostname: str | None
    mac: str | None
    status: AddrStatus
    device_id: int | None
    description: str | None
    last_seen: datetime | None


class AuditOut(ORM):
    id: int
    at: datetime
    actor: str
    action: str
    target: str
    detail: str | None
    client_ip: str | None
