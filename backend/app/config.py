"""Application settings, loaded from environment variables (prefix IPAM_)."""
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IPAM_", env_file=".env", extra="ignore")

    # Database: either a full SQLAlchemy URL, or the separate fields below (preferred: the
    # password is escaped automatically, so it may contain @ / : etc.).
    database_url: str | None = None
    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_name: str = "ipam"
    db_user: str = "ipam"
    db_password: str | None = None
    # No default on purpose: the app refuses to start without a strong key.
    secret_key: str = Field(min_length=32)
    access_token_minutes: int = 15
    cors_origins: list[str] = []
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # Optional LDAP / Active Directory
    ldap_url: str | None = None            # e.g. ldaps://dc1.example.com:636
    ldap_base_dn: str | None = None
    ldap_bind_dn: str | None = None
    ldap_bind_password: str | None = None
    ldap_user_filter: str = "(sAMAccountName={username})"
    ldap_admin_group_dn: str | None = None

    # Public URL used in password-reset links, e.g. https://ipam.example.com
    public_url: str = "https://localhost"
    reset_token_minutes: int = 30

    # SMTP (password reset and notifications). Leave smtp_host empty to disable e-mail.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "ipam@localhost"
    smtp_starttls: bool = True

    # First-start admin (only used when the users table is empty). Remove after first start.
    bootstrap_admin_user: str | None = None
    bootstrap_admin_password: str | None = None

    # Scanner limits
    scan_max_hosts: int = 1024
    scan_workers: int = 32

    def sqlalchemy_url(self):
        if self.database_url:
            return self.database_url
        if not self.db_password:
            raise ValueError("Set IPAM_DB_PASSWORD (or IPAM_DATABASE_URL)")
        from sqlalchemy.engine import URL
        return URL.create("mysql+pymysql", username=self.db_user, password=self.db_password,
                          host=self.db_host, port=self.db_port, database=self.db_name,
                          query={"charset": "utf8mb4"})

    @field_validator("secret_key")
    @classmethod
    def _not_placeholder(cls, v: str) -> str:
        if v.lower().startswith(("change", "secret", "password")):
            raise ValueError("IPAM_SECRET_KEY must be a random value")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
