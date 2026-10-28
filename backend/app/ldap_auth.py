"""LDAP / Active Directory authentication (search-then-bind)."""
import logging

from ldap3 import Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
import ssl

from .config import get_settings

log = logging.getLogger(__name__)


def ldap_enabled() -> bool:
    s = get_settings()
    return bool(s.ldap_url and s.ldap_base_dn and s.ldap_bind_dn)


def ldap_authenticate(username: str, password: str) -> dict | None:
    """Return {'email', 'is_admin'} on success, None on any failure.

    - The username is escaped before being placed in the search filter (LDAP injection).
    - Empty passwords are rejected (an empty password is an anonymous bind on many servers).
    - Certificates are always validated; use ldaps:// or a StartTLS-capable server.
    """
    s = get_settings()
    if not ldap_enabled() or not password:
        return None
    try:
        tls = Tls(validate=ssl.CERT_REQUIRED)
        server = Server(s.ldap_url, use_ssl=s.ldap_url.startswith("ldaps://"),
                        tls=tls, connect_timeout=5)
        flt = s.ldap_user_filter.format(username=escape_filter_chars(username))
        with Connection(server, s.ldap_bind_dn, s.ldap_bind_password, auto_bind=True,
                        receive_timeout=10) as conn:
            conn.search(s.ldap_base_dn, flt, attributes=["mail", "memberOf"], size_limit=2)
            if len(conn.entries) != 1:
                return None
            entry = conn.entries[0]
            user_dn = entry.entry_dn
            email = str(entry.mail) if "mail" in entry and entry.mail else None
            groups = [g.lower() for g in entry.memberOf.values] if "memberOf" in entry else []
        with Connection(server, user_dn, password, auto_bind=True, receive_timeout=10):
            pass  # successful bind == valid password
        is_admin = bool(s.ldap_admin_group_dn and s.ldap_admin_group_dn.lower() in groups)
        return {"email": email, "is_admin": is_admin}
    except LDAPException:
        log.warning("LDAP authentication failed for %r", username)
        return None
