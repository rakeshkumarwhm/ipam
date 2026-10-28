"""Minimal SMTP sender. Never logs message bodies (they contain reset links)."""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from .config import get_settings

log = logging.getLogger(__name__)


def send_mail(to: str, subject: str, body: str) -> bool:
    s = get_settings()
    if not s.smtp_host:
        log.warning("SMTP not configured; e-mail to %s not sent", to)
        return False
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from, to, subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as smtp:
            if s.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if s.smtp_user and s.smtp_password:
                smtp.login(s.smtp_user, s.smtp_password)
            smtp.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError):
        log.exception("Failed to send e-mail to %s", to)
        return False


def send_reset_email(to: str, link: str, minutes: int) -> None:
    send_mail(to, "IPAM password reset",
              f"A password reset was requested for your IPAM account.\n\n"
              f"Open this link within {minutes} minutes to choose a new password:\n{link}\n\n"
              f"If you did not request this, you can ignore this message.")
