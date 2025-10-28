"""Simple SMTP-based notification helpers.

Environment variables:
  MAIL_ENABLED - set to '1' or 'true' to enable sending (default: disabled)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_TLS

This module intentionally keeps a minimal surface so it's safe to import
from other backend modules without creating circular imports.
"""
from __future__ import annotations
import os
import smtplib
import logging
from email.message import EmailMessage
from typing import Iterable

logger = logging.getLogger("notifications")


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "on")


def is_mail_enabled() -> bool:
    return _env_bool("MAIL_ENABLED", False)


def _get_smtp_config():
    host = os.environ.get("SMTP_HOST", "localhost")
    port = int(os.environ.get("SMTP_PORT", "25"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    sender = os.environ.get("SMTP_FROM", os.environ.get("MAIL_FROM", f"noreply@{host}"))
    tls = _env_bool("SMTP_TLS", False)
    use_ssl = _env_bool("SMTP_SSL", False)
    return host, port, user, password, sender, tls, use_ssl


def send_email(to_addrs: Iterable[str] | str, subject: str, text: str, html: str | None = None) -> bool:
    """Send a simple email. Returns True if send attempted (or simulated), False on failure.

    If MAIL_ENABLED is not set, this will only log the message and return True (safe no-op).
    """
    if isinstance(to_addrs, str):
        to = [to_addrs]
    else:
        to = list(to_addrs)

    if not to:
        logger.debug("send_email called with empty recipient list")
        return False

    if not is_mail_enabled():
        logger.info("MAIL_DISABLED - would send email to %s subject=%s", to, subject)
        logger.debug("email body:\n%s", text)
        return True

    host, port, user, password, sender, tls, use_ssl = _get_smtp_config()

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg.set_content(text or "")
    if html:
        msg.add_alternative(html, subtype="html")

    try:
        if use_ssl:
            smtp = smtplib.SMTP_SSL(host, port, timeout=30)
        else:
            smtp = smtplib.SMTP(host, port, timeout=30)
        with smtp:
            if tls and not use_ssl:
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        logger.info("Sent email to %s subject=%s", to, subject)
        return True
    except Exception as e:
        logger.exception("Failed to send email to %s: %s", to, e)
        return False
