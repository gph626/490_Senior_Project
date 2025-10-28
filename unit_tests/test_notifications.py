import os
import importlib
from unittest import mock


def test_send_email_noop(monkeypatch):
    # Ensure MAIL_ENABLED not set
    monkeypatch.delenv("MAIL_ENABLED", raising=False)

    # Import fresh to pick up env
    import backend.notifications as notifications
    importlib.reload(notifications)

    assert notifications.is_mail_enabled() is False
    ok = notifications.send_email("test@example.com", "sub", "body")
    assert ok is True


def test_send_email_with_smtp(monkeypatch):
    # Enable mail and configure SMTP to use SMTP + STARTTLS path
    monkeypatch.setenv("MAIL_ENABLED", "1")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.local")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "user1")
    monkeypatch.setenv("SMTP_PASS", "pass1")
    monkeypatch.setenv("SMTP_FROM", "from@example.local")
    monkeypatch.setenv("SMTP_TLS", "1")
    monkeypatch.delenv("SMTP_SSL", raising=False)

    import backend.notifications as notifications
    importlib.reload(notifications)

    # Create a dummy SMTP class to capture calls
    class DummySMTP:
        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.started = False
            self.logged = False
            self.sent = False

        def starttls(self):
            self.started = True

        def login(self, u, p):
            assert u == 'user1'
            assert p == 'pass1'
            self.logged = True

        def send_message(self, msg):
            # basic sanity checks on the message object
            assert 'Subject' in msg
            assert 'From' in msg
            self.sent = True

        def quit(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr('smtplib.SMTP', DummySMTP)

    ok = notifications.send_email(["to@example.com"], "hi", "hello")
    assert ok is True
