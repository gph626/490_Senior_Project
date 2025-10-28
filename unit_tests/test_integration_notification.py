import importlib
import uuid


def test_insert_leak_triggers_notification(monkeypatch):
    # Ensure mailing is enabled for this test path
    monkeypatch.setenv("MAIL_ENABLED", "1")

    # Some environments running unit tests may not have `flask_login` installed.
    # Provide a lightweight stub module so `backend.database` can import cleanly.
    import sys
    import types
    if 'flask_login' not in sys.modules:
        mod = types.ModuleType('flask_login')
        # Minimal UserMixin placeholder used only for SQLAlchemy model mixin
        class _UserMixin:
            pass
        mod.UserMixin = _UserMixin
        sys.modules['flask_login'] = mod

    # Provide a minimal bcrypt shim for environments that don't have the
    # package installed (we only need gensalt/hashpw/checkpw signatures).
    if 'bcrypt' not in sys.modules:
        bcrypt_mod = types.ModuleType('bcrypt')
        def gensalt(rounds=12):
            return b"$2b$12$testsalttestsalttest"
        def hashpw(pw, salt):
            return b"$2b$12$fakehash"
        def checkpw(pw, stored):
            return True
        bcrypt_mod.gensalt = gensalt
        bcrypt_mod.hashpw = hashpw
        bcrypt_mod.checkpw = checkpw
        sys.modules['bcrypt'] = bcrypt_mod

    # Import database and notifications modules
    import backend.database as db
    import backend.notifications as notifications
    importlib.reload(db)
    importlib.reload(notifications)

    # Replace send_email with a fake to capture calls
    calls = {}

    def fake_send_email(to_addrs, subject, text, html=None):
        calls['to'] = to_addrs
        calls['subject'] = subject
        calls['text'] = text
        return True

    # The database module imported `send_email` into its own namespace, so
    # patch that reference as well to intercept calls originating from
    # `backend.database.insert_leak_with_dedupe`.
    monkeypatch.setattr('backend.notifications.send_email', fake_send_email)
    monkeypatch.setattr('backend.database.send_email', fake_send_email)

    # Create a unique test user directly via SessionLocal to avoid bcrypt dependency
    username = f"notif_test_{uuid.uuid4().hex[:8]}"
    email = f"{username}@example.test"
    session = db.SessionLocal()
    try:
        user = db.User(username=username, email=email, password_hash='x')
        session.add(user)
        session.commit()
        session.refresh(user)
        user_id = user.id
    finally:
        session.close()

    try:
        # Insert a new leak with a unique content_hash so dedupe doesn't trigger
        content_hash = 'unittest-' + uuid.uuid4().hex
        new_id, is_dup = db.insert_leak_with_dedupe(
            source='unittest',
            url='http://example.test/leak',
            title='Unit Test Leak',
            content='sensitive data here',
            content_hash=content_hash,
            entities={},
            user_id=user_id,
        )

        assert is_dup is False

        # Ensure our fake send_email was called and targeted the user's email
        assert 'to' in calls
        # send_email may receive a single email string or list; normalize
        to_val = calls['to']
        if isinstance(to_val, (list, tuple)):
            assert email in to_val
        else:
            assert to_val == email

    finally:
        # Clean up created user and their leaks
        try:
            db.delete_user(user_id)
        except Exception:
            pass
