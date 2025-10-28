import time
import pytest
from backend.app import app as flask_app
import backend.app as ba
from backend.database import SessionLocal, create_user
from tests.conftest import TEST_USERNAME, TEST_PASSWORD


def test_login_sets_session_timestamps():
    flask_app.config['TESTING'] = True
    client = flask_app.test_client()

    # GET login page to set CSRF token
    resp = client.get('/login')
    assert resp.status_code == 200

    # grab csrf token from session
    with client.session_transaction() as sess:
        csrf = sess.get('_csrf_token')
        assert csrf is not None

    # Create a fresh user with the project's password hashing, so authenticate_user succeeds
    username = 'session_test_user'
    password = 'TestPass123!'
    # remove if exists then create
    session = SessionLocal()
    try:
        session.query(session.get_bind().mapper.class_manager.mapper.class_ if False else object)
    except Exception:
        # ignore — we just ensure DB is reachable
        pass
    session.close()
    try:
        create_user(username, f"{username}@example.com", password)
    except ValueError:
        # user may already exist; that's fine
        pass

    # POST login
    resp = client.post('/login', data={'csrf_token': csrf, 'user_login': username, 'user_password': password}, follow_redirects=False)
    # Successful login redirects to /dashboard/
    assert resp.status_code in (302, 303, 301)

    # Check session values
    with client.session_transaction() as sess:
        assert sess.get('logged_in') is True
        assert 'issued_at' in sess
        assert 'last_activity' in sess
        assert isinstance(sess['issued_at'], int)
        assert isinstance(sess['last_activity'], int)
        assert sess['last_activity'] >= sess['issued_at']


def test_idle_timeout_clears_session():
    flask_app.config['TESTING'] = True
    client = flask_app.test_client()

    # ensure a short idle timeout for test
    old_idle = getattr(ba, 'SESSION_IDLE_TIMEOUT_MINUTES', None)
    ba.SESSION_IDLE_TIMEOUT_MINUTES = 0  # force idle expiry

    try:
        resp = client.get('/login')
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            csrf = sess.get('_csrf_token')
        # create fresh user
        username = 'session_test_user_idle'
        password = 'TestPass123!'
        try:
            create_user(username, f"{username}@example.com", password)
        except ValueError:
            pass
        resp = client.post('/login', data={'csrf_token': csrf, 'user_login': username, 'user_password': password}, follow_redirects=False)
        assert resp.status_code in (302, 303, 301)

        # Force last_activity to be sufficiently far in the past so the
        # idle check will expire the session on the next request.
        with client.session_transaction() as sess:
            sess['last_activity'] = int(time.time()) - (ba.SESSION_IDLE_TIMEOUT_MINUTES * 60) - 10

        resp2 = client.get('/dashboard/', follow_redirects=False)
        # After expiry, session should no longer have logged_in
        with client.session_transaction() as sess:
            assert not sess.get('logged_in')
    finally:
        # restore
        if old_idle is not None:
            ba.SESSION_IDLE_TIMEOUT_MINUTES = old_idle


def test_absolute_timeout_clears_session():
    flask_app.config['TESTING'] = True
    client = flask_app.test_client()

    # ensure a short absolute timeout for test
    old_abs = getattr(ba, 'SESSION_ABSOLUTE_TIMEOUT_MINUTES', None)
    ba.SESSION_ABSOLUTE_TIMEOUT_MINUTES = 0  # force absolute expiry

    try:
        resp = client.get('/login')
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            csrf = sess.get('_csrf_token')
        username = 'session_test_user_abs'
        password = 'TestPass123!'
        try:
            create_user(username, f"{username}@example.com", password)
        except ValueError:
            pass
        resp = client.post('/login', data={'csrf_token': csrf, 'user_login': username, 'user_password': password}, follow_redirects=False)
        assert resp.status_code in (302, 303, 301)

        # Force issued_at back in time so absolute expiry triggers
        with client.session_transaction() as sess:
            sess['issued_at'] = int(time.time()) - (ba.SESSION_ABSOLUTE_TIMEOUT_MINUTES * 60) - 10

        resp2 = client.get('/dashboard/', follow_redirects=False)
        with client.session_transaction() as sess:
            assert not sess.get('logged_in')
    finally:
        if old_abs is not None:
            ba.SESSION_ABSOLUTE_TIMEOUT_MINUTES = old_abs
