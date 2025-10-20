import re, secrets
import pytest
import requests
from datetime import datetime, timedelta
from backend.database import SessionLocal, APIKey, create_user
from sqlalchemy import text
import pytest, re, requests
from datetime import datetime, timedelta
from backend.database import init_db, SessionLocal, create_user

BASE_URL = "http://127.0.0.1:5000"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpassword"
TEST_EMAIL = "testuser@example.com"

@pytest.fixture(scope="session", autouse=True)
def setup_test_user():
    """Ensure the test user exists before running any tests."""
    init_db()
    session = SessionLocal()
    try:
        existing = session.execute(
            text("SELECT id FROM users WHERE username=:u OR email=:e"),
            {"u": TEST_USERNAME, "e": TEST_EMAIL}
        ).fetchone()

        if not existing:
            create_user(TEST_USERNAME, TEST_EMAIL, TEST_PASSWORD)
    finally:
        session.close()


@pytest.fixture(scope="session")
def session():
    s = requests.Session()

    # 1. Get CSRF token from the login page
    r = s.get(f"{BASE_URL}/login")
    assert r.status_code == 200, f"Failed to load login page: {r.status_code}"

    match = re.search(r'name="csrf_token" value="(.+?)"', r.text)
    assert match, "CSRF token not found in login page"
    csrf_token = match.group(1)

    # 2. Log in using the real CSRF token
    login_data = {
        "user_login": TEST_USERNAME,
        "user_password": TEST_PASSWORD,
        "csrf_token": csrf_token,
    }
    r = s.post(f"{BASE_URL}/login", data=login_data)
    assert r.status_code in (200, 302), f"Login failed: {r.status_code}"

    # 3. Fetch dashboard HTML and extract API key
    r = s.get(f"{BASE_URL}/dashboard/")
    assert r.status_code == 200, f"Failed to load dashboard: {r.status_code}"
    text = r.text

    marker = 'localStorage.setItem(\'api_key\', "'
    start = text.find(marker)
    assert start != -1, "API key script not found in dashboard HTML"
    start += len(marker)
    end = text.find('"', start)
    api_key = text[start:end]
    assert api_key, "API key could not be extracted"

    return {"session": s, "api_key": api_key}


def test_valid_api_key_allows_crawler_run(session):
    """
    Using a valid API key should return 200.
    """
    headers = {"X-API-Key": session["api_key"], "Content-Type": "application/json"}
    r = session["session"].post(f"{BASE_URL}/api/crawlers/pastebin/run", headers=headers, json={"limit": 1})
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"


def test_missing_api_key_is_rejected(session):
    """
    No API key should return 401.
    """
    r = session["session"].post(f"{BASE_URL}/api/crawlers/pastebin/run", json={"limit": 1})
    assert r.status_code == 401, f"Expected 401 for missing key, got {r.status_code}"


def test_invalid_api_key_is_rejected(session):
    """
    Invalid API key should return 401.
    """
    headers = {"X-API-Key": "invalidkey", "Content-Type": "application/json"}
    r = session["session"].post(f"{BASE_URL}/api/crawlers/pastebin/run", headers=headers, json={"limit": 1})
    assert r.status_code == 401, f"Expected 401 for invalid key, got {r.status_code}"


def test_crawler_rejects_missing_api_key():
    r = requests.post("http://127.0.0.1:5000/api/crawlers/pastebin/run", json={"mock": True})
    assert r.status_code == 401

def test_new_api_key_has_expiry(session):
    s = session["session"]  # from your existing login fixture

    r = s.post(f"{BASE_URL}/api/keys/new")
    assert r.status_code == 200
    data = r.json()
    assert "api_key" in data
    assert "expires_at" in data

    # sanity check: the date string can be parsed
    expires_at = datetime.fromisoformat(data["expires_at"])
    assert expires_at > datetime.utcnow()



def test_crawler_rejects_invalid_api_key():
    headers = {"X-API-Key": "invalid_key_123"}
    r = requests.post("http://127.0.0.1:5000/api/crawlers/pastebin/run", json={"mock": True}, headers=headers)
    assert r.status_code == 401

def test_valid_key_still_allows_crawler(session):
    s = session["session"]
    api_key = session["api_key"]  # pulled from dashboard earlier

    r = s.post(
        f"{BASE_URL}/api/crawlers/pastebin/run",
        headers={"X-API-Key": api_key},
        json={"mock": True}
    )
    assert r.status_code == 200


def test_expired_api_key_is_rejected():
    session_db = SessionLocal()
    try:
        expired_key = "expired_" + secrets.token_hex(8)
        expired_time = datetime.utcnow() - timedelta(days=1)
        key = APIKey(key=expired_key, user_id=1, expires_at=expired_time)
        session_db.add(key)
        session_db.commit()
    finally:
        session_db.close()

    r = requests.post(
        f"{BASE_URL}/api/crawlers/pastebin/run",
        headers={"X-API-Key": expired_key},
        json={"mock": True}
    )
    assert r.status_code == 401
    assert "expired" in r.text.lower()
