# tests/test_leaks_user_scope.py
import pytest
from backend.database import insert_leak, get_leaks_for_user, SessionLocal, Leak
from backend.app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def create_user_leak(user_id, source="pastebin", data="testdata", severity="critical"):
    return insert_leak(
        source=source,
        url="https://example.com/test",
        data=data,
        severity=severity,
        normalized={"entities": {"emails": ["user@example.com"]}},
        user_id=user_id
    )


def test_insert_and_get_leaks_for_user(tmp_path):
    # Insert leaks for two users
    leak_a1 = create_user_leak(user_id=1)
    leak_a2 = create_user_leak(user_id=1)
    leak_b1 = create_user_leak(user_id=2)

    leaks_user1 = get_leaks_for_user(1)
    leaks_user2 = get_leaks_for_user(2)

    assert {l.id for l in leaks_user1} == {leak_a1, leak_a2}
    assert {l.id for l in leaks_user2} == {leak_b1}


def test_api_leaks_only_returns_logged_in_users_leaks(client):
    # Insert leaks for user 1 and 2
    leak_a = create_user_leak(user_id=1)
    leak_b = create_user_leak(user_id=2)

    # Simulate login as user 1
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['user_id'] = 1
        sess['username'] = "user1"

    resp = client.get("/api/leaks?limit=100")
    assert resp.status_code == 200
    data = resp.get_json()
    leak_ids = {d['id'] for d in data}
    assert leak_a in leak_ids
    assert leak_b not in leak_ids


def test_api_alerts_user_scope(client):
    # Insert a critical leak for user 2 only
    leak_b = create_user_leak(user_id=2, severity="critical")

    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['user_id'] = 1
        sess['username'] = "user1"

    resp = client.get("/api/alerts")
    data = resp.get_json()
    ids = {d['id'] for d in data}
    assert leak_b not in ids
