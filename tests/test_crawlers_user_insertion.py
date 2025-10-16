# tests/test_crawlers_user_insertion.py
from backend.app import app
from backend.database import get_leaks_for_user


def test_i2p_mock_inserts_user_leak(client=None):
    client = client or app.test_client()

    # Simulate login as user 5
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['user_id'] = 5
        sess['username'] = "i2puser"

    resp = client.post("/api/crawlers/i2p/run", json={"mock": True})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["mocked"] is True

    leaks = get_leaks_for_user(5)
    assert any("I2P mock leak" in (l.normalized.get("title") if l.normalized else "") for l in leaks)
