from backend.database import SessionLocal, APIKey
import secrets
from backend.app import app


def test_i2p_mock_inserts_user_leak():
    client = app.test_client()

    # Simulate login
    with client.session_transaction() as sess:
        # Use Flask-Login session key so current_user is populated in tests
        sess['_user_id'] = str(5)
        sess['user_id'] = 5
        sess['username'] = "i2puser"

    # Ensure user 5 has an API key
    session = SessionLocal()
    try:
        key_obj = session.query(APIKey).filter_by(user_id=5).first()
        if not key_obj:
            new_key = secrets.token_hex(32)
            key_obj = APIKey(user_id=5, key=new_key)
            session.add(key_obj)
            session.commit()
            session.refresh(key_obj)
        api_key = key_obj.key
    finally:
        session.close()

    # Send the mock crawler request with API key
    resp = client.post(
        "/api/crawlers/i2p/run",
        json={"mock": True},
        headers={"X-API-Key": api_key}
    )

    assert resp.status_code == 200, resp.data