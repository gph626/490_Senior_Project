import sys
import types

# Some optional runtime deps (like flask_login) may not be installed in the
# test environment used here. Provide a minimal stub before importing the
# project's modules so imports succeed.
if 'flask_login' not in sys.modules:
    mod = types.ModuleType('flask_login')
    # provide a simple UserMixin placeholder used by the ORM model
    class UserMixin:
        pass
    mod.UserMixin = UserMixin
    sys.modules['flask_login'] = mod

from backend import database
from backend.database import SessionLocal, APIKey, User, create_user, delete_user


def test_delete_user_removes_api_keys():
    # Ensure DB/tables exist
    database.init_db()

    # Clean up any previous test user with the same username
    username = 'pytest_delete_user'
    email = 'pytest_delete_user@example.com'
    session = SessionLocal()
    # Remove any previous users with this username and any test API keys
    session.query(User).filter(User.username == username).delete(synchronize_session=False)
    session.query(APIKey).filter(APIKey.key == 'test-delete-key').delete(synchronize_session=False)
    session.commit()
    session.close()

    # Create a fresh user
    user_id = create_user(username, email, 'TestPassword123!')

    # Attach an API key for that user
    session = SessionLocal()
    api = APIKey(user_id=user_id, key='test-delete-key')
    session.add(api)
    session.commit()
    session.close()

    # Verify the API key exists
    session = SessionLocal()
    keys_before = session.query(APIKey).filter(APIKey.user_id == user_id).count()
    session.close()
    assert keys_before >= 1

    # Call the deletion helper
    ok = delete_user(user_id)
    assert ok is True

    # Verify user and associated api keys are gone
    session = SessionLocal()
    u = session.query(User).filter(User.id == user_id).first()
    keys_after = session.query(APIKey).filter(APIKey.user_id == user_id).count()
    session.close()

    assert u is None
    assert keys_after == 0
