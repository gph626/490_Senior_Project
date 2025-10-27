import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from backend import database
from backend.database import SessionLocal, APIKey, Leak, Asset, CrawlRun


def test_delete_user_cascade():
    database.init_db()
    session = SessionLocal()
    try:
        # Create a fresh user
        username = 'cascade_test_user'
        email = 'cascade_test_user@example.com'
        password = 'Password123!'

        # Remove existing if present
        session.query(database.User).filter(database.User.username == username).delete()
        session.commit()

        user_id = database.create_user(username, email, password)

        # Insert related rows
        ak = APIKey(key='testkey-'+str(user_id), user_id=user_id)
        session.add(ak)
        session.commit()

        a = Asset(user_id=user_id, type='email', value=email)
        session.add(a)
        session.commit()

        l = Leak(source='test', url='http://x', data='d', user_id=user_id)
        session.add(l)
        session.commit()

        cr = CrawlRun(source='testcrawl', user_id=user_id)
        session.add(cr)
        session.commit()

        # Ensure rows exist
        assert session.query(APIKey).filter(APIKey.user_id == user_id).count() == 1
        assert session.query(Asset).filter(Asset.user_id == user_id).count() == 1
        assert session.query(Leak).filter(Leak.user_id == user_id).count() == 1
        assert session.query(CrawlRun).filter(CrawlRun.user_id == user_id).count() == 1

    finally:
        session.close()

    # Call the delete function
    ok = database.delete_user(user_id)
    assert ok is True

    # Verify related rows are removed
    session = SessionLocal()
    try:
        assert session.query(APIKey).filter(APIKey.user_id == user_id).count() == 0
        assert session.query(Asset).filter(Asset.user_id == user_id).count() == 0
        assert session.query(Leak).filter(Leak.user_id == user_id).count() == 0
        assert session.query(CrawlRun).filter(CrawlRun.user_id == user_id).count() == 0
        assert session.query(database.User).filter(database.User.id == user_id).count() == 0
    finally:
        session.close()
