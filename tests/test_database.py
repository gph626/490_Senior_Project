import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from backend import database


def run_test():
    database.init_db()
    normalized = {'title': 'Sample Paste', 'entities': [], 'source_type': 'paste'}
    nid = database.insert_leak(source='paste_test', url='http://paste.local/1', data='raw content', severity='medium', normalized=normalized)
    print('Inserted id:', nid)
    latest = database.get_latest_leaks(1)
    assert len(latest) == 1
    row = latest[0]
    assert row.source == 'paste_test'
    assert row.normalized is not None
    print('Normalized stored:', row.normalized)

    # --- Password hashing and user creation tests ---
    username = 'testuser1'
    email = 'testuser1@example.com'
    password = 'SuperSecret123!'
    # Remove user if exists (for repeatable test)
    session = database.SessionLocal()
    session.query(database.User).filter(database.User.username == username).delete()
    session.commit()
    session.close()

    user_id = database.create_user(username, email, password)
    print('User created with id:', user_id)
    user = database.get_user_by_username_or_email(username)
    print('Fetched user:', user)
    assert user is not None
    assert user.username == username
    assert user.email == email.lower()
    assert user.password_hash != password  # Should be hashed
    print('Password hash:', user.password_hash)

    # Password verification
    print('Correct password verification:', database.verify_password(password, user.password_hash))
    print('Wrong password verification:', database.verify_password('WrongPassword', user.password_hash))
    assert database.verify_password(password, user.password_hash)
    assert not database.verify_password('WrongPassword', user.password_hash)

    # Authentication
    auth_user = database.authenticate_user(username, password)
    print('Authenticated user:', auth_user)
    assert auth_user is not None
    assert auth_user.username == username
    print('Authentication with wrong password:', database.authenticate_user(username, 'WrongPassword'))
    assert database.authenticate_user(username, 'WrongPassword') is None


if __name__ == '__main__':
    run_test()
