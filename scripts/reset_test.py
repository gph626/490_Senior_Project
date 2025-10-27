"""Quick test to reproduce/reset password flow using Flask test client.
Run from repo root with the project's virtualenv activated.
"""
import sys
import os

# Ensure repo root is on path so we can import the backend package when running
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend import app as app_module
from backend.database import init_db, create_user, get_user_by_username_or_email
import json

TEST_USER = {
    'username': 'reset_test_user',
    'email': 'reset_test_user@example.com',
    'password': 'Password123!'
}


def ensure_user():
    init_db()
    try:
        uid = create_user(TEST_USER['username'], TEST_USER['email'], TEST_USER['password'])
        print('Created user id', uid)
    except Exception as e:
        # user likely exists
        existing = get_user_by_username_or_email(TEST_USER['username'])
        if existing:
            print('User exists:', existing.id)
        else:
            print('create_user error:', e)


if __name__ == '__main__':
    ensure_user()
    client = app_module.app.test_client()

    # Get login page to establish session and CSRF token
    r = client.get('/login')
    print('GET /login status:', r.status_code)

    # Read CSRF token from session
    with client.session_transaction() as sess:
        csrf = sess.get('_csrf_token')
    print('CSRF token present:', bool(csrf))

    # Post to login
    login_data = {
        'user_login': TEST_USER['username'],
        'user_password': TEST_USER['password'],
        'csrf_token': csrf
    }
    r = client.post('/login', data=login_data, follow_redirects=True)
    print('POST /login status:', r.status_code)
    # Show whether session has logged_in
    with client.session_transaction() as sess:
        print('session logged_in:', sess.get('logged_in'))
        print('session user_id:', sess.get('user_id'))

    # Now attempt to reset password via /api/reset_password
    new_pw = 'NewPassword123!'
    r = client.post('/api/reset_password', json={'new_password': new_pw})
    try:
        data = r.get_json()
    except Exception:
        data = r.data.decode('utf-8')
    print('POST /api/reset_password status:', r.status_code)
    print('Response JSON / body:', data)

    # Try logging in with new password to verify
    # Start new client to clear session
    client2 = app_module.app.test_client()
    r = client2.get('/login')
    with client2.session_transaction() as sess2:
        csrf2 = sess2.get('_csrf_token')
    r = client2.post('/login', data={'user_login': TEST_USER['username'], 'user_password': new_pw, 'csrf_token': csrf2}, follow_redirects=True)
    print('Login with new password status:', r.status_code)
    with client2.session_transaction() as sess2:
        print('session logged_in after new-login:', sess2.get('logged_in'))

