"""Test that username and email uniqueness constraints are enforced during registration."""
import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from backend import database


def test_unique_username():
    """Test that duplicate usernames are rejected."""
    database.init_db()
    session = database.SessionLocal()
    
    # Clean up any existing test users
    session.query(database.User).filter(
        database.User.username.in_(['uniquetest1', 'uniquetest2'])
    ).delete(synchronize_session=False)
    session.commit()
    session.close()
    
    # Create first user
    user_id1 = database.create_user('uniquetest1', 'user1@example.com', 'Password123!')
    assert user_id1 is not None
    print(f'✓ Created user with username "uniquetest1" and email "user1@example.com"')
    
    # Try to create another user with the same username but different email
    try:
        database.create_user('uniquetest1', 'user2@example.com', 'Password123!')
        assert False, "Should have raised ValueError for duplicate username"
    except ValueError as e:
        error_msg = str(e).lower()
        assert 'username' in error_msg, f"Error message should mention 'username', got: {e}"
        print(f'✓ Correctly rejected duplicate username with error: {e}')


def test_unique_email():
    """Test that duplicate emails are rejected."""
    database.init_db()
    session = database.SessionLocal()
    
    # Clean up any existing test users
    session.query(database.User).filter(
        database.User.email.in_(['unique1@example.com', 'unique2@example.com'])
    ).delete(synchronize_session=False)
    session.commit()
    session.close()
    
    # Create first user
    user_id1 = database.create_user('uniqueuser1', 'unique1@example.com', 'Password123!')
    assert user_id1 is not None
    print(f'✓ Created user with username "uniqueuser1" and email "unique1@example.com"')
    
    # Try to create another user with the same email but different username
    try:
        database.create_user('uniqueuser2', 'unique1@example.com', 'Password123!')
        assert False, "Should have raised ValueError for duplicate email"
    except ValueError as e:
        error_msg = str(e).lower()
        assert 'email' in error_msg, f"Error message should mention 'email', got: {e}"
        print(f'✓ Correctly rejected duplicate email with error: {e}')


def test_unique_both_different():
    """Test that users with different username and email can be created."""
    database.init_db()
    session = database.SessionLocal()
    
    # Clean up any existing test users
    session.query(database.User).filter(
        database.User.username.in_(['unique_both_1', 'unique_both_2'])
    ).delete(synchronize_session=False)
    session.commit()
    session.close()
    
    # Create two users with different credentials
    user_id1 = database.create_user('unique_both_1', 'both1@example.com', 'Password123!')
    user_id2 = database.create_user('unique_both_2', 'both2@example.com', 'Password123!')
    
    assert user_id1 is not None
    assert user_id2 is not None
    assert user_id1 != user_id2
    print(f'✓ Successfully created two users with unique credentials')


if __name__ == '__main__':
    print("\n=== Testing Username Uniqueness ===")
    test_unique_username()
    
    print("\n=== Testing Email Uniqueness ===")
    test_unique_email()
    
    print("\n=== Testing Unique Users Creation ===")
    test_unique_both_different()
    
    print("\n✅ All uniqueness tests passed!")
