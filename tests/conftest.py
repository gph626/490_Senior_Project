# tests/conftest.py
import pytest
from backend.database import SessionLocal
from backend.database import User
from werkzeug.security import generate_password_hash


TEST_USERNAME = "anna_test"
TEST_PASSWORD = "password123"

@pytest.fixture(scope="session", autouse=True)
def create_test_user():
    session = SessionLocal()
    session.query(User).filter_by(username=TEST_USERNAME).delete()
    session.commit()

    user = User(
        username=TEST_USERNAME,
        email="anna_test@example.com",
        password_hash=generate_password_hash(TEST_PASSWORD)
    )
    session.add(user)
    session.commit()
    session.close()