# tests/test_risk_summary_user_scope.py
from backend.database import insert_leak
from backend.analytics import severity_counts, asset_risk
from backend.utils import get_assets_sets
import pytest
from backend.database import Base, SessionLocal
from sqlalchemy import create_engine
engine = create_engine("sqlite:///./backend.db", connect_args={"check_same_thread": False})
@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    

def test_severity_counts_user_specific(monkeypatch):
    # Insert 2 critical leaks for user 1, 1 for user 2
    from backend.database import SessionLocal, Leak
    session = SessionLocal()
    session.query(Leak).delete()
    session.commit()
    session.close()

    insert_leak(source="pastebin", url="x", data="u1a", severity="critical", user_id=1)
    insert_leak(source="pastebin", url="y", data="u1b", severity="high", user_id=1)
    insert_leak(source="pastebin", url="z", data="u2", severity="critical", user_id=2)

    # Monkeypatch _iter_recent_leaks to only return user 1's leaks
    from backend import database
    leaks_user1 = database.get_leaks_for_user(1)
    monkeypatch.setattr(database, "_iter_recent_leaks", lambda limit=None: leaks_user1)

    counts = severity_counts(limit=1000)
    assert counts.get("critical", 0) == 1
    assert counts.get("high", 0) == 1
    assert counts.get("medium", 0) == 0


def test_asset_risk_user_specific(monkeypatch):
    # Insert a leak with an email entity for user 1 only
    insert_leak(
        source="pastebin",
        url="a",
        data="test leak",
        severity="critical",
        normalized={"entities": {"emails": ["alice@example.com"]}},
        user_id=1
    )
    # Monkeypatch to return user 1 leaks only
    from backend import database
    leaks_user1 = database.get_leaks_for_user(1)
    monkeypatch.setattr(database, "_iter_recent_leaks", lambda limit=None: leaks_user1)

    # Also monkeypatch get_assets_sets to pretend the user is watching that asset
    monkeypatch.setattr("backend.analytics.get_assets_sets", lambda: {"email": {"alice@example.com"}})

    results = asset_risk(limit=1000)
    assert any(r['value'] == 'alice@example.com' and r['risk'] == 'high' for r in results)
