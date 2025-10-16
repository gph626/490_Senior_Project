# tests/test_assets.py
from backend.database import SessionLocal, Asset

def test_asset_insertion_and_query():
    s = SessionLocal()
    try:
        a = Asset(user_id=42, type='email', value='alice@example.com')
        s.add(a)
        s.commit()
        found = s.query(Asset).filter_by(user_id=42).all()
        assert any(f.value == 'alice@example.com' for f in found)
    finally:
        s.close()
