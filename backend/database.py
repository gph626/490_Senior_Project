import os
import json
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.types import JSON
from sqlalchemy import text
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('DARKWEB_DB_PATH', os.path.join(BASE_DIR, 'data.sqlite'))
def get_engine():
    """Return a fresh SQLAlchemy engine for the current DB_PATH."""
    return create_engine(
        f"sqlite:///{DB_PATH}",
        echo=False,
        connect_args={"check_same_thread": False}
    )
ENGINE = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=ENGINE)
Base = declarative_base()


class Leak(Base):
    __tablename__ = 'leaks'
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(128), nullable=False)
    url = Column(String(1024), nullable=True)
    data = Column(Text, nullable=True)
    normalized = Column(JSON, nullable=True)
    severity = Column(String(32), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    passwords = Column(Text, nullable=True)
    ssn = Column(String(11), nullable=True)
    names = Column(Text, nullable=True)
    phone_numbers = Column(Text, nullable=True)
    physical_addresses = Column(Text, nullable=True)


def init_db():
    # Refresh engine in case DB_PATH changed 
    global ENGINE, SessionLocal
    ENGINE = get_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=ENGINE)

    # Create tables that don't exist yet
    Base.metadata.create_all(bind=ENGINE)

    # Lightweight migration: ensure 'normalized' column exists in SQLite table
    # SQLAlchemy won't auto-add new columns for existing tables, so check and ALTER if needed.
    with ENGINE.connect() as conn:
        try:
            res = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            # table_names = [r[0] for r in res.fetchall()]

            res = conn.execute(text("PRAGMA table_info('leaks')"))
            rows = res.fetchall()
            cols = [r[1] for r in rows]


            # Ensure 'normalized' column exists
            if 'normalized' not in cols:
                try:
                    conn.execute(text("ALTER TABLE leaks ADD COLUMN normalized JSON"))
                except Exception as e:
                    print('DB migration: failed to add normalized column:', e, file=sys.stderr)

            # Ensure new columns exist
            new_columns = {
                'passwords': 'TEXT',
                'ssn': 'TEXT',
                'names': 'TEXT',
                'phone_numbers': 'TEXT',
                'physical_addresses': 'TEXT'
            }

            for col_name, col_type in new_columns.items():
                if col_name not in cols:
                    try:
                        conn.execute(text(f"ALTER TABLE leaks ADD COLUMN {col_name} {col_type}"))
                    except Exception as e:
                        print(f'DB migration: failed to add {col_name} column:', e, file=sys.stderr)

        except Exception as e:
            print('DB migration: pragma check failed:', e, file=sys.stderr)


def insert_leak(
        source: str,
        url: str | None,
        data: str | None,
        severity: str | None = None,
        normalized: dict | None = None,
        passwords: str | None = None,
        ssn: str | None = None,
        names: str | None = None,
        phone_numbers: str | None = None,
        physical_addresses: str | None = None,
    ) -> int:
    """Insert a leak and return the assigned id.

    Parameters
    - source: origin label (e.g., 'pastebin', 'tor')
    - url: optional source URL
    - data: raw text/html
    - severity: optional severity tag
    - normalized: optional dict following the project-normalized schema
    """
    session = SessionLocal()
    try:
        leak = Leak(
            source=source,
            url=url,
            data=data,
            severity=severity,
            normalized=normalized,
            passwords=passwords,
            ssn=ssn,
            names=names,
            phone_numbers=phone_numbers,
            physical_addresses=physical_addresses,
        )
        session.add(leak)
        session.commit()
        session.refresh(leak)
        return leak.id
    finally:
        session.close()


def find_leak_by_content_hash(content_hash: str) -> Leak | None:
    """Return the most recent leak whose normalized dict has the given content_hash.

    Note: JSON querying varies by SQLite build; we keep it simple by scanning
    normalized dicts in Python for now. For larger datasets, consider adding a
    dedicated column and index for the hash.
    """
    if not content_hash:
        return None
    session = SessionLocal()
    try:
        # Fetch a reasonable window of recent rows to keep this fast in dev
        rows = session.query(Leak).order_by(Leak.timestamp.desc()).limit(1000).all()
        for row in rows:
            try:
                norm = row.normalized or {}
                if isinstance(norm, dict) and norm.get('content_hash') == content_hash:
                    return row
            except (TypeError, ValueError, KeyError):
                continue
        return None
    finally:
        session.close()


def find_leak_by_url(url: str) -> Leak | None:
    """Return the most recent leak with the same URL (normalized lower-case).

    Useful when content_hash is missing.
    """
    if not url:
        return None
    url_norm = (url or '').strip().lower()
    session = SessionLocal()
    try:
        row = (
            session.query(Leak)
            .filter(Leak.url == url_norm)
            .order_by(Leak.timestamp.desc())
            .first()
        )
        return row
    finally:
        session.close()


def find_leaks_with_passwords(limit: int = 50):
    session = SessionLocal()
    try:
        return session.query(Leak).filter(Leak.passwords.isnot(None)).limit(limit).all()
    finally:
        session.close()



def insert_leak_with_dedupe(
    *,
    source: str,
    url: str | None,
    title: str | None,
    content: str | None,
    content_hash: str | None,
    severity: str | None = None,
    entities: dict | None = None,
    passwords: str | None = None,
    ssn: str | None = None,
    names: str | None = None,
    phone_numbers: str | None = None,
    physical_addresses: str | None = None,
) -> tuple[int, bool]:
    """Insert a leak using content_hash as a dedupe key.

    Returns (leak_id, is_duplicate).
    - Stores `content` in the existing `data` column for compatibility.
    - Stores `title`, `entities`, and `content_hash` inside `normalized`.
    """
    # Normalize URL for dedupe
    url_norm = (url or '').strip().lower() or None

    # If we have a hash, check for an existing record
    if content_hash:
        existing = find_leak_by_content_hash(content_hash)
        if existing is not None:
            return existing.id, True
    else:
        # Fallback: dedupe by URL if provided
        existing = find_leak_by_url(url_norm)
        if existing is not None:
            return existing.id, True

    # --- Serialize list fields to JSON strings ---
    def serialize(value):
        if isinstance(value, list):
            return json.dumps(value)
        return value
    
    passwords = serialize(passwords)
    ssn = serialize(ssn)
    names = serialize(names)
    phone_numbers = serialize(phone_numbers)
    physical_addresses = serialize(physical_addresses)

    # Ensure normalized JSON carries at least title and content_hash
    normalized: dict = {
        'title': title,
        'entities': entities or {},
        'content_hash': content_hash,
    }
    new_id = insert_leak(
        source=source,
        url=url_norm,
        data=content,
        severity=severity,
        normalized=normalized,
        passwords=passwords,
        ssn=ssn,
        names=names,
        phone_numbers=phone_numbers,
        physical_addresses=physical_addresses,
    )
    return new_id, False


def get_latest_leaks(limit: int = 10):
    session = SessionLocal()
    try:
        return session.query(Leak).order_by(Leak.timestamp.desc()).limit(limit).all()
    finally:
        session.close()


def leak_to_dict(leak: Leak) -> dict:
    """Convert a Leak ORM object into a plain dict (JSON-serializable)."""
    norm = leak.normalized if leak.normalized is not None else {}
    out = {
        'id': leak.id,
        'source': leak.source,
        'url': leak.url,
        # Keep current field names for compatibility; also expose convenience keys
        'data': leak.data,
        'title': (norm or {}).get('title'),
        'content': leak.data,
        'severity': leak.severity,
        'timestamp': leak.timestamp.isoformat() if leak.timestamp else None,
        'normalized': norm,
        'passwords': leak.passwords,
        'ssn': leak.ssn,
        'names': leak.names,
        'phone_numbers': leak.phone_numbers,
        'physical_addresses': leak.physical_addresses,

    }
    return out


if __name__ == "__main__":
    init_db()
    print('Initialized DB at', DB_PATH)
