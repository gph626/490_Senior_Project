import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.types import JSON
from sqlalchemy import text
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('DARKWEB_DB_PATH', os.path.join(BASE_DIR, 'data.sqlite'))
ENGINE = create_engine(f'sqlite:///{DB_PATH}', echo=False, connect_args={"check_same_thread": False})
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


def init_db():
    # Create tables that don't exist yet
    Base.metadata.create_all(bind=ENGINE)

    # Lightweight migration: ensure 'normalized' column exists in SQLite table
    # SQLAlchemy won't auto-add new columns for existing tables, so check and ALTER if needed.
    with ENGINE.connect() as conn:
        try:
            res = conn.execute(text("PRAGMA table_info('leaks')"))
            rows = res.fetchall()
            cols = []
            for r in rows:
                # PRAGMA returns (cid, name, type, notnull, dflt_value, pk)
                try:
                    cols.append(r[1])
                except Exception:
                    # Fallback for different row types
                    cols.append(list(r)[1])

            if 'normalized' not in cols:
                # Add column (SQLite allows adding a column with ALTER TABLE)
                try:
                    conn.execute(text("ALTER TABLE leaks ADD COLUMN normalized JSON"))
                except Exception as e:
                    print('DB migration: failed to add normalized column:', e, file=sys.stderr)
        except Exception as e:
            print('DB migration: pragma check failed:', e, file=sys.stderr)


def insert_leak(source: str, url: str | None, data: str | None, severity: str | None = None, normalized: dict | None = None) -> int:
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
        leak = Leak(source=source, url=url, data=data, severity=severity, normalized=normalized)
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


def insert_leak_with_dedupe(
    *,
    source: str,
    url: str | None,
    title: str | None,
    content: str | None,
    content_hash: str | None,
    severity: str | None = None,
    entities: dict | None = None,
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
    }
    return out


if __name__ == "__main__":
    init_db()
    print('Initialized DB at', DB_PATH)
