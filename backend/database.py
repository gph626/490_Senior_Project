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


def get_latest_leaks(limit: int = 10):
    session = SessionLocal()
    try:
        return session.query(Leak).order_by(Leak.timestamp.desc()).limit(limit).all()
    finally:
        session.close()


def leak_to_dict(leak: Leak) -> dict:
    """Convert a Leak ORM object into a plain dict (JSON-serializable)."""
    out = {
        'id': leak.id,
        'source': leak.source,
        'url': leak.url,
        'data': leak.data,
        'severity': leak.severity,
        'timestamp': leak.timestamp.isoformat() if leak.timestamp else None,
        'normalized': leak.normalized if leak.normalized is not None else None,
    }
    return out


if __name__ == "__main__":
    init_db()
    print('Initialized DB at', DB_PATH)
