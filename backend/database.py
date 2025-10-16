import os
import json
import datetime
from sqlalchemy.sql import func
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, UniqueConstraint, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.types import JSON
from sqlalchemy import text
from flask_login import UserMixin
import sys
from datetime import timedelta
import bcrypt
import secrets

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
api_key = secrets.token_hex(32)


class Leak(Base):
    __tablename__ = 'leaks'
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(128), nullable=False)
    url = Column(String(1024), nullable=True)
    data = Column(Text, nullable=True)
    normalized = Column(JSON, nullable=True)
    severity = Column(String(32), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    user_id = Column(Integer, nullable=True)
    passwords = Column(Text, nullable=True)
    ssn = Column(String(11), nullable=True)
    names = Column(Text, nullable=True)
    phone_numbers = Column(Text, nullable=True)
    physical_addresses = Column(Text, nullable=True)

class CrawlRun(Base):
    __tablename__ = "crawl_runs"
    id = Column(Integer, primary_key=True)
    source = Column(String(128), nullable=False) 
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(32), nullable=True)
    user_id = Column(Integer, nullable=False)


class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, nullable=False, index=True)
    assets = relationship("Asset", back_populates="user", cascade="all, delete-orphan")
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (
        UniqueConstraint('username', name='uq_users_username'),
        UniqueConstraint('email', name='uq_users_email'),
    )
    api_keys = relationship("APIKey", back_populates="user")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # assuming your users table is named 'users'
    type = Column(String, nullable=False)   # e.g., 'email', 'domain', 'ip', 'btc'
    value = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship("User", back_populates="assets")

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)
    user = relationship("User", back_populates="api_keys")


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
            # --- LEAKS table migration ---
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
                'user_id': 'INTEGER',
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

            # --- CRAWL_RUNS table migration ---
            # (only if the table exists — this won't throw if it doesn't)
            crawl_rows = conn.execute(text("PRAGMA table_info('crawl_runs')")).fetchall()
            crawl_cols = [r[1] for r in crawl_rows]

            if crawl_cols:  # only do migration if crawl_runs table exists
                if 'user_id' not in crawl_cols:
                    try:
                        conn.execute(text("ALTER TABLE crawl_runs ADD COLUMN user_id INTEGER"))
                    except Exception as e:
                        print('DB migration: failed to add user_id column to crawl_runs:', e, file=sys.stderr)


        except Exception as e:
            print('DB migration: pragma check failed:', e, file=sys.stderr)


# ------------------ User / Auth Helpers ------------------
def hash_password(plain_password: str) -> str:
    if not isinstance(plain_password, str) or not plain_password:
        raise ValueError("Password must be a non-empty string")
    pw_bytes = plain_password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)  # cost factor 12 (adjust if needed for perf)
    return bcrypt.hashpw(pw_bytes, salt).decode('utf-8')


def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception:
        return False


def create_user(username: str, email: str, password: str) -> int:
    """Create a user with a hashed password. Returns new user id.

    Raises ValueError if username/email already exist or invalid input.
    """
    username_clean = (username or '').strip()
    email_clean = (email or '').strip().lower()
    if not username_clean or not email_clean or not password:
        raise ValueError("username, email, password required")
    session = SessionLocal()
    try:
        # Uniqueness checks
        existing = session.query(User).filter((User.username == username_clean) | (User.email == email_clean)).first()
        if existing:
            raise ValueError("username or email already exists")
        pw_hash = hash_password(password)
        user = User(username=username_clean, email=email_clean, password_hash=pw_hash)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user.id
    finally:
        session.close()


def get_user_by_username_or_email(login: str) -> User | None:
    if not login:
        return None
    login_norm = login.strip().lower()
    session = SessionLocal()
    try:
        user = (
            session.query(User)
            .filter((User.username == login_norm) | (User.email == login_norm))
            .first()
        )
        return user
    finally:
        session.close()


def authenticate_user(login: str, password: str) -> User | None:
    user = get_user_by_username_or_email(login)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def get_assets_for_user(user_id: int):
    """Return all assets belonging to the given user_id."""
    session = SessionLocal()
    try:
        return session.query(Asset).filter(Asset.user_id == user_id).all()
    finally:
        session.close()


def insert_crawl_run(source: str, user_id: int | None, status: str = "started") -> int:
    """Insert a new crawl run row and return its ID."""
    session = SessionLocal()
    try:
        run = CrawlRun(
            source=source,
            status=status,
            user_id=user_id if user_id is not None else 0  # fallback for anonymous runs
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        return run.id
    finally:
        session.close()


def get_crawl_runs_for_user(user_id: int, limit: int = 50):
    """Return the most recent crawl runs for the given user ID."""
    session = SessionLocal()
    try:
        return (
            session.query(CrawlRun)
            .filter(CrawlRun.user_id == user_id)
            .order_by(CrawlRun.started_at.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()


def update_crawl_run_status(run_id: int, status: str):
    session = SessionLocal()
    try:
        run = session.query(CrawlRun).get(run_id)
        if run:
            run.status = status
            run.finished_at = datetime.datetime.utcnow()
            session.commit()
    finally:
        session.close()

def _iter_recent_leaks(limit: int | None = None, user_id: int | None = None):
    """Yield leaks newest-first. Optional limit (None = no explicit cap)."""
    session = SessionLocal()
    try:
        q = session.query(Leak)
        if user_id is not None:
            q = q.filter(Leak.user_id == user_id)
        q = q.order_by(Leak.timestamp.desc())
        if limit:
            q = q.limit(int(limit))
        return q.all()
    finally:
        session.close()


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
        user_id: int | None = None,
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
            user_id=user_id,
        )
        session.add(leak)
        session.commit()
        session.refresh(leak)
        return leak.id
    finally:
        session.close()


def delete_user(user_id: int) -> bool:
    """Delete a user by their ID. Returns True if deleted, False if not found."""
    session = SessionLocal()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        session.delete(user)
        session.commit()
        return True
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
    user_id: int | None = None,
    
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
        user_id=user_id,
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


def get_leaks_for_user(user_id: int):
    """Return all leaks belonging to a specific user."""
    session = SessionLocal()
    try:
        return session.query(Leak).filter(Leak.user_id == user_id).all()
    finally:
        session.close()



if __name__ == "__main__":
    init_db()
    print('Initialized DB at', DB_PATH)
