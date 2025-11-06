import os
import json
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, UniqueConstraint, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.types import JSON
from sqlalchemy import text, func
from flask_login import UserMixin
import sys
import bcrypt
import secrets
import logging
from colorama import Fore, Style
from typing import Dict, Set, Any

logger = logging.getLogger("database")

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
    alerted = Column(Integer, default=0)  # 0 = not alerted, 1 = alerted

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


class Config(Base):
    __tablename__ = "configs"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, unique=True, index=True, nullable=False)
    config_data = Column(JSON, nullable=False)  # Store entire config as JSON
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class AlertHistory(Base):
    __tablename__ = "alert_history"
    id = Column(Integer, primary_key=True)
    leak_id = Column(Integer, ForeignKey("leaks.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    alert_type = Column(String, nullable=False)  # 'webhook' or 'email'
    destination = Column(String, nullable=False)  # webhook URL or email address
    status = Column(String, nullable=False)  # 'sent', 'failed', 'pending'
    error_message = Column(Text, nullable=True)
    sent_at = Column(DateTime, default=datetime.datetime.utcnow)
    leak = relationship("Leak")
    user = relationship("User")


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
        # Do a case-insensitive match for both username and email so users
        # can login using either value regardless of case.
        user = (
            session.query(User)
            .filter((func.lower(User.username) == login_norm) | (func.lower(User.email) == login_norm))
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


def get_asset_sets_for_user(user_id: int) -> Dict[str, Set[str]]:
    """Return asset values grouped into sets, keyed to match entity names used by severity.

    Keys: emails, domains, ips, btc_wallets, ssns, phone_numbers, passwords, physical_addresses, names
    Note: Sensitive types are stored hashed in DB (sha256 hex); values are returned as-is for comparison.
    """
    rows = get_assets_for_user(user_id) or []
    out: Dict[str, Set[str]] = {
        'emails': set(),
        'domains': set(),
        'ips': set(),
        'btc_wallets': set(),
        'ssns': set(),
        'phone_numbers': set(),
        'passwords': set(),
        'physical_addresses': set(),
        'names': set(),
    }
    for a in rows:
        t = (a.type or '').strip().lower()
        v = (a.value or '').strip()
        if not t or not v:
            continue
        if t == 'email':
            out['emails'].add(v.lower())
        elif t == 'domain':
            out['domains'].add(v.lower())
        elif t == 'ip':
            out['ips'].add(v.lower())
        elif t == 'btc':
            out['btc_wallets'].add(v)
        elif t == 'ssn':
            out['ssns'].add(v)
        elif t == 'phone':
            out['phone_numbers'].add(v)
        elif t == 'password':
            out['passwords'].add(v)
        elif t == 'address':
            out['physical_addresses'].add(v)
        elif t == 'name':
            out['names'].add(v)
    return out


def _parse_maybe_json_list(val: Any) -> list[str]:
    if not val:
        return []
    if isinstance(val, list):
        return [str(x) for x in val]
    s = str(val)
    try:
        j = json.loads(s)
        return [str(x) for x in j] if isinstance(j, list) else [s]
    except Exception:
        return [s]


def _build_entities_from_leak(leak: Leak) -> Dict[str, Any]:
    norm = leak.normalized or {}
    ents = (norm.get('entities') or {}) if isinstance(norm, dict) else {}
    # Ensure list types are lists; include top-level columns (which are JSON strings)
    def lower_list(arr):
        return [str(x).lower() for x in arr]

    emails = lower_list(ents.get('emails') or [])
    domains = lower_list(ents.get('domains') or [])
    ips = lower_list(ents.get('ips') or [])
    btcs = ents.get('btc_wallets') or []
    entity = {
        'emails': emails,
        'domains': domains,
        'ips': ips,
        'btc_wallets': btcs,
        'ssns': _parse_maybe_json_list(leak.ssn),
        'phone_numbers': _parse_maybe_json_list(leak.phone_numbers),
        'passwords': _parse_maybe_json_list(leak.passwords),
        'physical_addresses': _parse_maybe_json_list(leak.physical_addresses),
        'names': _parse_maybe_json_list(leak.names),
    }
    return entity


def recompute_severity_for_user_leaks(user_id: int) -> int:
    """Recompute severity for all leaks of a user based on current assets.

    Returns number of leaks updated.
    """
    from backend.severity import compute_severity_with_assets
    assets_sets = get_asset_sets_for_user(user_id)
    session = SessionLocal()
    updated = 0
    try:
        leaks = session.query(Leak).filter(Leak.user_id == user_id).all()
        for lk in leaks:
            ents = _build_entities_from_leak(lk)
            new_sev = compute_severity_with_assets(ents, assets_sets)
            if (lk.severity or '').lower() != new_sev:
                old_severity = lk.severity
                lk.severity = new_sev
                # Reset alerted status when severity changes so it can be re-alerted
                lk.alerted = 0
                updated += 1
                logger.info(f"Leak {lk.id}: severity changed from '{old_severity}' to '{new_sev}', reset alerted=0")
        if updated:
            session.commit()
        return updated
    finally:
        session.close()


def recompute_severity_for_leak(leak_id: int) -> bool:
    """Recompute severity for a single leak based on current assets.

    Returns True if updated, False otherwise.
    """
    from backend.severity import compute_severity_with_assets
    session = SessionLocal()
    try:
        lk = session.query(Leak).get(leak_id)
        if not lk or not lk.user_id:
            return False
        assets_sets = get_asset_sets_for_user(lk.user_id)
        ents = _build_entities_from_leak(lk)
        new_sev = compute_severity_with_assets(ents, assets_sets)
        if (lk.severity or '').lower() != new_sev:
            old_severity = lk.severity
            lk.severity = new_sev
            # Reset alerted status when severity changes so it can be re-alerted
            lk.alerted = 0
            session.commit()
            logger.info(f"Leak {leak_id}: severity changed from '{old_severity}' to '{new_sev}', reset alerted=0")
            return True
        return False
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

def find_leak_by_content_hash(content_hash: str, user_id: int | None = None) -> Leak | None:
    """Return the most recent leak for this user whose normalized dict has the given content_hash."""
    if not content_hash:
        return None

    session = SessionLocal()
    try:
        query = session.query(Leak).order_by(Leak.timestamp.desc())

        # Only check leaks for this specific user; never mix across users
        if user_id is not None:
            query = query.filter(Leak.user_id == user_id)
        else:
            # If user_id is missing, skip dedupe entirely to avoid cross-user conflicts
            return None

        rows = query.limit(1000).all()
        for row in rows:
            try:
                norm = row.normalized or {}
                if isinstance(norm, dict) and norm.get('content_hash') == content_hash:
                    return row
            except Exception:
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
        existing = find_leak_by_content_hash(content_hash, user_id)
        if existing is not None and existing.user_id == user_id:
            # Duplicate only if this user already owns it
            print(f"[DUPLICATE] Skipping {source} leak (hash={content_hash[:12]}) for user {user_id}")
            return existing.id, True

    else:
        # Fallback: dedupe by URL if provided
        existing = find_leak_by_url(url_norm)
        if existing is not None:
            print(f"{Fore.YELLOW}[DUPLICATE]{Style.RESET_ALL} Skipping {source} leak (url={url_norm})")
            logger.info("Duplicate leak skipped (url=%s, source=%s)", url_norm, source)
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

    # Compute severity based on user assets (if available). If no user_id, fallback to entity-only.
    try:
        from backend.severity import compute_severity_with_assets, compute_severity_from_entities
        if user_id is not None:
            assets_sets = get_asset_sets_for_user(user_id)
            severity = compute_severity_with_assets(entities or {}, assets_sets)
        else:
            severity = compute_severity_from_entities(entities)
    except Exception:
        pass

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
    print(f"{Fore.GREEN}[NEW]{Style.RESET_ALL} Inserted {source} leak (id={new_id}, hash={content_hash[:12] if content_hash else 'n/a'})")
    logger.info("Inserted new leak (id=%s, source=%s, hash=%s)", new_id, source, content_hash)
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
        'alerted': leak.alerted if hasattr(leak, 'alerted') else 0,

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
