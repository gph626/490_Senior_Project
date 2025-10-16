import os
import re
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base

# Separate SQLite file for assets of interest (watchlist)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DB_PATH = os.environ.get('ASSETS_DB_PATH', os.path.join(BASE_DIR, 'assets.sqlite'))
ASSETS_ENGINE = create_engine(f'sqlite:///{ASSETS_DB_PATH}', echo=False, connect_args={"check_same_thread": False})
AssetsSession = sessionmaker(autocommit=False, autoflush=False, bind=ASSETS_ENGINE)
AssetsBase = declarative_base()
ALLOWED_ASSET_TYPES = {'email', 'domain', 'ip', 'btc', 'ssn', 'phone', 'address', 'name'}


class Asset(AssetsBase):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(16), nullable=False)  # email, domain, ip, btc
    value = Column(String(512), nullable=False)  # normalized lower-case
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (
        UniqueConstraint('type', 'value', name='uq_asset_type_value'),
    )


def init_assets_db():
    AssetsBase.metadata.create_all(bind=ASSETS_ENGINE)


def upsert_asset(asset_type: str, value: str) -> int:
    init_assets_db()
    if not asset_type or not value:
        raise ValueError('type and value are required')
    asset_type = asset_type.strip().lower()
    value_norm = value.strip().lower()
    
    if asset_type not in ALLOWED_ASSET_TYPES:
        raise ValueError(f"type must be one of: {', '.join(ALLOWED_ASSET_TYPES)}")

    # Additional normalization for specific types
    if asset_type == 'phone':
        value_norm = re.sub(r'\D', '', value_norm)  # keep only digits
    elif asset_type == 'ssn':
        value_norm = value_norm.replace('-', '').strip()
    elif asset_type == 'name':
        value_norm = value_norm.strip().lower()

    session = AssetsSession()
    try:
        existing = session.query(Asset).filter(Asset.type == asset_type, Asset.value == value_norm).first()
        if existing:
            return existing.id
        obj = Asset(type=asset_type, value=value_norm)
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj.id
    finally:
        session.close()


def list_assets() -> list[dict]:
    init_assets_db()
    session = AssetsSession()
    try:
        rows = session.query(Asset).order_by(Asset.created_at.desc()).all()
        return [
            {
                'id': r.id,
                'type': r.type,
                'value': r.value,
                'created_at': r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    finally:
        session.close()


def delete_asset(asset_id: int) -> bool:
    init_assets_db()
    session = AssetsSession()
    try:
        obj = session.query(Asset).filter(Asset.id == asset_id).first()
        if not obj:
            return False
        session.delete(obj)
        session.commit()
        return True
    finally:
        session.close()


def get_assets_sets() -> dict:
    """Return assets as sets per type for fast membership checks."""
    init_assets_db()
    session = AssetsSession()
    try:
        out = {
            'email': set(),
            'domain': set(),
            'ip': set(),
            'btc': set(),
            'ssn': set(),
            'phone': set(),
            'address': set(),
            'name': set(),
        }

        for r in session.query(Asset).all():
            out.get(r.type, set()).add(r.value)
        return out
    finally:
        session.close()

# If companies upload CSVs or JSON lists, use this.
def upsert_assets_bulk(assets: list[tuple[str, str]]) -> list[int]:
    """Insert many assets efficiently (type, value). Returns list of IDs."""
    init_assets_db()
    session = AssetsSession()
    ids = []
    try:
        for asset_type, value in assets:
            asset_type = asset_type.strip().lower()
            value_norm = value.strip().lower()

            if asset_type not in ALLOWED_ASSET_TYPES:
                continue

            if asset_type == 'phone':
                value_norm = re.sub(r'\D', '', value_norm)  # keep only digits
            elif asset_type == 'ssn':
                value_norm = value_norm.replace('-', '').strip()
            elif asset_type == 'name':
                value_norm = value_norm.strip().lower()

            existing = session.query(Asset).filter(Asset.type == asset_type, Asset.value == value_norm).first()
            if existing:
                ids.append(existing.id)
                continue
            obj = Asset(type=asset_type, value=value_norm)
            session.add(obj)
            session.flush()
            ids.append(obj.id)
        session.commit()
        return ids
    finally:
        session.close()
