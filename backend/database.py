import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

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
    severity = Column(String(32), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=ENGINE)


def insert_leak(source: str, url: str | None, data: str | None, severity: str | None = None) -> int:
    """Insert a leak and return the assigned id."""
    session = SessionLocal()
    try:
        leak = Leak(source=source, url=url, data=data, severity=severity)
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


if __name__ == "__main__":
    init_db()
    print('Initialized DB at', DB_PATH)
