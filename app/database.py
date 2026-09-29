from datetime import UTC
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("timezone-aware datetime required")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=UTC) if value else None


class Database:
    def __init__(self, url: str):
        parsed = make_url(url)
        if parsed.drivername != "sqlite":
            raise ValueError("Milestone 1 requires sqlite")
        memory = parsed.database in (None, "", ":memory:")
        if not memory:
            Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
        kwargs = {"poolclass": StaticPool} if memory else {}
        self.engine = create_engine(
            url, connect_args={"check_same_thread": False, "timeout": 30}, **kwargs
        )

        @event.listens_for(self.engine, "connect")
        def configure(connection, _):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

        self.session = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self):
        from app import models  # noqa: F401

        Base.metadata.create_all(self.engine)
