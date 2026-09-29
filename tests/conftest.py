import httpx
import pytest

from app.config import Settings
from app.database import Database
from app.feeds.base import Candidate, ParsedFeed, utcnow
from app.services.ingestion import store_feed


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    async def fail_async(*args, **kwargs):
        raise AssertionError("tests must never contact a live HTTP endpoint")

    def fail_sync(*args, **kwargs):
        raise AssertionError("tests must never contact a live HTTP endpoint")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", fail_async)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fail_sync)


@pytest.fixture
def settings(tmp_path):
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        scheduler={"enabled": False, "update_on_start": False},
    )


@pytest.fixture
def db(settings):
    database = Database(settings.database_url)
    database.initialize()
    yield database
    database.engine.dispose()


def candidate(value="evil.example", kind="domain", **kwargs):
    now = utcnow()
    values = dict(
        value=value, ioc_type=kind, external_id="1", confidence=90, first_seen=now, last_seen=now
    )
    values.update(kwargs)
    return Candidate(**values)


def ingest(db, settings, source="threatfox", candidates=None):
    rows = candidates if candidates is not None else [candidate()]
    return store_feed(db, settings, source, ParsedFeed(candidates=rows, fetched=len(rows)))
