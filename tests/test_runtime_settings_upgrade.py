"""Persistent runtime data upgrades, including the historical OTX bare dict."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from app.config import Settings
from app.database import Database
from app.main import create_app
from app.management import load_runtime_settings, save_runtime_setting
from app.models import AdminAccount, ProviderCredential, RuntimeSetting


@pytest.mark.parametrize(
    "raw,expected",
    [(False, False), ("false", False), (0, False), ({"value": False}, False), ("true", True)],
)
def test_legacy_enabled_values(db, settings, raw, expected):
    with db.session.begin() as session:
        session.add(RuntimeSetting(name="provider.otx.enabled", value=raw))
    load_runtime_settings(db, settings)
    assert settings.providers.otx.enabled is expected
    with db.session() as session:
        assert session.get(RuntimeSetting, "provider.otx.enabled").value == {"value": expected}


def test_existing_db_bare_otx_dict_does_not_raise_keyerror(db, settings):
    state = {
        "retrieval": "activity fallback",
        "subscribed_retry_after": "2026-10-03T12:00:00+00:00",
    }
    with db.session.begin() as session:
        session.add(RuntimeSetting(name="otx.retrieval_state", value=state))
    load_runtime_settings(db, settings)
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.retrieval_state").value == {"value": state}


def test_mixed_settings_preserved_and_idempotent(db, settings):
    values = {
        "scheduler.interval": "120",
        "scheduler.enabled": {"value": False},
        "enrichment.cache_ttl_hours": 48,
        "policy.otx.enabled": True,
        "policy.otx.official_author_only": "false",
        "policy.otx.max_age_days": {"value": 15},
        "otx.retrieval_state": {"retrieval": "subscribed"},
        "otx.modified_since": "2026-10-02T00:00:00+00:00",
        "future.setting": {"opaque": "preserve"},
    }
    with db.session.begin() as session:
        session.add_all(RuntimeSetting(name=k, value=v) for k, v in values.items())
    load_runtime_settings(db, settings)
    assert settings.scheduler.update_interval_minutes == 120
    assert settings.enrichment.cache_ttl_hours == 48
    assert settings.policy.otx.model_dump() == {
        "enabled": True,
        "official_author_only": False,
        "max_age_days": 15,
    }
    writes = []

    def track(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE"):
            writes.append(statement)

    event.listen(db.engine, "before_cursor_execute", track)
    try:
        load_runtime_settings(db, settings)
    finally:
        event.remove(db.engine, "before_cursor_execute", track)
    assert writes == []
    with db.session() as session:
        assert session.get(RuntimeSetting, "future.setting").value == values["future.setting"]


@pytest.mark.parametrize(
    "raw",
    [{}, {"unexpected": "secret-token"}, None, [], {"value": "secret-token"}, {"value": 366}, True],
)
def test_malformed_falls_back_without_logging_values(db, settings, caplog, raw):
    settings.policy.otx.max_age_days = 42
    with db.session.begin() as session:
        session.add(RuntimeSetting(name="policy.otx.max_age_days", value=raw))
    load_runtime_settings(db, settings)
    assert settings.policy.otx.max_age_days == 42
    assert "policy.otx.max_age_days" in caplog.text
    assert "secret-token" not in caplog.text
    with db.session() as session:
        assert session.get(RuntimeSetting, "policy.otx.max_age_days").value == {"value": 42}


def test_file_database_reopened_by_application(settings):
    # The same SQLite file is reopened across process lifetimes, as in /data in Docker.
    database = Database(settings.database_url)
    database.initialize()
    with database.session.begin() as session:
        session.add_all(
            [
                RuntimeSetting(name="otx.retrieval_state", value={"retrieval": "activity"}),
                RuntimeSetting(name="policy.otx.max_age_days", value="17"),
                AdminAccount(id=1, password_hash="existing-hash"),
                ProviderCredential(source="virustotal", ciphertext="existing-encrypted-key"),
            ]
        )
    database.engine.dispose()
    for _ in range(2):
        fresh = Settings(
            database_url=settings.database_url,
            scheduler={"enabled": False, "update_on_start": False},
        )
        with TestClient(create_app(fresh)) as client:
            assert client.get("/lists/domains.txt").status_code == 200
            assert fresh.policy.otx.max_age_days == 17
            with client.app.state.db.session() as session:
                assert session.get(AdminAccount, 1).password_hash == "existing-hash"
                assert (
                    session.get(ProviderCredential, "virustotal").ciphertext
                    == "existing-encrypted-key"
                )
                assert len(list(session.scalars(select(RuntimeSetting)))) == 2


def test_future_writes_are_canonical(db):
    save_runtime_setting(db, "otx.retrieval_state", {"retrieval": "subscribed"})
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.retrieval_state").value == {
            "value": {"retrieval": "subscribed"}
        }


@pytest.mark.parametrize(
    "name,raw,expected",
    [
        ("otx.retrieval_state", [], {}),
        ("otx.retrieval_state", {"retrieval": "invalid"}, {}),
        ("otx.modified_since", {"missing": "secret-token"}, None),
        ("enrichment.virustotal.next_allowed_at", 123, None),
    ],
)
def test_malformed_provider_state(db, settings, caplog, name, raw, expected):
    with db.session.begin() as session:
        session.add(RuntimeSetting(name=name, value=raw))
    load_runtime_settings(db, settings)
    assert name in caplog.text
    assert "secret-token" not in caplog.text
    with db.session() as session:
        assert session.get(RuntimeSetting, name).value == {"value": expected}


def test_upgrade_preserves_other_tables(db, settings):
    from datetime import timedelta

    from app.database import Base
    from app.feeds.base import utcnow
    from app.models import IOC, IOCEnrichment
    from tests.conftest import ingest

    ingest(db, settings)
    with db.session.begin() as session:
        ioc = session.scalar(select(IOC))
        session.add(
            IOCEnrichment(
                ioc_id=ioc.id,
                provider="virustotal",
                result={"existing": "cache"},
                queried_at=utcnow(),
                expires_at=utcnow() + timedelta(hours=24),
            )
        )
        session.add(AdminAccount(id=1, password_hash="existing-hash"))
        session.add(ProviderCredential(source="otx", ciphertext="encrypted"))
        session.add(RuntimeSetting(name="otx.retrieval_state", value={"retrieval": "activity"}))

    def snapshot():
        with db.engine.connect() as connection:
            return {
                table.name: connection.execute(select(table)).all()
                for table in Base.metadata.sorted_tables
                if table.name != "runtime_settings"
            }

    before = snapshot()
    load_runtime_settings(db, settings)
    assert snapshot() == before
