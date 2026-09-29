import asyncio
from datetime import timedelta

import httpx
from conftest import candidate, ingest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select, text
from test_feeds import tf_body, tf_row, uh_body

from app.feeds.base import utcnow
from app.feeds.threatfox import ThreatFoxProvider
from app.feeds.urlhaus import URLhausProvider
from app.main import create_app
from app.models import ProviderState
from app.services.ingestion import UpdateService


def test_app_lifecycle_endpoints_and_database(settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").json() == {"status": "ok", "database": "ok"}
        assert client.get("/lists/domains.txt").text == ""
        ingest(client.app.state.db, settings)
        ingest(
            client.app.state.db,
            settings,
            "urlhaus",
            [candidate("evil.example", "hostname", confidence=None)],
        )
        ingest(client.app.state.db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
        response = client.get("/lists/domains.txt")
        assert response.text == "evil.example\n"
        assert response.headers["content-type"].startswith("text/plain")
        assert response.headers["cache-control"] == "no-store"
        lookup = client.get("/api/iocs/EVIL.example.").json()
        assert lookup["blocked"] and len(lookup["sources"]) == 2
        assert lookup["policy_reasons"] == ["eligible_source_evidence"]
        assert client.get("/api/iocs?limit=1").json()["total"] == 2
        assert len(client.get("/api/iocs?limit=1&offset=1").json()["items"]) == 1
        assert client.get("/api/iocs?ioc_type=ipv4").json()["items"][0]["ioc"] == "8.8.8.8"
        assert client.get("/api/iocs?limit=501").status_code == 422
        assert client.get("/api/iocs/absent.example").status_code == 404
        assert client.get("/api/iocs/bad%20host").status_code == 422
        stats = client.get("/api/stats").json()
        assert (stats["total_iocs"], stats["blocked_domains"], stats["tracked_ips"]) == (2, 1, 1)
        assert stats["sources"]["urlhaus"]["ioc_count"] == 1
        with client.app.state.db.session() as session:
            assert session.scalar(text("PRAGMA journal_mode")) == "wal"
            assert session.scalar(text("PRAGMA foreign_keys")) == 1
    # Persisted data survives a new application lifespan.
    with TestClient(create_app(settings)) as client:
        assert client.get("/lists/domains.txt").text == "evil.example\n"


async def test_failure_isolation_and_cooldown(db, settings, caplog):
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.host == "urlhaus-api.abuse.ch":
            return httpx.Response(503, text="NEVER_LOG_THIS_SECRET")
        return httpx.Response(200, content=tf_body(tf_row()))

    providers = [
        URLhausProvider("NEVER_LOG_THIS_SECRET", settings.http),
        ThreatFoxProvider("key", settings.http),
    ]
    service = UpdateService(db, settings, providers, httpx.MockTransport(handler))
    assert service.trigger()
    assert not service.trigger()
    await service.task
    assert service.last_result["providers"]["urlhaus"]["status"] == "failed"
    assert service.last_result["providers"]["threatfox"]["new"] == 1
    with db.session() as session:
        assert session.get(ProviderState, "urlhaus").last_failure is not None
        assert session.get(ProviderState, "threatfox").last_success is not None
    assert "NEVER_LOG_THIS_SECRET" not in caplog.text
    assert service.trigger()
    await service.task
    assert len(requests) == 2  # Persisted five-minute provider cooldown, even for manual runs.
    assert all(p["status"] == "cooldown" for p in service.last_result["providers"].values())


async def test_rate_limit_persisted_and_recovery(db, settings):
    status = 429

    def handler(request):
        return httpx.Response(status, headers={"Retry-After": "3600"}, content=tf_body(tf_row()))

    service = UpdateService(
        db, settings, [ThreatFoxProvider("key", settings.http)], httpx.MockTransport(handler)
    )
    service.trigger()
    await service.task
    with db.session.begin() as session:
        state = session.get(ProviderState, "threatfox")
        assert state.next_allowed_at > utcnow() + timedelta(minutes=59)
        state.next_allowed_at = utcnow() - timedelta(seconds=1)
    status = 200
    service.trigger()
    await service.task
    with db.session() as session:
        state = session.get(ProviderState, "threatfox")
        assert state.last_success and state.last_failure and state.last_error is None


async def test_full_mocked_pipeline_and_overlap(settings):
    gate = asyncio.Event()
    started = asyncio.Event()

    async def handler(request):
        started.set()
        await gate.wait()
        return httpx.Response(
            200,
            content=uh_body() if request.url.host == "urlhaus-api.abuse.ch" else tf_body(tf_row()),
        )

    settings.urlhaus_auth_key = SecretStr("fake-key")
    settings.threatfox_auth_key = SecretStr("fake-key")
    app = create_app(settings, httpx.MockTransport(handler))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://test"
        ) as client:
            assert (await client.post("/api/update")).status_code == 202
            await started.wait()
            assert (await client.post("/api/update")).status_code == 409
            # Request remains responsive while HTTP ingestion is waiting.
            assert (await client.get("/health")).status_code == 200
            gate.set()
            await app.state.updates.task
            assert (await client.get("/lists/domains.txt")).text == "evil.example\n"
            detail = (await client.get("/api/iocs/evil.example")).json()
            assert len(detail["sources"]) == 2
            assert {s["confidence"] for s in detail["sources"]} == {90, None}
            assert (await client.get("/api/stats")).json()["total_iocs"] == 1


def test_expiry_at_read_time_without_updates(settings):
    with TestClient(create_app(settings)) as client:
        ingest(client.app.state.db, settings)
        assert client.get("/lists/domains.txt").text
        from app.models import Observation

        with client.app.state.db.session.begin() as session:
            session.scalar(select(Observation)).expires_at = utcnow() - timedelta(seconds=1)
        assert client.get("/lists/domains.txt").text == ""
        assert not client.get("/api/iocs/evil.example").json()["active"]


def test_no_keys_starts_and_records_safe_errors(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.post("/api/update").status_code == 202
    assert all(
        p["error"] == "missing_api_key" for p in app.state.updates.last_result["providers"].values()
    )
