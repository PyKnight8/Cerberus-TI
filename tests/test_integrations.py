import asyncio
import json
from datetime import timedelta

import httpx
import pytest
from conftest import ingest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select
from test_web import login

from app.feeds.base import FeedError, utcnow
from app.feeds.otx import OTXProvider
from app.feeds.virustotal import VirusTotalProvider
from app.main import create_app
from app.models import (
    IOC,
    IOCEnrichment,
    Observation,
    ProviderCredential,
    ProviderUsage,
    SchemaVersion,
)
from app.services.ingestion import UpdateService, store_feed


def pulse(*indicators, next_page=None):
    now = utcnow().isoformat()
    return {
        "next": next_page,
        "results": [
            {
                "id": "pulse-1",
                "name": "Trusted pulse",
                "description": "Threat context",
                "author_name": "researcher",
                "tags": ["malware"],
                "created": now,
                "modified": now,
                "indicators": [
                    {"id": i, "indicator": value, "type": kind, "created": now}
                    for i, (value, kind) in enumerate(indicators, 1)
                ],
            }
        ],
    }


def vt_data():
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 2,
                    "harmless": 20,
                    "undetected": 36,
                },
                "reputation": -5,
                "registrar": "<script>evil()</script>",
                "whois": "Registration context",
                "last_analysis_date": 1700000000,
                "last_analysis_results": {
                    "Engine A": {"category": "malicious", "result": "phishing"},
                    "Engine B": {"category": "harmless", "result": None},
                },
            }
        }
    }


def test_otx_normalization_metadata_dedup(db, settings):
    provider = OTXProvider("secret", settings.http)
    feed = provider.parse(
        json.dumps(
            pulse(
                ("EVIL.Example.", "domain"),
                ("8.8.8.8", "IPv4"),
                ("2001:4860:4860::8888", "IPv6"),
                ("https://host.example/path", "URL"),
                ("bad/value", "domain"),
                ("a" * 64, "FileHash-SHA256"),
                ("8.8.8.8", "IPv6"),
            )
        ).encode()
    )
    assert (feed.fetched, feed.rejected, feed.ignored) == (7, 2, 1)
    assert {c.ioc_type for c in feed.candidates} == {"domain", "hostname", "ipv4", "ipv6"}
    assert all(c.confidence is None for c in feed.candidates)
    ingest(db, settings)
    store_feed(db, settings, "otx", feed)
    store_feed(db, settings, "otx", feed)
    with db.session() as session:
        assert session.scalar(select(func.count()).select_from(IOC)) == 4
        assert session.scalar(select(func.count()).select_from(Observation)) == 5
        obs = session.scalar(select(Observation).where(Observation.source == "otx"))
        assert obs.details["name"] == "Trusted pulse"
        assert obs.details["author_name"] == "researcher"
        assert obs.confidence is None


def test_otx_pagination_accounting_and_official_origin(db, settings):
    seen = []

    def handler(request):
        seen.append(request)
        assert request.url.host == "otx.alienvault.com"
        assert request.headers["X-OTX-API-KEY"] == "secret"
        assert "secret" not in str(request.url)
        n = int(request.url.params["page"])
        return httpx.Response(
            200,
            json=pulse(
                (f"host{n}.example", "hostname"),
                next_page="https://otx.alienvault.com/api/v1/pulses/subscribed?page=2&limit=50"
                if n == 1
                else None,
            ),
        )

    provider = OTXProvider("secret", settings.http)
    service = UpdateService(db, settings, [provider], httpx.MockTransport(handler))
    provider.account_request = service.account_request
    asyncio.run(service._run())
    assert len(seen) == 2
    assert service.last_result["providers"]["otx"]["valid"] == 2
    with db.session() as session:
        assert session.get(ProviderUsage, "otx").total_requests == 2


@pytest.mark.parametrize("status", [429, 503])
def test_otx_failure_isolation(db, settings, status, monkeypatch):
    async def no_wait(self, seconds):
        pass

    monkeypatch.setattr(OTXProvider, "_wait_before_retry", no_wait)
    from test_feeds import tf_body, tf_row

    from app.feeds.threatfox import ThreatFoxProvider

    def handler(request):
        if request.url.host == "otx.alienvault.com":
            return httpx.Response(status, headers={"Retry-After": "900"})
        return httpx.Response(200, content=tf_body(tf_row()))

    providers = [OTXProvider("secret", settings.http), ThreatFoxProvider("secret", settings.http)]
    service = UpdateService(db, settings, providers, httpx.MockTransport(handler))
    for provider in providers:
        provider.account_request = service.account_request
    asyncio.run(service._run())
    assert service.last_result["providers"]["otx"]["status"] == "failed"
    assert service.last_result["providers"]["threatfox"]["status"] == "success"
    with db.session() as session:
        assert session.get(ProviderUsage, "otx").rate_limited_requests == int(status == 429)


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"results":null}'])
def test_otx_malformed_response(settings, payload):
    with pytest.raises(FeedError, match="invalid_response"):
        OTXProvider("secret", settings.http).parse(payload)


@pytest.mark.parametrize("name", ["otx", "virustotal"])
def test_keys_encrypted_masked_tested_reloaded(settings, monkeypatch, name, caplog):
    monkeypatch.setenv("CERBERUS_SECRET_KEY", Fernet.generate_key().decode())
    keys_seen = []

    def handler(request):
        keys_seen.append(request.headers.get("X-OTX-API-KEY") or request.headers.get("x-apikey"))
        return httpx.Response(200, json=pulse() if name == "otx" else vt_data())

    settings.providers.otx.enabled = True
    with TestClient(create_app(settings, httpx.MockTransport(handler))) as client:
        token = login(client)
        for key in ("secret-key-one-A123", "secret-key-two-B456"):
            assert (
                client.post(f"/admin/api-keys/{name}", data={"csrf": token, "key": key}).status_code
                == 200
            )
            html = client.get("/admin/api-keys").text
            assert key not in html and key[-4:] in html
            assert (
                "Key test: valid"
                in client.post(f"/admin/api-keys/{name}/test", data={"csrf": token}).text
            )
            with client.app.state.db.session() as session:
                assert key not in session.get(ProviderCredential, name).ciphertext
            if name == "otx":
                assert (
                    next(p for p in client.app.state.updates.providers if p.name == name).key == key
                )
        assert keys_seen == ["secret-key-one-A123", "secret-key-two-B456"]
        assert "secret-key" not in caplog.text
        client.post(f"/admin/api-keys/{name}/remove", data={"csrf": token})
        assert (
            "No key configured"
            in client.post(f"/admin/api-keys/{name}/test", data={"csrf": token}).text
        )
        assert "virustotal" not in client.get("/admin/feeds").text.lower()
        assert "AlienVault OTX" in client.get("/admin/feeds").text
        assert "On-demand enrichment" in client.get("/admin/api-keys").text


def test_vt_explicit_query_cache_refresh_persistence(settings, caplog):
    settings.virustotal_auth_key = SecretStr("vt-secret-key")
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["x-apikey"] == settings.virustotal_auth_key.get_secret_value()
        assert "vt-secret" not in str(request.url)
        data = vt_data()
        data["data"]["attributes"]["whois"] = "echo vt-secret-key"
        return httpx.Response(200, json=data)

    transport = httpx.MockTransport(handler)
    with TestClient(create_app(settings, transport)) as client:
        token = login(client)
        ingest(client.app.state.db, settings)
        for path in ("/admin/iocs", "/admin/iocs/1", "/lists/domains.txt", "/admin"):
            assert client.get(path).status_code == 200
        assert not calls
        assert all(p.name != "virustotal" for p in client.app.state.updates.providers)
        assert client.post("/admin/iocs/1/virustotal", data={"csrf": "wrong"}).status_code == 403
        html = client.post("/admin/iocs/1/virustotal", data={"csrf": token}).text
        assert len(calls) == 1
        for expected in (
            "Live / freshly queried",
            "14",
            "72",
            "Engine breakdown",
            "phishing",
            "VirusTotal reputation",
            "&lt;script&gt;",
            "detection-bar",
        ):
            assert expected in html
        assert "<script>evil" not in html
        assert "vt-secret-key" not in html + caplog.text
        with client.app.state.db.session() as session:
            row = session.get(IOCEnrichment, (1, "virustotal"))
            assert row.expires_at - row.queried_at == timedelta(hours=24)
            assert session.get(ProviderUsage, "virustotal").total_requests == 1
        for _ in range(3):
            client.get("/admin/iocs/1")
            client.post("/admin/iocs/1/virustotal", data={"csrf": token})
        assert len(calls) == 1
        settings.virustotal_auth_key = SecretStr("new-key")
        client.post("/admin/iocs/1/virustotal", data={"csrf": token, "refresh": "yes"})
        assert len(calls) == 2
        assert client.get("/lists/domains.txt").text == "evil.example\n"
    with TestClient(create_app(settings, transport)) as client:
        login(client)
        assert "Engine breakdown" in client.get("/admin/iocs/1").text
        assert len(calls) == 2
        with client.app.state.db.session() as session:
            assert session.get(SchemaVersion, 1).version == 4


@pytest.mark.parametrize("status", [429, 503, 404, 200])
def test_vt_failed_query_cached_fallback(settings, status):
    settings.virustotal_auth_key = SecretStr("secret")
    code = [200]
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            code[0],
            json=vt_data() if code[0] == 200 and len(calls) == 1 else {"error": "secret"},
            headers={"Retry-After": "600"},
        )

    with TestClient(create_app(settings, httpx.MockTransport(handler))) as client:
        token = login(client)
        ingest(client.app.state.db, settings)
        client.post("/admin/iocs/1/virustotal", data={"csrf": token})
        code[0] = status
        html = client.post("/admin/iocs/1/virustotal", data={"csrf": token, "refresh": "yes"}).text
        assert "Previous cached result retained" in html
        assert "phishing" in html
        assert '"error": "secret"' not in html
        if status == 429:
            assert "VirusTotal rate limit reached" in html
            client.post("/admin/iocs/1/virustotal", data={"csrf": token, "refresh": "yes"})
            assert len(calls) == 2
        with client.app.state.db.session() as session:
            assert session.get(ProviderUsage, "virustotal").total_requests == 2


def test_vt_stale_cache_never_auto_refreshes(settings):
    settings.virustotal_auth_key = SecretStr("secret")
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=vt_data())

    with TestClient(create_app(settings, httpx.MockTransport(handler))) as client:
        token = login(client)
        ingest(client.app.state.db, settings)
        client.post("/admin/iocs/1/virustotal", data={"csrf": token})
        with client.app.state.db.session.begin() as session:
            session.get(IOCEnrichment, (1, "virustotal")).expires_at = utcnow() - timedelta(hours=1)
        assert "Stale cache" in client.get("/admin/iocs/1").text
        assert len(calls) == 1
        client.post("/admin/iocs/1/virustotal", data={"csrf": token})
        assert len(calls) == 2


def test_vt_not_configured(settings):
    with TestClient(create_app(settings)) as client:
        token = login(client)
        ingest(client.app.state.db, settings)
        assert "VirusTotal enrichment is not configured" in client.get("/admin/iocs/1").text
        assert (
            "VirusTotal enrichment is not configured"
            in client.post("/admin/iocs/1/virustotal", data={"csrf": token}).text
        )


@pytest.mark.parametrize(
    "value,kind,path",
    [
        ("EXAMPLE.COM", "domain", "/domains/example.com"),
        ("8.8.8.8", "ipv4", "/ip_addresses/8.8.8.8"),
        ("2001:4860:4860::8888", "ipv6", "/ip_addresses/2001:4860:4860::8888"),
    ],
)
def test_vt_validated_official_endpoints(settings, value, kind, path):
    def handler(request):
        assert request.url.host == "www.virustotal.com"
        assert request.url.path.endswith(path)
        return httpx.Response(200, json=vt_data())

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await VirusTotalProvider("secret", settings.http).lookup(client, value, kind)
            with pytest.raises(ValueError):
                await VirusTotalProvider("secret", settings.http).lookup(
                    client, "https://attacker.invalid", "domain"
                )

    asyncio.run(run())


def test_cache_ttl_runtime_setting(settings):
    with TestClient(create_app(settings)) as client:
        token = login(client)
        client.post(
            "/admin/settings", data={"csrf": token, "interval": "15", "cache_ttl_hours": "48"}
        )
        assert client.app.state.settings.enrichment.cache_ttl_hours == 48
    with TestClient(create_app(settings)) as client:
        assert client.app.state.settings.enrichment.cache_ttl_hours == 48


def test_vt_never_called_by_ingestion_or_scheduler(settings):
    from test_feeds import tf_body, tf_row

    from app.feeds.threatfox import ThreatFoxProvider

    settings.virustotal_auth_key = SecretStr("configured-vt-key")
    settings.threatfox_auth_key = SecretStr("feed-key")
    calls = []

    def handler(request):
        calls.append(request.url.host)
        assert request.url.host == "threatfox-api.abuse.ch"
        return httpx.Response(200, content=tf_body(tf_row()))

    with TestClient(create_app(settings, httpx.MockTransport(handler))) as client:
        service = client.app.state.updates
        # Scheduler/startup/manual updates all share this same job owner.
        asyncio.run(
            service._run([next(p for p in service.providers if isinstance(p, ThreatFoxProvider))])
        )
        assert calls == ["threatfox-api.abuse.ch"]
        login(client)
        assert client.get("/admin/iocs/1").status_code == 200
        assert client.get("/lists/domains.txt").status_code == 200
        with client.app.state.db.session() as session:
            assert session.get(ProviderUsage, "virustotal") is None


def test_schema_two_upgrade_preserves_data_and_is_idempotent(settings):
    from app.database import Base, Database

    db = Database(settings.database_url)
    Base.metadata.create_all(
        db.engine,
        tables=[table for table in Base.metadata.sorted_tables if table.name != "ioc_enrichments"],
    )
    ingest(db, settings)
    with db.session.begin() as session:
        session.add(SchemaVersion(id=1, version=2))
        session.add(ProviderCredential(source="otx", ciphertext="preserved-encrypted-value"))
    db.initialize()
    db.initialize()
    with db.session() as session:
        assert session.get(SchemaVersion, 1).version == 4
        assert session.get(IOC, 1).normalized_value == "evil.example"
        assert session.scalar(select(func.count()).select_from(Observation)) == 1
        assert session.get(ProviderCredential, "otx").ciphertext == "preserved-encrypted-value"
        assert session.scalar(select(func.count()).select_from(IOCEnrichment)) == 0
    db.engine.dispose()


@pytest.mark.parametrize("status", [429, 403, 503])
def test_vt_initial_failure_clean_state(settings, status):
    settings.virustotal_auth_key = SecretStr("secret-key")
    transport = httpx.MockTransport(
        lambda request: httpx.Response(status, json={"error": "secret-key"})
    )
    with TestClient(create_app(settings, transport)) as client:
        token = login(client)
        ingest(client.app.state.db, settings)
        html = client.post("/admin/iocs/1/virustotal", data={"csrf": token}).text
        assert "Try again later" in html
        assert "secret-key" not in html
        assert "Query VirusTotal" in html
        with client.app.state.db.session() as session:
            assert session.get(IOCEnrichment, (1, "virustotal")) is None
            usage = session.get(ProviderUsage, "virustotal")
            assert (usage.total_requests, usage.failed_requests) == (1, 1)
            assert usage.rate_limited_requests == int(status == 429)


@pytest.mark.parametrize(
    "payload",
    [{"results": [{"indicators": None}]}, {"results": [42]}, {"results": [{"indicators": [None]}]}],
)
def test_otx_malformed_pulses(settings, payload):
    feed = OTXProvider("secret", settings.http).parse(json.dumps(payload).encode())
    assert not feed.candidates
    assert feed.rejected == 1


def test_otx_pagination_ceiling(settings):
    provider = OTXProvider("secret", settings.http, max_pages=1)

    async def run():
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json=pulse(
                    next_page="https://otx.alienvault.com/api/v1/pulses/subscribed?page=2&limit=50"
                ),
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(FeedError, match="pagination_limit"):
                async for _ in provider.pages(client):
                    pass

    asyncio.run(run())


def test_environment_keys_and_yaml_secret_rejection(tmp_path, monkeypatch):
    from app.config import load_settings

    config = tmp_path / "config.yaml"
    config.write_text("{}")
    monkeypatch.setenv("CERBERUS_CONFIG", str(config))
    monkeypatch.setenv("OTX_API_KEY", "otx-env-key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-env-key")
    settings = load_settings()
    assert settings.otx_auth_key.get_secret_value() == "otx-env-key"
    assert settings.virustotal_auth_key.get_secret_value() == "vt-env-key"
    assert "env-key" not in settings.model_dump_json()
    config.write_text("virustotal_auth_key: forbidden")
    with pytest.raises(ValueError, match="credentials"):
        load_settings()


def test_otx_enable_disable_runtime(settings):
    with TestClient(create_app(settings)) as client:
        token = login(client)
        assert not any(p.name == "otx" for p in client.app.state.updates.providers)
        client.post("/admin/feeds/otx/toggle", data={"csrf": token})
        assert any(p.name == "otx" for p in client.app.state.updates.providers)
    with TestClient(create_app(settings)) as client:
        token = login(client)
        assert any(p.name == "otx" for p in client.app.state.updates.providers)
        client.post("/admin/feeds/otx/toggle", data={"csrf": token})
        assert not any(p.name == "otx" for p in client.app.state.updates.providers)


def test_request_accounting_concurrent_calls(db, settings):
    from concurrent.futures import ThreadPoolExecutor

    service = UpdateService(db, settings, [])
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: service.account_request("virustotal", True, 200), range(20)))
    with db.session() as session:
        usage = session.get(ProviderUsage, "virustotal")
        assert (usage.total_requests, usage.successful_requests) == (20, 20)
