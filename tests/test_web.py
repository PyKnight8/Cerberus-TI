import httpx
from conftest import ingest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr
from test_feeds import tf_body, tf_row

from app.main import create_app
from app.management import mask, set_password, verify_password
from app.models import (
    ManagedAllowlist,
    ProviderCredential,
    ProviderKeyCheck,
    ProviderUsage,
    SchemaVersion,
)


def login(client):
    set_password(client.app.state.db, "a-long-test-password")
    assert client.post("/admin/login", data={"password": "wrong"}).status_code == 401
    assert client.post("/admin/login", data={"password": "a-long-test-password"}).status_code == 200
    return client.app.state.sessions[client.cookies["cerberus_session"]][0]


def test_login_pages_csrf_and_allowlist(settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/admin").url.path == "/admin/login"
        assert client.post("/api/update").status_code == 401
        assert client.get("/lists/domains.txt").status_code == 200
        token = login(client)
        assert verify_password(client.app.state.db, "a-long-test-password")
        assert not verify_password(client.app.state.db, "wrong")
        for path in (
            "/admin",
            "/admin/feeds",
            "/admin/api-keys",
            "/admin/iocs",
            "/admin/allowlist",
            "/admin/settings",
            "/admin/logs",
        ):
            assert client.get(path).status_code == 200
        assert client.post("/admin/allowlist", data={"domain": "evil.example"}).status_code == 403
        ingest(client.app.state.db, settings)
        assert client.get("/lists/domains.txt").text == "evil.example\n"
        client.post("/admin/allowlist", data={"csrf": token, "domain": "evil.example"})
        assert client.get("/lists/domains.txt").text == ""
        with client.app.state.db.session() as session:
            assert session.get(ManagedAllowlist, "evil.example")
        client.post("/admin/allowlist/evil.example/remove", data={"csrf": token})
        assert client.get("/lists/domains.txt").text == "evil.example\n"
        client.post("/admin/logout", data={"csrf": token})
        assert client.get("/admin").url.path == "/admin/login"


def test_encrypted_key_reload_and_accounting(settings, monkeypatch):
    secret = Fernet.generate_key().decode()
    monkeypatch.setenv("CERBERUS_SECRET_KEY", secret)

    def handler(request):
        return httpx.Response(200, content=tf_body(tf_row()))

    with TestClient(create_app(settings, httpx.MockTransport(handler))) as client:
        token = login(client)
        key = "top-secret-example-A92F"
        response = client.post("/admin/api-keys/threatfox", data={"csrf": token, "key": key})
        assert response.status_code == 200
        assert key not in client.get("/admin/api-keys").text
        assert "A92F" in client.get("/admin/api-keys").text
        response = client.post("/admin/api-keys/threatfox/test", data={"csrf": token})
        assert "Key test: valid" in response.text
        assert (
            next(p for p in client.app.state.updates.providers if p.name == "threatfox").key == key
        )
        with client.app.state.db.session() as session:
            row = session.get(ProviderCredential, "threatfox")
            assert key not in row.ciphertext
            assert session.get(ProviderKeyCheck, "threatfox").status == "valid"
        provider = next(p for p in client.app.state.updates.providers if p.name == "threatfox")
        with httpx.Client() as _:
            pass
        import asyncio

        async def fetch():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as external:
                await provider.fetch(external)

        asyncio.run(fetch())
        with client.app.state.db.session() as session:
            usage = session.get(ProviderUsage, "threatfox")
            assert (usage.total_requests, usage.successful_requests, usage.failed_requests) == (
                2,
                2,
                0,
            )


def test_ioc_pagination(settings):
    with TestClient(create_app(settings)) as client:
        login(client)
        ingest(client.app.state.db, settings)
        assert "evil.example" in client.get("/admin/iocs?q=evil").text
        assert "evil.example" not in client.get("/admin/iocs?q=absent").text


def test_additive_migration_keeps_milestone_one_data(settings):
    from sqlalchemy import text

    from app.database import Base, Database
    from app.models import IOC, Observation, ProviderState

    db = Database(settings.database_url)
    Base.metadata.create_all(
        db.engine, tables=[IOC.__table__, Observation.__table__, ProviderState.__table__]
    )
    from app.feeds.base import utcnow

    now = utcnow()
    with db.session.begin() as session:
        session.add(
            IOC(
                id=7,
                value="legacy.example",
                normalized_value="legacy.example",
                ioc_type="domain",
                first_seen=now,
                last_seen=now,
                created_at=now,
                updated_at=now,
            )
        )
    db.initialize()
    with db.session() as session:
        assert (
            session.scalar(text("SELECT normalized_value FROM iocs WHERE id=7")) == "legacy.example"
        )
        assert session.get(SchemaVersion, 1).version == 3
    db.engine.dispose()


def test_request_failure_and_rate_limit_counts(settings):
    with TestClient(create_app(settings)) as client:
        service = client.app.state.updates
        service.account_request("threatfox", False, 429)
        service.account_request("threatfox", False, 503)
        with client.app.state.db.session() as session:
            usage = session.get(ProviderUsage, "threatfox")
            assert (usage.total_requests, usage.failed_requests, usage.rate_limited_requests) == (
                2,
                2,
                1,
            )


def test_key_persistence_and_missing_master_secret(settings, monkeypatch):
    from pytest import raises

    secret = Fernet.generate_key().decode()
    monkeypatch.setenv("CERBERUS_SECRET_KEY", secret)
    with TestClient(create_app(settings)) as client:
        token = login(client)
        client.post("/admin/api-keys/urlhaus", data={"csrf": token, "key": "persisted-secret"})
    with TestClient(create_app(settings)) as client:
        assert next(p for p in client.app.state.updates.providers if p.name == "urlhaus").key == (
            "persisted-secret"
        )
    monkeypatch.delenv("CERBERUS_SECRET_KEY")
    with raises(RuntimeError, match="CERBERUS_SECRET_KEY"):
        with TestClient(create_app(settings)):
            pass
    assert "tiny" not in mask("tiny")


def test_manual_provider_update_and_settings(settings):
    settings.threatfox_auth_key = SecretStr("test-key")

    def handler(request):
        assert request.url.host == "threatfox-api.abuse.ch"
        return httpx.Response(200, content=tf_body(tf_row()))

    app = create_app(settings, httpx.MockTransport(handler))
    with TestClient(app) as client:
        token = login(client)
        client.post("/admin/settings", data={"csrf": token, "interval": "15"})
        assert not app.state.settings.scheduler.enabled
        assert app.state.settings.scheduler.update_interval_minutes == 15
        response = client.post("/admin/feeds/threatfox/update", data={"csrf": token})
        assert response.status_code == 200
        assert "Update started" in response.text
    assert app.state.updates.last_result["providers"]["threatfox"]["status"] == "success"
    with TestClient(create_app(settings)) as client:
        assert client.app.state.settings.scheduler.update_interval_minutes == 15
