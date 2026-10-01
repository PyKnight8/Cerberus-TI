import asyncio
import logging
from datetime import timedelta

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select
from test_integrations import pulse
from test_web import login

from app.config import ProviderTimeouts
from app.feeds.base import FeedError, utcnow
from app.feeds.otx import OTXProvider
from app.feeds.registry import make_provider
from app.main import create_app
from app.models import OperationalEvent, ProviderState, ProviderUsage, RuntimeSetting
from app.services.ingestion import UpdateService


@pytest.mark.asyncio
async def test_otx_response_after_thirty_seconds(settings):
    # MockTransport does not enforce socket timeouts; assert the HTTPX extensions
    # as well as waiting beyond the previous read timeout and exercising the deadline.
    async def handler(request):
        assert request.extensions["timeout"]["connect"] == 10
        assert request.extensions["timeout"]["read"] == 120
        await asyncio.sleep(31)
        return httpx.Response(200, json=pulse())

    provider = make_provider("otx", "secret", settings)
    assert provider.total_timeout == 180
    async with httpx.AsyncClient(timeout=30, transport=httpx.MockTransport(handler)) as client:
        pages = [page async for page in provider.pages(client)]
    assert len(pages) == 1


def test_provider_timeouts_configurable_and_isolated(settings):
    settings.providers.otx.http = ProviderTimeouts(
        connect_timeout_seconds=7, read_timeout_seconds=150, total_timeout_seconds=240
    )
    provider = make_provider("otx", "secret", settings)
    assert provider.http_timeout().connect == 7
    assert provider.http_timeout().read == 150
    assert provider.total_timeout == 240
    for name in ("urlhaus", "threatfox", "virustotal"):
        other = make_provider(name, "secret", settings)
        assert other.http_timeout().read == 30
        assert other.total_timeout == 120
    settings.providers.threatfox.http.read_timeout_seconds = 45
    assert make_provider("threatfox", "secret", settings).http_timeout().read == 45
    assert make_provider("urlhaus", "secret", settings).http_timeout().read == 30


@pytest.mark.parametrize(
    "exception,category",
    [
        (httpx.ConnectTimeout, "connect"),
        (httpx.ReadTimeout, "read"),
        (httpx.WriteTimeout, "write"),
        (httpx.PoolTimeout, "pool"),
    ],
)
@pytest.mark.asyncio
async def test_otx_timeout_diagnostics_and_accounting(db, settings, caplog, exception, category):
    caplog.set_level(logging.INFO)

    def handler(request):
        raise exception("SECRET-HEADER-AND-KEY")

    provider = OTXProvider("SECRET-HEADER-AND-KEY", settings.http)
    service = UpdateService(db, settings, [provider], httpx.MockTransport(handler))
    provider.account_request = service.account_request
    await service._run()
    assert service.last_result["providers"]["otx"]["error"] == "timeout"
    assert f"timeout_category={category}" in caplog.text
    assert "operation=subscribed_pulses" in caplog.text
    assert "page=1" in caplog.text
    assert "elapsed_seconds=" in caplog.text
    assert "SECRET-HEADER-AND-KEY" not in caplog.text
    with db.session() as session:
        state = session.get(ProviderState, "otx")
        assert state.last_success is None
        assert state.next_allowed_at > utcnow()
        assert state.counts["last_failure_diagnostics"]["timeout_category"] == category
        usage = session.get(ProviderUsage, "otx")
        assert (usage.total_requests, usage.failed_requests) == (1, 1)
        event = session.scalar(select(OperationalEvent))
        assert f"timeout_category={category}" in event.message
        assert "SECRET-HEADER-AND-KEY" not in event.message


@pytest.mark.asyncio
async def test_otx_total_request_deadline(settings, caplog):
    async def handler(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json=pulse())

    provider = OTXProvider("secret", settings.http)
    provider.timeouts.total_timeout_seconds = 0.01
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(FeedError, match="timeout"):
            async for _ in provider.pages(client):
                pass
    assert "timeout_category=total" in caplog.text


@pytest.mark.asyncio
async def test_otx_official_pagination_and_incremental_checkpoint(db, settings):
    settings.providers.otx.initial_lookback_days = None
    requests = []

    def handler(request):
        requests.append(request)
        page = int(request.url.params["page"])
        # Provider's next page need not be current+1. Honor validated API pagination.
        next_link = OTXProvider.endpoint + "?page=3&limit=20" if page == 1 else None
        return httpx.Response(
            200, json=pulse((f"host{page}.example", "domain"), next_page=next_link)
        )

    provider = OTXProvider("secret", settings.http)
    service = UpdateService(db, settings, [provider], httpx.MockTransport(handler))
    provider.account_request = service.account_request
    before = utcnow() - timedelta(minutes=5)
    await service._run()
    assert [r.url.params["page"] for r in requests] == ["1", "3"]
    assert requests[1].url.params["limit"] == "20"
    assert all("modified_since" not in r.url.params for r in requests)
    with db.session.begin() as session:
        checkpoint = session.get(RuntimeSetting, "otx.modified_since").value["value"]
        assert checkpoint >= before.isoformat()
        session.get(ProviderState, "otx").next_allowed_at = utcnow() - timedelta(seconds=1)
    # A fresh provider/service uses the persisted checkpoint, not in-memory state.
    reloaded = OTXProvider("secret", settings.http)
    service = UpdateService(db, settings, [reloaded], httpx.MockTransport(handler))
    reloaded.account_request = service.account_request
    await service._run()
    assert all(r.url.params["modified_since"] == checkpoint for r in requests[2:])
    with db.session() as session:
        assert session.get(ProviderUsage, "otx").total_requests == 4


@pytest.mark.parametrize("initial", [True, False])
@pytest.mark.asyncio
async def test_failed_later_page_does_not_advance_checkpoint_or_success(db, settings, initial):
    previous = utcnow() - timedelta(days=1)
    if not initial:
        with db.session.begin() as session:
            session.add(
                RuntimeSetting(name="otx.modified_since", value={"value": previous.isoformat()})
            )
            session.add(ProviderState(source="otx", last_success=previous, counts={}))

    def handler(request):
        if request.url.params["page"] == "2":
            raise httpx.ReadTimeout("secret")
        return httpx.Response(
            200,
            json=pulse(
                ("partial.example", "domain"), next_page=OTXProvider.endpoint + "?page=2&limit=50"
            ),
        )

    provider = OTXProvider("secret", settings.http)
    service = UpdateService(db, settings, [provider], httpx.MockTransport(handler))
    await service._run()
    with db.session() as session:
        cursor = session.get(RuntimeSetting, "otx.modified_since")
        assert cursor is None if initial else cursor.value["value"] == previous.isoformat()
        assert session.get(ProviderState, "otx").last_success == (None if initial else previous)
        assert session.get(ProviderState, "otx").counts["last_failure_diagnostics"]["page"] == 2


@pytest.mark.parametrize(
    "next_link",
    [
        "https://attacker.invalid/?page=2",
        "http://otx.alienvault.com/api/v1/pulses/subscribed?page=2",
        "https://otx.alienvault.com/api/v1/users/me?page=2",
        "?page=1",
        "?page=2&page=3",
        "?page=2&key=secret",
        "?page=2&modified_since=wrong",
        "?page=2&limit=1000",
    ],
)
@pytest.mark.asyncio
async def test_untrusted_pagination_rejected(settings, next_link):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=pulse(next_page=next_link))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(FeedError, match="invalid_pagination"):
            async for _ in OTXProvider("secret", settings.http).pages(client):
                pass
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_automatic_cooldown_logged_and_counted_once(db, settings, caplog):
    caplog.set_level(logging.INFO)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "900"})

    provider = OTXProvider("secret", settings.http)
    service = UpdateService(db, settings, [provider], httpx.MockTransport(handler))
    provider.account_request = service.account_request
    await service._run()
    await service._run()
    assert len(calls) == 1
    result = service.last_result["providers"]["otx"]
    assert result["status"] == "cooldown" and result["retry_at"]
    assert "update skipped reason=cooldown" in caplog.text
    assert not service.trigger("otx")
    assert "cooldown" in service.trigger_notice and result["retry_at"] in service.trigger_notice
    with db.session() as session:
        usage = session.get(ProviderUsage, "otx")
        assert (usage.total_requests, usage.rate_limited_requests) == (1, 1)


def test_manual_cooldown_ui_and_key_test(settings):
    settings.providers.otx.enabled = True
    settings.otx_auth_key = SecretStr("secret")
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.params["limit"] == "1"  # Key validation remains lightweight.
        return httpx.Response(200, json=pulse())

    with TestClient(create_app(settings, httpx.MockTransport(handler))) as client:
        token = login(client)
        retry_at = utcnow() + timedelta(minutes=5)
        with client.app.state.db.session.begin() as session:
            session.add(
                ProviderState(
                    source="otx",
                    last_error="timeout",
                    next_allowed_at=retry_at,
                    counts={
                        "last_failure_diagnostics": {
                            "timeout_category": "read",
                            "operation": "subscribed_pulses",
                            "page": 1,
                            "elapsed_seconds": 30,
                        }
                    },
                )
            )
        html = client.post("/admin/feeds/otx/update", data={"csrf": token}).text
        assert "is in cooldown. Retry after" in html
        assert retry_at.isoformat() in html
        assert "Update started" not in html
        assert "Cooldown" in html and "Timeout: read" in html
        assert "Read timeout 120" in html
        assert not calls and client.app.state.updates.task is None
        html = client.post("/admin/api-keys/otx/test", data={"csrf": token}).text
        assert "Key test: valid" in html and len(calls) == 1
        assert calls[0].extensions["timeout"]["read"] == 120


def test_manual_after_cooldown_really_requests(settings):
    settings.providers.otx.enabled = True
    settings.otx_auth_key = SecretStr("secret")
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=pulse())

    with TestClient(create_app(settings, httpx.MockTransport(handler))) as client:
        token = login(client)
        with client.app.state.db.session.begin() as session:
            session.add(
                ProviderState(
                    source="otx",
                    last_error="timeout",
                    next_allowed_at=utcnow() - timedelta(seconds=1),
                )
            )
        assert "Update started" in client.post("/admin/feeds/otx/update", data={"csrf": token}).text
    assert len(calls) == 1


def test_otx_key_change_resets_checkpoint(settings, monkeypatch):
    monkeypatch.setenv("CERBERUS_SECRET_KEY", Fernet.generate_key().decode())
    with TestClient(create_app(settings)) as client:
        token = login(client)
        with client.app.state.db.session.begin() as session:
            session.add(
                RuntimeSetting(name="otx.modified_since", value={"value": utcnow().isoformat()})
            )
        client.post("/admin/api-keys/otx", data={"csrf": token, "key": "new-account-key"})
        with client.app.state.db.session() as session:
            assert session.get(RuntimeSetting, "otx.modified_since") is None


def test_partial_otx_timeout_config_retains_otx_defaults():
    from app.config import Settings

    settings = Settings(providers={"otx": {"http": {"read_timeout_seconds": 150}}})
    provider = make_provider("otx", "secret", settings)
    assert provider.http_timeout().connect == 10
    assert provider.http_timeout().read == 150
    assert provider.total_timeout == 180


@pytest.mark.asyncio
async def test_full_resync_option_and_checkpoint_after_empty_update(db, settings):
    previous = utcnow() - timedelta(days=1)
    with db.session.begin() as session:
        session.add(
            RuntimeSetting(name="otx.modified_since", value={"value": previous.isoformat()})
        )
    settings.providers.otx.incremental = False
    settings.providers.otx.initial_lookback_days = None
    requests = []

    def handler(request):
        requests.append(request)
        assert "modified_since" not in request.url.params
        return httpx.Response(200, json={"results": [], "next": None})

    service = UpdateService(
        db, settings, [OTXProvider("secret", settings.http)], httpx.MockTransport(handler)
    )
    await service._run()
    assert len(requests) == 1
    with db.session() as session:
        assert (
            session.get(RuntimeSetting, "otx.modified_since").value["value"] > previous.isoformat()
        )
        assert session.get(ProviderState, "otx").last_success
