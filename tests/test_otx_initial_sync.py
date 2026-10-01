import logging
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_integrations import pulse
from test_web import login

from app.config import OTXConfig
from app.feeds.base import FeedError, utcnow
from app.feeds.otx import OTXProvider
from app.feeds.registry import make_provider
from app.main import create_app
from app.models import IOC, ProviderState, ProviderUsage, RuntimeSetting
from app.services.ingestion import UpdateService


@pytest.fixture
def retry_waits(monkeypatch):
    waits = []

    async def wait(self, seconds):
        waits.append(seconds)

    monkeypatch.setattr(OTXProvider, "_wait_before_retry", wait)
    monkeypatch.setattr("app.feeds.otx.random.uniform", lambda lower, upper: upper)
    return waits


def service_for(db, settings, handler):
    provider = make_provider("otx", "DO-NOT-LOG-KEY", settings)
    service = UpdateService(db, settings, [provider], httpx.MockTransport(handler))
    provider.account_request = service.account_request
    return service


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_transient_response_then_success(db, settings, retry_waits, status, caplog):
    caplog.set_level(logging.INFO)
    requests = []

    def handler(request):
        requests.append(request)
        return (
            httpx.Response(status, text="DO-NOT-LOG-KEY")
            if len(requests) == 1
            else httpx.Response(200, json=pulse(("retry.example", "domain")))
        )

    service = service_for(db, settings, handler)
    await service._run()
    assert service.last_result["providers"]["otx"]["status"] == "success"
    assert retry_waits == [7.5]
    assert len(requests) == 2
    assert requests[0].url == requests[1].url  # Retry exactly the failed page/filter.
    assert "page=1 page_size=10 attempt=1" in caplog.text
    assert "retry_attempt=2 retry_in_seconds=7.500" in caplog.text
    assert "sync_mode=initial_lookback" in caplog.text
    assert "DO-NOT-LOG-KEY" not in caplog.text
    with db.session() as session:
        usage = session.get(ProviderUsage, "otx")
        assert (usage.total_requests, usage.successful_requests, usage.failed_requests) == (2, 1, 1)
        assert usage.last_http_status == 200
        assert session.get(RuntimeSetting, "otx.modified_since")


async def test_repeated_504_stops_and_enters_cooldown(db, settings, retry_waits):
    settings.providers.otx.retrieval_strategy = "subscribed"
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(504)

    service = service_for(db, settings, handler)
    await service._run()
    assert len(requests) == 3
    assert retry_waits == [7.5, 15]
    result = service.last_result["providers"]["otx"]
    assert result == {"status": "failed", "error": "http_error_504"}
    with db.session() as session:
        state = session.get(ProviderState, "otx")
        assert state.last_success is None and state.next_allowed_at > utcnow()
        assert state.counts["last_failure_diagnostics"]["attempt"] == 3
        assert session.get(RuntimeSetting, "otx.modified_since") is None
        usage = session.get(ProviderUsage, "otx")
        assert (usage.total_requests, usage.failed_requests) == (3, 3)
        assert usage.last_http_status == 504
    await service._run()
    assert len(requests) == 3  # Exhaustion is followed by persisted normal cooldown.
    assert service.last_result["providers"]["otx"]["status"] == "cooldown"
    assert not service.trigger("otx")


@pytest.mark.parametrize("lookback", [90, 30, None])
async def test_initial_window_and_small_pagination(db, settings, retry_waits, lookback):
    settings.providers.otx.initial_lookback_days = lookback
    requests = []
    before = utcnow()

    def handler(request):
        requests.append(request)
        page = int(request.url.params["page"])
        return httpx.Response(
            200,
            json=pulse(
                (f"page{page}.example", "domain"),
                next_page=OTXProvider.endpoint + "?page=2&limit=10" if page == 1 else None,
            ),
        )

    service = service_for(db, settings, handler)
    await service._run()
    after = utcnow()
    assert len(requests) == 2 and not retry_waits
    assert [r.url.params["page"] for r in requests] == ["1", "2"]
    assert all(r.url.params["limit"] == "10" for r in requests)
    if lookback is None:
        assert all("modified_since" not in r.url.params for r in requests)
    else:
        since = requests[0].url.params["modified_since"]
        assert (
            (before - timedelta(days=lookback)).isoformat()
            <= since
            <= (after - timedelta(days=lookback)).isoformat()
        )
        assert requests[1].url.params["modified_since"] == since
    with db.session() as session:
        cursor = session.get(RuntimeSetting, "otx.modified_since").value["value"]
        assert (
            (before - timedelta(minutes=5)).isoformat()
            <= cursor
            <= (after - timedelta(minutes=5)).isoformat()
        )
        assert session.get(ProviderUsage, "otx").total_requests == 2


async def test_configured_page_size_and_retry_limit(db, settings, retry_waits):
    settings.providers.otx.retrieval_strategy = "subscribed"
    settings.providers.otx.page_size = 20
    settings.providers.otx.transient_retries = 1
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(504)

    await service_for(db, settings, handler)._run()
    assert len(requests) == 2
    assert all(r.url.params["limit"] == "20" for r in requests)
    assert retry_waits == [7.5]


@pytest.mark.parametrize("has_checkpoint", [False, True])
async def test_later_page_exhaustion_preserves_partial_data_and_checkpoint(
    db, settings, retry_waits, has_checkpoint
):
    settings.providers.otx.retrieval_strategy = "subscribed"
    old = utcnow() - timedelta(days=1)
    if has_checkpoint:
        with db.session.begin() as session:
            session.add(RuntimeSetting(name="otx.modified_since", value={"value": old.isoformat()}))
            session.add(ProviderState(source="otx", last_success=old, counts={}))
    requests = []
    failed = [True]

    def handler(request):
        requests.append(request)
        if request.url.params["page"] == "2" and failed[0]:
            return httpx.Response(504)
        return httpx.Response(
            200,
            json=pulse(
                ("partial.example", "domain"),
                next_page=OTXProvider.endpoint + "?page=2&limit=10"
                if request.url.params["page"] == "1"
                else None,
            ),
        )

    service = service_for(db, settings, handler)
    await service._run()
    assert [r.url.params["page"] for r in requests] == ["1", "2", "2", "2"]
    with db.session.begin() as session:
        checkpoint = session.get(RuntimeSetting, "otx.modified_since")
        assert (
            checkpoint.value["value"] == old.isoformat() if has_checkpoint else checkpoint is None
        )
        assert session.get(ProviderState, "otx").last_success == (old if has_checkpoint else None)
        assert session.scalar(select(func.count()).select_from(IOC)) == 1
        usage = session.get(ProviderUsage, "otx")
        assert (usage.total_requests, usage.successful_requests, usage.failed_requests) == (4, 1, 3)
        session.get(ProviderState, "otx").next_allowed_at = utcnow() - timedelta(seconds=1)
    failed[0] = False
    await service._run()
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.modified_since").value["value"] > old.isoformat()
        assert session.scalar(select(func.count()).select_from(IOC)) == 1
        assert session.get(ProviderUsage, "otx").total_requests == 6
    if has_checkpoint:
        assert all(r.url.params["modified_since"] == old.isoformat() for r in requests)


async def test_existing_checkpoint_overrides_initial_lookback(db, settings, retry_waits, caplog):
    caplog.set_level(logging.INFO)
    checkpoint = (utcnow() - timedelta(hours=3)).isoformat()
    with db.session.begin() as session:
        session.add(RuntimeSetting(name="otx.modified_since", value={"value": checkpoint}))
    settings.providers.otx.initial_lookback_days = 1

    def handler(request):
        assert request.url.params["modified_since"] == checkpoint
        return httpx.Response(200, json=pulse())

    await service_for(db, settings, handler)._run()
    assert "sync_mode=incremental" in caplog.text and not retry_waits


@pytest.mark.parametrize("status", [401, 403, 429, 500])
async def test_nontransient_http_errors_not_retried(db, settings, retry_waits, status):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(status, headers={"Retry-After": "900"})

    service = service_for(db, settings, handler)
    await service._run()
    assert len(requests) == 1 and not retry_waits
    with db.session() as session:
        assert session.get(ProviderUsage, "otx").total_requests == 1
        if status == 429:
            assert session.get(ProviderState, "otx").next_allowed_at > utcnow() + timedelta(
                minutes=14
            )


async def test_key_validation_not_expanded_or_retried(settings, retry_waits):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(504)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(FeedError, match="http_error_504"):
            await make_provider("otx", "key", settings).fetch(client)
    assert len(requests) == 1 and not retry_waits
    assert requests[0].url.params["limit"] == "1"
    assert "modified_since" not in requests[0].url.params


@pytest.mark.parametrize(
    "checkpoint,lookback,label",
    [
        (False, 90, "Lookback: 90 days"),
        (False, None, "Full history"),
        (True, 90, "Incremental sync"),
    ],
)
def test_feeds_ui_sync_plan(settings, checkpoint, lookback, label):
    settings.providers.otx.initial_lookback_days = lookback
    with TestClient(create_app(settings)) as client:
        login(client)
        if checkpoint:
            with client.app.state.db.session.begin() as session:
                session.add(
                    RuntimeSetting(name="otx.modified_since", value={"value": utcnow().isoformat()})
                )
        html = client.get("/admin/feeds").text
        assert label in html
        if not checkpoint:
            assert "Initial sync" in html
        assert "Page size 10 pulses" in html
        assert "2 transient retries per page" in html


@pytest.mark.parametrize(
    "values",
    [
        {"page_size": 0},
        {"initial_lookback_days": 0},
        {"transient_retries": 4},
        {"retry_backoff_seconds": 0},
    ],
)
def test_otx_configuration_bounds(values):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        OTXConfig(**values)
