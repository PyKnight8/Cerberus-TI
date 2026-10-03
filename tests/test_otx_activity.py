"""Activity shape follows a read-only live API schema probe on 2026-10-01.

The real endpoint accepts modified_since; future cutoffs returned zero results.
No credentials or real intelligence records are included in these fixtures.
"""

import json
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_integrations import pulse
from test_otx_initial_sync import retry_waits as retry_fixture
from test_otx_initial_sync import service_for
from test_web import login

from app.feeds.base import utcnow
from app.feeds.otx import OTXProvider
from app.feeds.registry import make_provider
from app.main import create_app
from app.models import IOC, ProviderState, ProviderUsage, RuntimeSetting

retry_waits = retry_fixture


def release(db):
    with db.session.begin() as session:
        session.get(ProviderState, "otx").next_allowed_at = utcnow() - timedelta(seconds=1)


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_fallback_accounting_persistence_and_recovery(
    db, settings, retry_waits, status, caplog
):
    requests = []
    broken = [True]

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("subscribed") and broken[0]:
            return httpx.Response(status)
        return httpx.Response(200, json=pulse(("fallback.example", "domain")))

    service = service_for(db, settings, handler)
    before = utcnow()
    await service._run()
    assert service.last_result["providers"]["otx"]["status"] == "success"
    assert [r.url.path.rsplit("/", 1)[1] for r in requests] == ["subscribed"] * 3 + ["activity"]
    assert len({r.url.params["modified_since"] for r in requests}) == 1
    assert "retrieval=activity_fallback" in caplog.text
    with db.session() as session:
        state = session.get(RuntimeSetting, "otx.retrieval_state").value["value"]
        assert state["retrieval"] == "activity fallback"
        assert state["subscribed_retry_after"]
        cursor = session.get(RuntimeSetting, "otx.modified_since").value["value"]
        assert cursor >= (before - timedelta(minutes=5)).isoformat()
        usage = session.get(ProviderUsage, "otx")
        assert (usage.total_requests, usage.failed_requests, usage.successful_requests) == (4, 3, 1)
    release(db)
    # Reconstruct the service to prove the preference survives restarts.
    service = service_for(db, settings, handler)
    await service._run()
    assert len(requests) == 5 and requests[-1].url.path.endswith("activity")
    assert requests[-1].url.params["modified_since"] == cursor
    release(db)
    with db.session.begin() as session:
        row = session.get(RuntimeSetting, "otx.retrieval_state")
        row.value = {
            "value": {
                **row.value["value"],
                "subscribed_retry_after": (utcnow() - timedelta(seconds=1)).isoformat(),
            }
        }
    broken[0] = False
    await service._run()
    assert len(requests) == 6 and requests[-1].url.path.endswith("subscribed")
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.retrieval_state").value["value"] == {
            "retrieval": "subscribed"
        }
        assert session.get(ProviderUsage, "otx").total_requests == 6


async def test_both_endpoints_fail_bounded_no_checkpoint(db, settings, retry_waits):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(504)

    service = service_for(db, settings, handler)
    await service._run()
    assert len(requests) == 6
    assert len(retry_waits) == 4
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.modified_since") is None
        assert (
            session.get(RuntimeSetting, "otx.retrieval_state").value["value"]["retrieval"]
            == "activity fallback"
        )
        assert session.get(ProviderUsage, "otx").failed_requests == 6
    await service._run()
    assert len(requests) == 6


@pytest.mark.parametrize("strategy", ["auto", "subscribed", "activity"])
async def test_healthy_strategy(db, settings, retry_waits, strategy):
    settings.providers.otx.retrieval_strategy = strategy
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=pulse(("healthy.example", "domain")))

    await service_for(db, settings, handler)._run()
    expected = "activity" if strategy == "activity" else "subscribed"
    assert len(requests) == 1 and requests[0].url.path.endswith(expected)
    assert retry_waits == []
    with db.session() as session:
        assert (
            session.get(RuntimeSetting, "otx.retrieval_state").value["value"]["retrieval"]
            == expected
        )


@pytest.mark.parametrize("initial_days", [90, None])
@pytest.mark.parametrize("fail_page", [False, True])
async def test_activity_pagination_checkpoint_and_window(
    db, settings, retry_waits, initial_days, fail_page
):
    settings.providers.otx.retrieval_strategy = "activity"
    settings.providers.otx.initial_lookback_days = initial_days
    requests = []

    def handler(request):
        requests.append(request)
        page = request.url.params["page"]
        if page == "2" and fail_page:
            return httpx.Response(504)
        return httpx.Response(
            200,
            json=pulse(
                (f"activity{page}.example", "domain"),
                next_page=OTXProvider.activity_endpoint + "?page=2&limit=10"
                if page == "1"
                else None,
            ),
        )

    service = service_for(db, settings, handler)
    await service._run()
    assert all(r.url.path.endswith("activity") and r.url.params["limit"] == "10" for r in requests)
    assert all(("modified_since" in r.url.params) == (initial_days is not None) for r in requests)
    with db.session() as session:
        assert bool(session.get(RuntimeSetting, "otx.modified_since")) == (not fail_page)
        assert session.scalar(select(func.count()).select_from(IOC)) == (1 if fail_page else 2)
        assert session.get(ProviderUsage, "otx").total_requests == (4 if fail_page else 2)


async def test_activity_incremental_failure_keeps_existing_checkpoint(db, settings, retry_waits):
    settings.providers.otx.retrieval_strategy = "activity"
    cursor = (utcnow() - timedelta(days=1)).isoformat()
    with db.session.begin() as session:
        session.add(RuntimeSetting(name="otx.modified_since", value={"value": cursor}))
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(504)

    await service_for(db, settings, handler)._run()
    assert all(r.url.params["modified_since"] == cursor for r in requests)
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.modified_since").value["value"] == cursor


@pytest.mark.parametrize("optional", [False, True])
def test_activity_optional_metadata_is_never_invented(settings, optional):
    data = pulse(("metadata.example", "domain"))
    record = data["results"][0]
    # Actual activity returns UTC strings without a timezone suffix.
    record["modified"] = utcnow().replace(tzinfo=None).isoformat()
    record.pop("created")
    if optional:
        record.update(
            TLP="green", author={"username": "researcher"}, attack_ids=["T1001"], revision=3
        )
    else:
        for key in ("tags", "author_name", "description"):
            record.pop(key)
    provider = make_provider("otx", "dummy", settings)
    parsed = provider.parse(json.dumps(data).encode())
    assert len(parsed.candidates) == 1 and parsed.rejected == 0
    candidate = parsed.candidates[0]
    assert candidate.external_id == "pulse-1:1"
    assert "created" not in candidate.metadata
    assert ("TLP" in candidate.metadata) == optional
    assert ("author" in candidate.metadata) == optional
    if optional:
        assert candidate.metadata["TLP"] == "green"
        assert candidate.metadata["author"]["username"] == "researcher"
        assert candidate.tags == ["malware"]
    else:
        assert "tags" not in candidate.metadata and candidate.tags == []


def test_activity_ui_status(settings):
    with TestClient(create_app(settings)) as client:
        login(client)
        with client.app.state.db.session.begin() as session:
            session.add(
                RuntimeSetting(
                    name="otx.retrieval_state",
                    value={
                        "retrieval": "activity fallback",
                        "subscribed_retry_after": (utcnow() + timedelta(hours=6)).isoformat(),
                    },
                )
            )
        html = client.get("/admin/feeds").text
        assert "Retrieval: activity fallback" in html
        assert "Subscribed endpoint retry after" in html
        assert "Strategy: auto" in html


@pytest.mark.parametrize("status", [401, 429])
async def test_auth_and_rate_limit_never_fallback(db, settings, retry_waits, status):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(status)

    await service_for(db, settings, handler)._run()
    assert len(requests) == 1 and requests[0].url.path.endswith("subscribed")
    assert retry_waits == []


async def test_fallback_after_partial_subscribed_failure_keeps_data_and_cursor(
    db, settings, retry_waits
):
    cursor = (utcnow() - timedelta(days=1)).isoformat()
    with db.session.begin() as session:
        session.add(RuntimeSetting(name="otx.modified_since", value={"value": cursor}))
    requests = []

    def handler(request):
        requests.append(request)
        endpoint = request.url.path.rsplit("/", 1)[1]
        page = request.url.params["page"]
        if page == "2":
            return httpx.Response(504)
        return httpx.Response(
            200,
            json=pulse(
                (f"partial-{endpoint}.example", "domain"),
                next_page=f"https://otx.alienvault.com/api/v1/pulses/{endpoint}?page=2&limit=10",
            ),
        )

    service = service_for(db, settings, handler)
    await service._run()
    assert service.last_result["providers"]["otx"]["status"] == "failed"
    assert len(requests) == 8
    assert all(r.url.params["modified_since"] == cursor for r in requests)
    with db.session() as session:
        assert session.scalar(select(func.count()).select_from(IOC)) == 2
        assert session.get(RuntimeSetting, "otx.modified_since").value["value"] == cursor
        usage = session.get(ProviderUsage, "otx")
        assert (usage.total_requests, usage.failed_requests, usage.successful_requests) == (8, 6, 2)


@pytest.mark.parametrize(
    "next_link", [OTXProvider.endpoint + "?page=2", "https://evil.example/?page=2"]
)
async def test_activity_never_follows_cross_endpoint_links(db, settings, next_link):
    settings.providers.otx.retrieval_strategy = "activity"
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=pulse(("safe.example", "domain"), next_page=next_link))

    service = service_for(db, settings, handler)
    await service._run()
    assert len(requests) == 1
    assert service.last_result["providers"]["otx"]["error"] == "invalid_pagination"
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.modified_since") is None


async def test_fallback_shares_successful_page_budget(db, settings, retry_waits):
    settings.providers.otx.max_pages = 2
    requests = []

    def handler(request):
        requests.append(request)
        endpoint = request.url.path.rsplit("/", 1)[1]
        if endpoint == "subscribed" and request.url.params["page"] == "2":
            return httpx.Response(504)
        return httpx.Response(
            200,
            json=pulse(
                ("bounded.example", "domain"),
                next_page=f"https://otx.alienvault.com/api/v1/pulses/{endpoint}?page=2&limit=10",
            ),
        )

    service = service_for(db, settings, handler)
    await service._run()
    assert len(requests) == 5
    assert service.last_result["providers"]["otx"]["error"] == "pagination_limit"
    with db.session() as session:
        assert session.get(RuntimeSetting, "otx.modified_since") is None
