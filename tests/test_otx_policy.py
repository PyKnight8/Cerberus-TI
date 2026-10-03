from datetime import timedelta

import pytest
from conftest import candidate, ingest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from test_web import login

from app.config import Settings
from app.feeds.base import utcnow
from app.main import create_app
from app.management import load_runtime_settings, save_runtime_setting
from app.models import IOC, Observation, RuntimeSetting, SchemaVersion
from app.policy import BlockingPolicy, official_otx_author
from app.services.blocklist import domains_text, ioc_query


def evidence(settings, **changes):
    now = utcnow()
    values = dict(
        source="otx",
        active=True,
        confidence=None,
        last_seen=now,
        expires_at=now + timedelta(days=7),
        details={"author_name": "AlienVault"},
    )
    values.update(changes)
    settings.providers.otx.enabled = True
    return Observation(**values)


def test_safe_defaults_and_legacy_yaml():
    settings = Settings(policy={"sources": {"otx": {"allow_unknown_confidence": True}}})
    assert not settings.policy.otx.enabled
    assert settings.policy.otx.official_author_only
    assert settings.policy.otx.max_age_days == 30
    assert BlockingPolicy(settings).evidence_reason(evidence(settings), utcnow()) == (
        "otx_enforcement_disabled"
    )


@pytest.mark.parametrize(
    "metadata,accepted",
    [
        ({"author_name": "AlienVault"}, True),
        ({"author_name": "LevelBlue"}, True),
        ({"author": {"username": "alienvault"}}, True),
        ({"author": "LevelBlue"}, True),
        ({"author_name": "AlienVault", "author": {"username": "community"}}, False),
        ({"author_name": "AlienVault Research"}, False),
        ({"author_name": "fakeAlienVault"}, False),
        ({"author_name": "community"}, False),
        ({"author_name": None}, False),
        ({"author_name": ["AlienVault"]}, False),
        ({"author": {"display_name": "AlienVault"}}, False),
        ({"name": "AlienVault", "tags": ["LevelBlue"]}, False),
        ({}, False),
    ],
)
def test_exact_official_author_matching(metadata, accepted):
    assert official_otx_author(metadata) is accepted


@pytest.mark.parametrize("official_only", [True, False])
@pytest.mark.parametrize("author", ["AlienVault", "LevelBlue", "community", None])
def test_otx_provenance_policy(settings, official_only, author):
    settings.policy.otx.enabled = True
    settings.policy.otx.official_author_only = official_only
    obs = evidence(settings, details={"author_name": author})
    expected = (
        "otx_untrusted_author"
        if official_only and author not in ("AlienVault", "LevelBlue")
        else "eligible"
    )
    assert BlockingPolicy(settings).evidence_reason(obs, utcnow()) == expected
    assert obs.confidence is None


def test_otx_age_boundary_and_independent_general_freshness(settings):
    now = utcnow()
    settings.policy.otx.enabled = True
    settings.policy.expiration_days = 90
    policy = BlockingPolicy(settings)
    for age, expected in [(29, "eligible"), (30, "otx_stale"), (31, "otx_stale")]:
        obs = evidence(
            settings,
            last_seen=now - timedelta(days=age),
            expires_at=now + timedelta(days=7),
        )
        assert policy.evidence_reason(obs, now) == expected


@pytest.mark.parametrize("changes", [{"active": False}, {"expires_at": utcnow()}])
def test_inactive_and_expired_excluded(settings, changes):
    settings.policy.otx.enabled = True
    assert BlockingPolicy(settings).evidence_reason(evidence(settings, **changes), utcnow()) == (
        "inactive_or_expired"
    )


def test_general_expiration_still_applies(settings):
    settings.policy.otx.enabled = True
    obs = evidence(settings, last_seen=utcnow() - timedelta(days=8))
    assert BlockingPolicy(settings).evidence_reason(obs, utcnow()) == "inactive_or_expired"


@pytest.mark.parametrize(
    "value", ["localhost", "router.home.arpa", "host.local", "bad host.com", "https://evil.example"]
)
def test_unsafe_hostnames_excluded(settings, value):
    settings.policy.otx.enabled = True
    ioc = IOC(normalized_value=value, ioc_type="domain", observations=[evidence(settings)])
    assert BlockingPolicy(settings).evaluate(ioc, utcnow()).reasons == ["safety_exclusion"]


def test_allowlist_overrides_and_ips_stay_intelligence(settings):
    settings.policy.otx.enabled = True
    settings.allowlist.domains = ["evil.example"]
    policy = BlockingPolicy(settings)
    ioc = IOC(
        normalized_value="sub.evil.example", ioc_type="hostname", observations=[evidence(settings)]
    )
    assert policy.evaluate(ioc, utcnow()).reasons == ["allowlisted"]
    ioc = IOC(normalized_value="8.8.8.8", ioc_type="ipv4", observations=[evidence(settings)])
    assert policy.evaluate(ioc, utcnow()).reasons == ["ip_intelligence_only"]


@pytest.mark.parametrize("source", ["threatfox", "urlhaus"])
def test_other_sources_independently_block(db, settings, source):
    settings.providers.otx.enabled = True
    ingest(
        db, settings, "otx", [candidate(confidence=None, metadata={"author_name": "AlienVault"})]
    )
    assert domains_text(db, BlockingPolicy(settings)) == ""
    ingest(db, settings, source)
    assert domains_text(db, BlockingPolicy(settings)) == "evil.example\n"


def test_stale_otx_remains_stored(db, settings):
    settings.providers.otx.enabled = True
    settings.policy.otx.enabled = True
    settings.policy.expiration_days = 90
    seen = utcnow() - timedelta(days=31)
    ingest(
        db,
        settings,
        "otx",
        [
            candidate(
                first_seen=seen,
                last_seen=seen,
                confidence=None,
                metadata={"author_name": "AlienVault"},
            )
        ],
    )
    assert domains_text(db, BlockingPolicy(settings)) == ""
    with db.session() as session:
        ioc = session.scalar(ioc_query())
        assert ioc.observations[0].confidence is None
        assert BlockingPolicy(settings).evaluate(ioc, utcnow()).reasons == ["otx_stale"]


def test_live_settings_blocklist_details_and_persistence(settings):
    settings.providers.otx.enabled = True
    restart_settings = settings.model_copy(deep=True)
    with TestClient(create_app(settings)) as client:
        token = login(client)
        ingest(
            client.app.state.db,
            settings,
            "otx",
            [candidate(confidence=None, metadata={"author_name": "AlienVault"})],
        )
        ingest(
            client.app.state.db,
            settings,
            "otx",
            [
                candidate(
                    value="community.example",
                    confidence=None,
                    metadata={"author_name": "community"},
                )
            ],
        )
        assert client.get("/lists/domains.txt").text == ""
        assert "Disabled; retained as intelligence" in client.get("/admin/iocs/1").text
        page = client.get("/admin/settings").text
        assert "Allow OTX domain/hostname indicators" in page
        assert "Maximum age for OTX auto-blocking" in page
        url = "/admin/settings/otx"
        data = {"csrf": token, "enabled": "on", "official_author_only": "on", "max_age_days": "30"}
        assert client.post(url, data={**data, "csrf": "bad"}).status_code == 403
        assert client.post(url, data={**data, "max_age_days": "0"}).status_code == 422
        assert client.post(url, data={**data, "max_age_days": "garbage"}).status_code == 422
        assert client.get("/lists/domains.txt").text == ""
        assert client.post(url, data=data).status_code == 200
        assert client.get("/lists/domains.txt").text == "evil.example\n"
        assert "Eligible source evidence" in client.get("/admin/iocs/1").text
        assert "pulse author is not trusted" in client.get("/admin/iocs/2").text
        data.pop("official_author_only")
        assert client.post(url, data=data).status_code == 200
        assert client.get("/lists/domains.txt").text == "community.example\nevil.example\n"
        with client.app.state.db.session() as session:
            assert len(list(session.scalars(select(IOC)))) == 2
            assert session.get(RuntimeSetting, "policy.otx.official_author_only").value == {
                "value": False
            }
    with TestClient(create_app(restart_settings)) as client:
        assert client.app.state.settings.policy.otx.enabled
        assert not client.app.state.settings.policy.otx.official_author_only
        assert client.get("/lists/domains.txt").text == "community.example\nevil.example\n"
        token = login(client)
        client.post(
            "/admin/settings/otx",
            data={"csrf": token, "max_age_days": "30", "official_author_only": "on"},
        )
        assert client.get("/lists/domains.txt").text == ""


def test_runtime_settings_compatibility_and_validation(db, settings):
    with db.session() as session:
        assert session.get(SchemaVersion, 1).version == 3
    load_runtime_settings(db, settings)
    assert not settings.policy.otx.enabled
    save_runtime_setting(db, "policy.otx.max_age_days", 12)
    load_runtime_settings(db, settings)
    assert settings.policy.otx.max_age_days == 12
    assert settings.policy.otx.official_author_only
    for age in (0, 366):
        with pytest.raises(ValidationError):
            Settings(policy={"otx": {"max_age_days": age}})


def test_age_changes_apply_to_existing_data_and_detail(settings):
    settings.providers.otx.enabled = True
    with TestClient(create_app(settings)) as client:
        token = login(client)
        seen = utcnow() - timedelta(days=2)
        ingest(
            client.app.state.db,
            settings,
            "otx",
            [
                candidate(
                    first_seen=seen,
                    last_seen=seen,
                    confidence=None,
                    metadata={"author_name": "AlienVault"},
                )
            ],
        )
        data = {"csrf": token, "enabled": "on", "official_author_only": "on", "max_age_days": "30"}
        assert client.post("/admin/settings/otx", data=data).status_code == 200
        assert client.get("/lists/domains.txt").text == "evil.example\n"
        data["max_age_days"] = "1"
        assert client.post("/admin/settings/otx", data=data).status_code == 200
        assert client.get("/lists/domains.txt").text == ""
        assert "exceeds OTX maximum age" in client.get("/admin/iocs/1").text
        assert (
            client.get("/api/iocs/evil.example").json()["sources"][0]["policy_reason"]
            == "otx_stale"
        )
        data["max_age_days"] = "30"
        client.post("/admin/settings/otx", data=data)
        assert client.get("/lists/domains.txt").text == "evil.example\n"


@pytest.mark.parametrize("disabled", ["provider", "source"])
def test_explicit_source_disable_still_applies(settings, disabled):
    settings.policy.otx.enabled = True
    obs = evidence(settings)
    if disabled == "provider":
        settings.providers.otx.enabled = False
    else:
        settings.policy.sources["otx"].enabled = False
    assert BlockingPolicy(settings).evidence_reason(obs, utcnow()) == "source_not_enabled"


def test_otx_form_requires_authentication(settings):
    with TestClient(create_app(settings)) as client:
        assert (
            client.post(
                "/admin/settings/otx", data={"enabled": "on", "max_age_days": "30"}
            ).status_code
            == 401
        )
