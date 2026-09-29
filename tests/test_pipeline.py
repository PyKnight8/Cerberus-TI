from datetime import timedelta

import pytest
from conftest import candidate, ingest
from sqlalchemy import event, func, select

from app.feeds.base import utcnow
from app.models import IOC, Observation
from app.policy import BlockingPolicy
from app.services.blocklist import domains_text, ioc_query


def test_dedup_and_source_evidence(db, settings):
    row = candidate("EVIL.example.")
    counts = ingest(db, settings, candidates=[row, row])
    assert counts["new"] == 1
    ingest(db, settings, candidates=[row])
    ingest(db, settings, "urlhaus", [candidate("evil.example", "hostname", confidence=None)])
    with db.session() as session:
        ioc = session.scalar(ioc_query())
        assert session.scalar(select(func.count(IOC.id))) == 1
        assert len(ioc.observations) == 2
        assert {o.source for o in ioc.observations} == {"urlhaus", "threatfox"}
        assert {o.confidence for o in ioc.observations} == {None, 90}
        assert ioc.ioc_type == "domain"
    assert domains_text(db, BlockingPolicy(settings)) == "evil.example\n"


def test_distinct_reports_same_source(db, settings):
    ingest(db, settings, candidates=[candidate(external_id="1"), candidate(external_id="2")])
    with db.session() as session:
        assert session.scalar(select(func.count(IOC.id))) == 1
        assert session.scalar(select(func.count(Observation.id))) == 2


def test_allowlist_sorted_blocklist_and_ips(db, settings):
    settings.allowlist.domains = ["allowed.example"]
    ingest(
        db,
        settings,
        candidates=[
            candidate(v, k, external_id=str(n))
            for n, (v, k) in enumerate(
                [
                    ("z.example", "domain"),
                    ("a.example", "hostname"),
                    ("allowed.example", "domain"),
                    ("sub.allowed.example", "hostname"),
                    ("notallowed.example", "domain"),
                    ("10.0.0.1", "ipv4"),
                    ("8.8.8.8", "ipv4"),
                    ("2001:4860::1", "ipv6"),
                    ("router.local", "hostname"),
                ]
            )
        ],
    )
    assert (
        domains_text(db, BlockingPolicy(settings)) == "a.example\nnotallowed.example\nz.example\n"
    )


def test_expiry_repeated_download_does_not_refresh(db, settings):
    old = utcnow() - timedelta(days=8)
    row = candidate(first_seen=old, last_seen=old)
    ingest(db, settings, candidates=[row])
    ingest(db, settings, candidates=[row])
    assert domains_text(db, BlockingPolicy(settings)) == ""
    with db.session() as session:
        ioc = session.scalar(ioc_query())
        assert not BlockingPolicy(settings).evaluate(ioc, utcnow()).active
        assert ioc.last_seen == old
        assert ioc.observations[0].expires_at == old + timedelta(days=7)
    ingest(db, settings, candidates=[candidate(first_seen=old)])
    assert domains_text(db, BlockingPolicy(settings)) == "evil.example\n"


def test_no_mixing_confidence_and_recency(db, settings):
    old = utcnow() - timedelta(days=8)
    ingest(
        db,
        settings,
        candidates=[
            candidate(first_seen=old, last_seen=old, confidence=100),
            candidate(external_id="2", confidence=20),
        ],
    )
    assert domains_text(db, BlockingPolicy(settings)) == ""


@pytest.mark.parametrize(
    "confidence,active,source,expected",
    [
        (80, True, "threatfox", True),
        (79, True, "threatfox", False),
        (None, True, "threatfox", False),
        (None, True, "urlhaus", True),
        (100, False, "threatfox", False),
        (None, False, "urlhaus", False),
        (100, True, "unknown", False),
    ],
)
def test_policy(db, settings, confidence, active, source, expected):
    ingest(db, settings, source, [candidate(confidence=confidence, active=active)])
    assert bool(domains_text(db, BlockingPolicy(settings))) == expected


def test_disabled_source_and_age(db, settings):
    old = utcnow() - timedelta(days=2)
    ingest(db, settings, candidates=[candidate(first_seen=old, last_seen=old)])
    settings.policy.max_age_days = 1
    assert domains_text(db, BlockingPolicy(settings)) == ""
    settings.policy.max_age_days = 7
    settings.providers.threatfox.enabled = False
    assert domains_text(db, BlockingPolicy(settings)) == ""


def test_offline_status_revokes_at_same_evidence_time(db, settings):
    row = candidate()
    ingest(db, settings, "urlhaus", [row])
    ingest(db, settings, "urlhaus", [row.model_copy(update={"active": False})])
    assert domains_text(db, BlockingPolicy(settings)) == ""


def test_batch_transaction_rolls_back(db, settings):
    ingest(db, settings)

    def fail(*args):
        raise RuntimeError("simulated storage failure")

    event.listen(db.session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError):
            ingest(db, settings, candidates=[candidate("second.example")])
    finally:
        event.remove(db.session, "before_commit", fail)
    with db.session() as session:
        assert session.scalar(select(func.count(IOC.id))) == 1


def test_invalid_indicator_rejected_among_valid(db, settings):
    counts = ingest(db, settings, candidates=[candidate(), candidate("not a host")])
    assert counts["valid"] == 1 and counts["rejected"] == 1
