import asyncio
import socket
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import maxminddb
import pytest
import yaml
from conftest import candidate, ingest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, inspect, select, text
from test_web import login

from app.config import Settings
from app.database import Base, Database
from app.feeds.base import ParsedFeed, utcnow
from app.main import create_app
from app.models import IOC, AdminAccount, GeoIPRun, IOCGeoIP, ProviderCredential, SchemaVersion
from app.policy import BlockingPolicy
from app.services.geoip import GeoIPService
from app.services.ingestion import store_feed
from app.services.overview import ThreatOverview


class MockMMDB:
    def __init__(self, role):
        self.role = role
        self.calls = []
        self.closed = False
        self.build = 1750000000
        self.ip_version = 6
        self.error = False
        self.records = {}

    def metadata(self):
        return SimpleNamespace(
            database_type=f"GeoLite2-{self.role}",
            build_epoch=self.build,
            ip_version=self.ip_version,
        )

    def get(self, address):
        assert not self.closed
        self.calls.append(address)
        if self.error:
            raise maxminddb.InvalidDatabaseError("private provider value should not appear in logs")
        return self.records.get(address)

    def close(self):
        self.closed = True


@pytest.fixture
def readers(settings, tmp_path, monkeypatch):
    country, asn = MockMMDB("Country"), MockMMDB("ASN")
    for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        country.records[address] = {"country": {"iso_code": "DE", "names": {"en": "Germany"}}}
        asn.records[address] = {
            "autonomous_system_number": 64500,
            "autonomous_system_organization": "Example Hosting",
        }
    settings.geoip.enabled = True
    settings.geoip.country_database = str(tmp_path / "GeoLite2-Country.mmdb")
    settings.geoip.asn_database = str(tmp_path / "GeoLite2-ASN.mmdb")
    for path in (settings.geoip.country_database, settings.geoip.asn_database):
        Path(path).write_bytes(b"test-only mock reader placeholder")
    monkeypatch.setattr(
        maxminddb, "open_database", lambda path: country if "Country" in path else asn
    )
    return country, asn


@pytest.fixture
def geoip(db, settings, readers):
    service = GeoIPService(db, settings.geoip)
    yield service
    asyncio.run(service.close())


def ip_ids(db):
    with db.session() as session:
        return list(session.scalars(select(IOC.id).order_by(IOC.id)))


def cached(db, ioc_id):
    with db.session() as session:
        return session.get(IOCGeoIP, ioc_id)


@pytest.mark.parametrize("enabled", [False, True])
def test_no_databases_startup_dashboard_and_ingestion(settings, enabled, monkeypatch, caplog):
    settings.geoip.enabled = enabled
    settings.geoip.country_database = "/missing/GeoLite2-Country.mmdb"
    settings.geoip.asn_database = "/missing/GeoLite2-ASN.mmdb"
    monkeypatch.setattr(
        maxminddb, "open_database", lambda path: pytest.fail("must not open absent files")
    )
    with TestClient(create_app(settings)) as client:
        login(client)
        ingest(client.app.state.db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
        html = client.get("/admin").text
        assert "No country attribution yet" in html
        assert "GeoIP disabled" in html if not enabled else "GeoIP database not configured" in html
        assert "GeoIP database not configured" in client.get("/admin/settings").text
        assert client.get("/api/stats/geo").json()["countries"] == []
        assert client.get("/lists/domains.txt").status_code == 200
        assert not client.app.state.geoip.available
    assert "GeoIP" not in caplog.text


def test_disabled_does_not_open_configured_files(db, settings, readers, monkeypatch):
    settings.geoip.enabled = False
    monkeypatch.setattr(
        maxminddb, "open_database", lambda path: pytest.fail("disabled GeoIP opened a file")
    )
    service = GeoIPService(db, settings.geoip)
    assert not service.available
    service.run()
    assert service.status()["run"] is None


@pytest.mark.parametrize("address,kind", [("8.8.8.8", "ipv4"), ("2606:4700:4700::1111", "ipv6")])
def test_lookup_persisted_and_idempotent(db, settings, readers, geoip, address, kind):
    store_feed(
        db,
        settings,
        "threatfox",
        ParsedFeed(candidates=[candidate(address, kind)], fetched=1),
        geoip=geoip,
    )
    row = cached(db, ip_ids(db)[0])
    assert (row.country_code, row.country_name, row.asn, row.asn_organization) == (
        "DE",
        "Germany",
        64500,
        "Example Hosting",
    )
    assert row.status == "matched" and row.database_version["country"]
    before = tuple(len(reader.calls) for reader in readers)
    geoip.enrich_ids(ip_ids(db))
    assert tuple(len(reader.calls) for reader in readers) == before
    geoip.enrich_ids(ip_ids(db), force=True)
    assert cached(db, row.ioc_id).enriched_at == row.enriched_at


@pytest.mark.parametrize(
    "address",
    [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "2001:db8::1",
    ],
)
def test_special_addresses_excluded(db, settings, readers, geoip, address):
    ingest(db, settings, candidates=[candidate(address, "ipv6" if ":" in address else "ipv4")])
    geoip.run()
    assert cached(db, ip_ids(db)[0]).status == "excluded"
    assert all(not reader.calls for reader in readers)
    assert geoip.status()["excluded"] == 1


def test_no_domain_resolution_or_external_lookup(db, settings, readers, geoip, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("DNS resolution attempted")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, forbidden)
    ingest(db, settings, candidates=[candidate("malicious.example"), candidate("8.8.8.8", "ipv4")])
    geoip.run()
    assert all(reader.calls == ["8.8.8.8"] for reader in readers)
    assert geoip.status()["total"] == 1


def test_negative_results_cached(db, settings, readers, geoip):
    ingest(db, settings, candidates=[candidate("9.9.9.9", "ipv4")])
    geoip.run()
    row = cached(db, ip_ids(db)[0])
    assert row.status == "no_result" and row.country_code is None and row.asn is None
    geoip.enrich_ids(ip_ids(db))
    assert all(reader.calls == ["9.9.9.9"] for reader in readers)
    assert geoip.status()["missing"] == 1


def test_refresh_after_database_update(db, settings, readers, geoip):
    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
    geoip.run()
    row = cached(db, ip_ids(db)[0])
    readers[0].records["8.8.8.8"]["country"] = {"iso_code": "US", "names": {"en": "United States"}}
    geoip.databases["country"]["identity"] = "new build identity"
    geoip.databases["country"]["build_date"] = "2026-10-03T00:00:00+00:00"
    geoip.run()
    refreshed = cached(db, row.ioc_id)
    assert refreshed.country_code == "US"
    assert refreshed.database_version != row.database_version
    assert refreshed.enriched_at >= row.enriched_at
    assert geoip.status()["run"].status == "completed"


@pytest.mark.parametrize("missing_role", ["country", "asn"])
def test_partial_database_and_existing_attribution_retained(
    db, settings, readers, geoip, missing_role
):
    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
    geoip.run()
    geoip.readers.pop(missing_role).close()
    geoip.run()
    row = cached(db, ip_ids(db)[0])
    assert row.country_code == "DE" and row.asn == 64500


def test_partial_database_first_lookup(db, settings, readers, geoip):
    geoip.readers.pop("country").close()
    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
    geoip.run()
    row = cached(db, ip_ids(db)[0])
    assert row.country_code is None and row.asn == 64500


def test_invalid_database_starts_normally(db, settings, readers, monkeypatch, caplog):
    def invalid(path):
        raise maxminddb.InvalidDatabaseError("secret file contents")

    monkeypatch.setattr(maxminddb, "open_database", invalid)
    service = GeoIPService(db, settings.geoip)
    assert not service.available
    assert all(info["status"] == "Invalid / unreadable" for info in service.databases.values())
    assert "secret file contents" not in caplog.text


def test_reader_failure_preserves_cache_without_warning_spam(db, settings, readers, geoip, caplog):
    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
    geoip.run()
    for reader in readers:
        reader.error = True
    geoip.run()
    geoip.run()
    assert cached(db, ip_ids(db)[0]).country_code == "DE"
    assert caplog.text.count("database lookup failed") == 2
    assert "private provider value" not in caplog.text


async def test_background_run_batched_and_single_job(db, settings, readers, geoip, monkeypatch):
    settings.geoip.batch_size = 10
    ingest(
        db,
        settings,
        candidates=[candidate(f"8.8.8.{n}", "ipv4", external_id=str(n)) for n in range(1, 26)],
    )
    sizes = []
    original = geoip.enrich_ids

    def tracked(ids, force=False):
        sizes.append(len(ids))
        return original(ids, force=force)

    monkeypatch.setattr(geoip, "enrich_ids", tracked)
    assert geoip.trigger()
    assert not geoip.trigger()
    await geoip.task
    assert sizes == [10, 10, 5]
    run = geoip.status()["run"]
    assert run.processed == run.total == 25 and run.status == "completed"
    with db.session() as session:
        assert session.scalar(select(func.count()).select_from(GeoIPRun)) == 1


def test_interrupted_previous_run(db, settings, readers):
    with db.session.begin() as session:
        session.add(GeoIPRun(id=1, status="running", started_at=utcnow(), processed=5, total=20))
    service = GeoIPService(db, settings.geoip)
    assert service.status()["run"].status == "interrupted"
    assert service.status()["run"].processed == 5
    asyncio.run(service.close())


def test_country_asn_aggregates_and_time_range(db, settings, readers, geoip):
    old = utcnow() - timedelta(days=40)
    ingest(
        db,
        settings,
        candidates=[
            candidate("8.8.8.8", "ipv4"),
            candidate("1.1.1.1", "ipv4", first_seen=old, last_seen=old),
            candidate("2606:4700:4700::1111", "ipv6"),
        ],
    )
    # Another provider observing the same IP must not double-count infrastructure.
    ingest(db, settings, source="otx", candidates=[candidate("8.8.8.8", "ipv4")])
    geoip.run()
    overview = ThreatOverview(db, BlockingPolicy(settings))
    all_data = overview.geography()
    assert all_data["countries"] == [dict(country_code="DE", country_name="Germany", count=3)]
    assert all_data["asns"] == [dict(asn=64500, organization="Example Hosting", count=3)]
    assert overview.geography("30d")["countries"][0]["count"] == 2
    mapped = next(c for c in overview.map_countries(all_data) if c["code"] == "DE")
    assert mapped["count"] == 3 and mapped["shade"] == 2


def test_context_distinct_iocs_dynamic_sources_and_bounded_tags(db, settings):
    ingest(
        db,
        settings,
        source="future-provider",
        candidates=[
            candidate(tags=["Botnet", "botnet", "unknown", "x" * 65], malware_family="Family")
        ],
    )
    ingest(
        db,
        settings,
        source="future-provider",
        candidates=[candidate(external_id="other", tags=["Botnet"], malware_family="Family")],
    )
    ingest(
        db,
        settings,
        candidates=[candidate("other.example", tags=["Botnet"], malware_family="Unknown")],
    )
    overview = ThreatOverview(db, BlockingPolicy(settings))
    context = overview.context()
    assert dict((r["name"], r["count"]) for r in context["sources"])["future-provider"] == 1
    assert context["malware"] == [dict(name="Family", count=1)]
    assert context["tags"] == [dict(name="botnet", count=2)]


def test_stats_cache_avoids_repeated_scans(db, settings):
    overview = ThreatOverview(db, BlockingPolicy(settings))
    overview.geography()
    overview.context()
    overview.metrics()
    queries = []

    def track(*args):
        queries.append(args[2])

    event.listen(db.engine, "before_cursor_execute", track)
    try:
        overview.geography()
        overview.context()
        overview.metrics()
    finally:
        event.remove(db.engine, "before_cursor_execute", track)
    assert queries == []


def test_recent_limit_and_policy_decisions(db, settings):
    ingest(
        db,
        settings,
        candidates=[candidate(f"evil-{n}.example", tags=["sample"]) for n in range(20)],
    )
    overview = ThreatOverview(db, BlockingPolicy(settings))
    assert len(overview.recent()) == 15
    assert all(row["blocked"] for row in overview.recent())
    assert overview.metrics()["total"] == 20
    assert overview.metrics()["active"] == 20
    assert overview.metrics()["blocked"] == 20


def test_dashboard_geo_api_detail_and_country_filter(settings, readers, monkeypatch):
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/stats/geo").status_code == 401
        assert client.get("/api/stats/intelligence").status_code == 401
        assert client.post("/admin/settings/geoip/refresh").status_code == 401
        token = login(client)
        state = client.app.state
        store_feed(
            state.db,
            settings,
            "threatfox",
            ParsedFeed(
                candidates=[candidate("8.8.8.8", "ipv4"), candidate("evil.example")], fetched=2
            ),
            geoip=state.geoip,
        )
        state.overview.invalidate()
        counts = tuple(len(reader.calls) for reader in readers)

        def forbidden(*args, **kwargs):
            pytest.fail("dashboard attempted DNS")

        monkeypatch.setattr(socket, "getaddrinfo", forbidden)
        data = client.get("/api/stats/geo").json()
        assert data["countries"][0]["count"] == 1
        assert data["asns"][0]["asn"] == 64500
        assert "iocs" not in data
        response = client.get("/admin")
        html = response.text
        assert 'class="map-country shade-1"' in html and "Germany · 1 IP IOCs" in html
        assert "Example Hosting" in html and "Recent Intelligence" in html
        assert "script-src 'none'" in response.headers["content-security-policy"]
        assert "Known IP infrastructure" in html and "live attacks" in html
        assert client.get("/api/stats/geo?period=bad").status_code == 422
        assert client.get("/admin?period=30d").status_code == 200
        assert client.get("/admin/iocs?country=DE").text.count("8.8.8.8") == 1
        assert "evil.example" not in client.get("/admin/iocs?country=DE").text
        assert client.get("/admin/iocs?country=bad").status_code == 422
        with state.db.session() as session:
            ioc_id = session.scalar(select(IOC.id).where(IOC.ioc_type == "ipv4"))
        detail = client.get(f"/admin/iocs/{ioc_id}").text
        assert "Germany (DE)" in detail and "AS64500" in detail
        assert tuple(len(reader.calls) for reader in readers) == counts
        assert (
            client.post("/admin/settings/geoip/refresh", data={"csrf": "invalid"}).status_code
            == 403
        )
        assert client.post("/admin/settings/geoip/refresh", data={"csrf": token}).status_code == 200
    assert all(reader.closed for reader in readers)


def test_detail_unavailable_and_untrusted_geoip_text_escaped(settings, readers):
    readers[0].records["8.8.8.8"]["country"]["names"]["en"] = "<script>alert(1)</script>"
    readers[1].records["8.8.8.8"]["autonomous_system_organization"] = "<img src=x onerror=alert(1)>"
    with TestClient(create_app(settings)) as client:
        login(client)
        state = client.app.state
        ingest(
            state.db,
            settings,
            candidates=[candidate("8.8.8.8", "ipv4"), candidate("9.9.9.9", "ipv4")],
        )
        state.geoip.run()
        ids = ip_ids(state.db)
        html = client.get(f"/admin/iocs/{ids[0]}").text
        assert "&lt;script&gt;" in html and "<script>" not in html
        assert "&lt;img" in html
        assert "GeoIP information unavailable" in client.get(f"/admin/iocs/{ids[1]}").text


def test_additive_upgrade_from_schema_three(settings):
    db = Database(settings.database_url)
    old_tables = [
        table
        for table in Base.metadata.sorted_tables
        if table.name not in ("ioc_geoip", "geoip_run")
    ]
    Base.metadata.create_all(db.engine, tables=old_tables)
    with db.engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_observations_recent"))
    ingest(db, settings)
    with db.session.begin() as session:
        session.add(SchemaVersion(id=1, version=3))
        session.add(AdminAccount(id=1, password_hash="persisted-admin"))
        session.add(ProviderCredential(source="otx", ciphertext="persisted-encrypted-key"))

    def snapshot():
        with db.engine.connect() as connection:
            return {
                table.name: connection.execute(select(table)).all()
                for table in old_tables
                if table.name != "schema_version"
            }

    before = snapshot()
    db.initialize()
    db.initialize()
    assert snapshot() == before
    assert {"ioc_geoip", "geoip_run"} <= set(inspect(db.engine).get_table_names())
    assert "ix_observations_recent" in {
        i["name"] for i in inspect(db.engine).get_indexes("observations")
    }
    with db.session() as session:
        assert session.get(SchemaVersion, 1).version == 4
    db.engine.dispose()


def test_compose_geoip_mount_is_optional_read_only_and_selinux_safe():
    root = Path(__file__).parents[1]
    service = yaml.safe_load((root / "docker-compose.yml").read_text())["services"]["cerberus-ti"]
    assert "./geoip:/data/geoip:ro,Z" in service["volumes"]
    assert "USER 10001:10001" in (root / "Dockerfile").read_text()
    config = Settings.model_validate(yaml.safe_load((root / "config.yaml").read_text()))
    assert config.geoip.country_database == "/data/geoip/GeoLite2-Country.mmdb"
    assert config.geoip.asn_database == "/data/geoip/GeoLite2-ASN.mmdb"
    assert not list((root / "app").rglob("*.mmdb"))


def test_city_database_country_fields_only(db, settings, readers):
    readers[0].role = "City"
    readers[0].records["8.8.8.8"]["location"] = {"latitude": 50, "longitude": 10}
    service = GeoIPService(db, settings.geoip)
    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
    service.run()
    row = cached(db, ip_ids(db)[0])
    assert row.country_code == "DE"
    assert not hasattr(row, "latitude")
    asyncio.run(service.close())


def test_ipv4_only_mmdb_skips_ipv6(db, settings, readers):
    for reader in readers:
        reader.ip_version = 4
    service = GeoIPService(db, settings.geoip)
    ingest(db, settings, candidates=[candidate("2606:4700:4700::1111", "ipv6")])
    service.run()
    assert all(not reader.calls for reader in readers)
    assert cached(db, ip_ids(db)[0]).status == "no_result"
    asyncio.run(service.close())


def test_cache_persistence_across_startup_with_databases_removed(settings, readers):
    with TestClient(create_app(settings)) as client:
        db = client.app.state.db
        ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
        client.app.state.geoip.run()
        ioc_id = ip_ids(db)[0]
    settings.geoip.enabled = False
    with TestClient(create_app(settings)) as client:
        login(client)
        assert cached(client.app.state.db, ioc_id).country_code == "DE"
        assert "Germany (DE)" in client.get(f"/admin/iocs/{ioc_id}").text
        assert "GeoIP disabled" in client.get("/admin").text
        assert client.get("/api/stats/geo").json()["countries"][0]["count"] == 1


def test_changed_file_metadata_invalidates_negative_cache(db, settings, readers, geoip):
    ingest(db, settings, candidates=[candidate("9.9.9.9", "ipv4")])
    geoip.run()
    readers[0].records["9.9.9.9"] = readers[0].records["8.8.8.8"]
    geoip.databases["country"]["identity"] = "updated-country-db"
    geoip.enrich_ids(ip_ids(db))
    assert cached(db, ip_ids(db)[0]).country_code == "DE"


def test_idempotent_enrichment_does_not_write_current_rows(db, settings, readers, geoip):
    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
    geoip.enrich_ids(ip_ids(db))
    writes = []

    def track(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
            writes.append(statement)

    event.listen(db.engine, "before_cursor_execute", track)
    try:
        geoip.enrich_ids(ip_ids(db))
        geoip.enrich_ids(ip_ids(db), force=True)
    finally:
        event.remove(db.engine, "before_cursor_execute", track)
    assert writes == []


def test_geoip_cache_failure_does_not_discard_feed(
    db, settings, readers, geoip, monkeypatch, caplog
):
    from sqlalchemy.exc import SQLAlchemyError

    def fail(*args, **kwargs):
        raise SQLAlchemyError("private database details")

    monkeypatch.setattr(geoip, "enrich_ids", fail)
    counts = store_feed(
        db,
        settings,
        "threatfox",
        ParsedFeed(candidates=[candidate("8.8.8.8", "ipv4")], fetched=1),
        geoip=geoip,
    )
    assert counts["new"] == 1 and len(ip_ids(db)) == 1
    assert "committed feed data retained" in caplog.text
    assert "private database details" not in caplog.text


def test_shutdown_interrupts_job_and_closes_readers(db, settings, readers, geoip):
    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4")])
    geoip.stop.set()
    geoip.run()
    assert geoip.status()["run"].status == "interrupted"
    assert not cached(db, ip_ids(db)[0])


def test_top_countries_and_asns_order_and_limits(db, settings):
    ingest(
        db,
        settings,
        candidates=[candidate(f"8.8.8.{n}", "ipv4", external_id=str(n)) for n in range(1, 25)],
    )
    codes = ["US", "DE", "NL", "FR", "GB", "JP", "CN", "CA", "AU", "BR", "IN", "KR"]
    with db.session.begin() as session:
        for index, ioc_id in enumerate(ip_ids(db)):
            session.add(
                IOCGeoIP(
                    ioc_id=ioc_id,
                    country_code=codes[index % len(codes)],
                    country_name=codes[index % len(codes)],
                    asn=1000 + index // 2,
                    asn_organization=f"Network {index // 2}",
                    enriched_at=utcnow(),
                    database_version={},
                    status="matched",
                )
            )
    overview = ThreatOverview(db, BlockingPolicy(settings))
    data = overview.geography()
    assert len(data["countries"]) == 12 and sum(c["count"] for c in data["countries"]) == 24
    assert data["countries"][0] == dict(country_code="AU", country_name="AU", count=2)
    assert len(data["asns"]) == 10
    assert data["asns"][0] == dict(asn=1000, organization="Network 0", count=2)
    assert data["asns"][-1]["asn"] == 1009


def test_country_filter_preserves_period_and_pagination(settings, readers):
    with TestClient(create_app(settings)) as client:
        login(client)
        state = client.app.state
        ingest(
            state.db,
            settings,
            candidates=[candidate(f"8.8.8.{n}", "ipv4", external_id=str(n)) for n in range(1, 55)],
        )
        with state.db.session.begin() as session:
            for ioc_id in ip_ids(state.db):
                session.add(
                    IOCGeoIP(
                        ioc_id=ioc_id,
                        country_code="DE",
                        country_name="Germany",
                        enriched_at=utcnow(),
                        database_version={},
                        status="matched",
                    )
                )
            session.get(IOC, 1).last_seen = utcnow() - timedelta(days=40)
        first = client.get("/admin/iocs?country=DE&period=30d").text
        assert "53 matching indicators" in first
        assert "country=DE&period=30d&page_number=2" in first
        second = client.get("/admin/iocs?country=DE&period=30d&page_number=2").text
        assert "8.8.8.1</a>" not in second
        assert "8.8.8.2</a>" in second


def test_ingestion_service_automatically_enriches_ips(db, settings, readers, geoip):
    from app.services.ingestion import UpdateService

    service = UpdateService(db, settings, [], geoip=geoip)
    service._store_feed(
        db, settings, "otx", ParsedFeed(candidates=[candidate("8.8.8.8", "ipv4")], fetched=1)
    )
    assert cached(db, ip_ids(db)[0]).country_code == "DE"


def test_loaded_database_metadata_visible(settings, readers):
    with TestClient(create_app(settings)) as client:
        login(client)
        html = client.get("/admin/settings").text
        assert "Loaded" in html and "GeoLite2-Country" in html and "GeoLite2-ASN" in html
        assert "2025-06-15" in html
        assert "IP IOCs enriched" in html and "IP IOCs missing GeoIP" in html


def test_bundled_world_geometry_is_local_and_offline():
    from app.services.overview import WORLD

    assert len(WORLD) > 150
    assert len({country["code"] for country in WORLD}) == len(WORLD)
    assert {"US", "DE", "JO", "NL"} <= {country["code"] for country in WORLD}
    assert all(country["path"].startswith("M") for country in WORLD)
    template = (Path(__file__).parents[1] / "app/templates/threat_overview.html").read_text()
    assert "<script" not in template and "https://" not in template


@pytest.mark.parametrize("database_type", ["Unrelated-MMDB", 123])
def test_incompatible_metadata_is_not_used(db, settings, readers, monkeypatch, database_type):
    for reader in readers:
        monkeypatch.setattr(
            reader,
            "metadata",
            lambda: SimpleNamespace(
                database_type=database_type, build_epoch=1750000000, ip_version=6
            ),
        )
    service = GeoIPService(db, settings.geoip)
    assert not service.available
    assert all(reader.closed for reader in readers)


def test_geoip_does_not_modify_other_persisted_data(db, settings, readers, geoip):
    from app.models import IOCEnrichment

    ingest(db, settings, candidates=[candidate("8.8.8.8", "ipv4"), candidate("evil.example")])
    with db.session.begin() as session:
        session.add(AdminAccount(id=1, password_hash="persisted-hash"))
        session.add(ProviderCredential(source="otx", ciphertext="persisted-ciphertext"))
        session.add(
            IOCEnrichment(
                ioc_id=ip_ids(db)[0],
                provider="virustotal",
                result={"cached": "enrichment"},
                queried_at=utcnow(),
                expires_at=utcnow() + timedelta(hours=24),
            )
        )

    def snapshot():
        with db.engine.connect() as connection:
            return {
                table.name: connection.execute(select(table)).all()
                for table in Base.metadata.sorted_tables
                if table.name not in ("ioc_geoip", "geoip_run")
            }

    before = snapshot()
    geoip.run()
    geoip.run()
    assert snapshot() == before
