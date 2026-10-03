"""Local-only country/ASN attribution. No DNS, HTTP, or database downloads."""

import asyncio
import hashlib
import json
import logging
import re
import threading
from datetime import UTC, datetime
from pathlib import Path

import maxminddb
from sqlalchemy import func, select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError

from app.feeds.base import utcnow
from app.models import IOC, GeoIPRun, IOCGeoIP
from app.normalization import safe_indicator

logger = logging.getLogger(__name__)
IP_TYPES = ("ipv4", "ipv6")


def bounded_text(value, length):
    return value[:length] if isinstance(value, str) and value.strip() else None


class GeoIPService:
    def __init__(self, db, config):
        self.db, self.config = db, config
        self.readers = {}
        self.databases = {}
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.task = None
        self.on_change = lambda: None
        for role in ("country", "asn"):
            path = getattr(config, f"{role}_database")
            info = {"path": path, "status": "Disabled" if not config.enabled else "Missing"}
            self.databases[role] = info
            if not config.enabled or not path:
                continue
            reader = None
            try:
                stat = Path(path).stat()
                reader = maxminddb.open_database(path)
                metadata = reader.metadata()
                expected = ("Country", "City") if role == "country" else ("ASN",)
                if (
                    not isinstance(metadata.database_type, str)
                    or not metadata.database_type.endswith(expected)
                    or metadata.ip_version not in (4, 6)
                ):
                    raise ValueError("wrong database type")
                info.update(
                    status="Loaded",
                    database_type=metadata.database_type,
                    build_date=datetime.fromtimestamp(metadata.build_epoch, UTC).isoformat(),
                    build_epoch=metadata.build_epoch,
                    ip_version=metadata.ip_version,
                    identity=f"{metadata.database_type}:{metadata.build_epoch}:{stat.st_size}:{stat.st_mtime_ns}",
                )
                self.readers[role] = reader
            except FileNotFoundError:
                pass  # An unconfigured installation is normal, not a warning.
            except (OSError, ValueError, OverflowError, maxminddb.InvalidDatabaseError):
                info["status"] = "Invalid / unreadable"
                logger.warning("GeoIP %s database unavailable; local enrichment limited", role)
            finally:
                if reader is not None and role not in self.readers:
                    reader.close()
        # Mark an interrupted previous process's job without restarting work implicitly.
        with db.session.begin() as session:
            run = session.get(GeoIPRun, 1)
            if run and run.status == "running":
                run.status, run.completed_at = "interrupted", utcnow()

    @property
    def available(self):
        return self.config.enabled and bool(self.readers)

    @property
    def version(self):
        identities = {role: self.databases[role]["identity"] for role in self.readers}
        return {
            "fingerprint": hashlib.sha256(
                json.dumps(identities, sort_keys=True).encode()
            ).hexdigest(),
            **{role: self.databases[role]["build_date"] for role in self.readers},
        }

    @property
    def running(self):
        return self.task is not None and not self.task.done()

    def _record(self, role, address):
        reader = self.readers.get(role)
        if reader is None:
            return None
        if ":" in address and self.databases[role]["ip_version"] == 4:
            return None
        try:
            result = reader.get(address)
            return result if isinstance(result, dict) else None
        except (ValueError, OSError, maxminddb.InvalidDatabaseError):
            # A reader failure is not a negative lookup. Retain previous cached data
            # and stop using this reader until restart rather than spamming warnings.
            logger.warning("GeoIP %s database lookup failed; restart after checking the file", role)
            self.databases[role]["status"] = "Invalid / unreadable"
            self.readers.pop(role).close()
            return None

    def _payload(self, ioc, previous):
        if not safe_indicator(ioc.normalized_value, ioc.ioc_type):
            return dict(
                country_code=None,
                country_name=None,
                asn=None,
                asn_organization=None,
                status="excluded",
                database_version=self.version,
            )
        # Missing one database must not erase attribution supplied by it previously.
        payload = {
            field: getattr(previous, field) if previous else None
            for field in ("country_code", "country_name", "asn", "asn_organization")
        }
        versions = dict(previous.database_version) if previous else {}
        for role in tuple(self.readers):
            data = self._record(role, ioc.normalized_value)
            if role not in self.readers:
                continue
            versions[role] = self.databases[role]["build_date"]
            if role == "country":
                country = (data or {}).get("country", {})
                if not isinstance(country, dict):
                    country = {}
                code = country.get("iso_code")
                names = country.get("names", {})
                payload["country_code"] = (
                    code.upper()
                    if isinstance(code, str) and re.fullmatch("[A-Za-z]{2}", code)
                    else None
                )
                payload["country_name"] = (
                    bounded_text(names.get("en") if isinstance(names, dict) else None, 128)
                    if payload["country_code"]
                    else None
                )
            else:
                asn = (data or {}).get("autonomous_system_number")
                payload["asn"] = asn if type(asn) is int and 0 < asn <= 4294967295 else None
                payload["asn_organization"] = (
                    bounded_text((data or {}).get("autonomous_system_organization"), 256)
                    if payload["asn"]
                    else None
                )
        versions["fingerprint"] = self.version["fingerprint"]
        payload.update(
            database_version=versions,
            status="matched" if payload["country_code"] or payload["asn"] else "no_result",
        )
        return payload

    def enrich_ids(self, ids, force=False):
        """Bounded ingestion hook; cache negative results and skip current entries."""
        if not self.available:
            return 0
        processed = 0
        # Release the read transaction before local lookup and write transactions;
        # concurrent feed ingestion must not cause SQLite WAL read-to-write upgrades.
        for start in range(0, len(ids), self.config.batch_size):
            with self.lock:
                if self.stop.is_set() or not self.available:
                    break
                with self.db.session() as session:
                    rows = session.execute(
                        select(IOC, IOCGeoIP)
                        .outerjoin(IOCGeoIP, IOCGeoIP.ioc_id == IOC.id)
                        .where(
                            IOC.id.in_(ids[start : start + self.config.batch_size]),
                            IOC.ioc_type.in_(IP_TYPES),
                        )
                        .order_by(IOC.id)
                    ).all()
                writes = []
                for ioc, previous in rows:
                    processed += 1
                    if (
                        not force
                        and previous
                        and previous.database_version.get("fingerprint")
                        == self.version["fingerprint"]
                    ):
                        continue
                    payload = self._payload(ioc, previous)
                    if not self.available:
                        continue
                    if previous and all(
                        getattr(previous, key) == value for key, value in payload.items()
                    ):
                        continue
                    writes.append(dict(ioc_id=ioc.id, enriched_at=utcnow(), **payload))
                if writes:
                    with self.db.session.begin() as session:
                        for values in writes:
                            session.execute(
                                insert(IOCGeoIP)
                                .values(**values)
                                .on_conflict_do_update(
                                    index_elements=[IOCGeoIP.ioc_id],
                                    set_={k: v for k, v in values.items() if k != "ioc_id"},
                                )
                            )
        return processed

    def run(self, force=True):
        """Keyset batches, fixed upper bound, short SQLite transactions."""
        if not self.available:
            return
        with self.db.session.begin() as session:
            upper = session.scalar(select(func.max(IOC.id))) or 0
            total = (
                session.scalar(
                    select(func.count())
                    .select_from(IOC)
                    .where(IOC.ioc_type.in_(IP_TYPES), IOC.id <= upper)
                )
                or 0
            )
            values = dict(
                id=1,
                started_at=utcnow(),
                completed_at=None,
                status="running",
                processed=0,
                total=total,
            )
            session.execute(
                insert(GeoIPRun)
                .values(**values)
                .on_conflict_do_update(index_elements=[GeoIPRun.id], set_=values)
            )
        cursor = processed = 0
        try:
            while not self.stop.is_set() and self.available:
                with self.db.session() as session:
                    ids = list(
                        session.scalars(
                            select(IOC.id)
                            .where(IOC.ioc_type.in_(IP_TYPES), IOC.id > cursor, IOC.id <= upper)
                            .order_by(IOC.id)
                            .limit(self.config.batch_size)
                        )
                    )
                if not ids:
                    break
                processed += self.enrich_ids(ids, force=force)
                cursor = ids[-1]
                with self.db.session.begin() as session:
                    session.get(GeoIPRun, 1).processed = processed
            with self.db.session.begin() as session:
                run = session.get(GeoIPRun, 1)
                run.status = (
                    "interrupted"
                    if self.stop.is_set()
                    else ("completed" if self.available else "failed")
                )
                run.completed_at = utcnow()
        except SQLAlchemyError:
            logger.error("GeoIP batch persistence failed")
            with self.db.session.begin() as session:
                run = session.get(GeoIPRun, 1)
                run.status, run.completed_at = "failed", utcnow()
        finally:
            self.on_change()

    def trigger(self):
        if self.running or not self.available:
            return False
        self.task = asyncio.create_task(asyncio.to_thread(self.run))
        return True

    def status(self):
        with self.lock:
            databases = {role: dict(info) for role, info in self.databases.items()}
        with self.db.session() as session:
            total = (
                session.scalar(
                    select(func.count()).select_from(IOC).where(IOC.ioc_type.in_(IP_TYPES))
                )
                or 0
            )
            enriched = (
                session.scalar(
                    select(func.count()).select_from(IOCGeoIP).where(IOCGeoIP.status == "matched")
                )
                or 0
            )
            excluded = (
                session.scalar(
                    select(func.count()).select_from(IOCGeoIP).where(IOCGeoIP.status == "excluded")
                )
                or 0
            )
            run = session.get(GeoIPRun, 1)
        return dict(
            enabled=self.config.enabled,
            available=self.available,
            databases=databases,
            total=total,
            enriched=enriched,
            missing=total - enriched - excluded,
            excluded=excluded,
            running=self.running,
            run=run,
        )

    async def close(self):
        self.stop.set()
        if self.task:
            await self.task
        with self.lock:
            for reader in self.readers.values():
                reader.close()
            self.readers.clear()
