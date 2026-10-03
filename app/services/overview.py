"""Small cached SQL aggregates and bounded recent intelligence for the console."""

import json
import threading
import time
from datetime import timedelta
from pathlib import Path

from sqlalchemy import String, cast, func, select, true

from app.feeds.base import utcnow
from app.models import IOC, IOCGeoIP, Observation
from app.services.blocklist import ioc_query

WORLD = json.loads((Path(__file__).parents[1] / "static" / "world-countries.json").read_text())


class ThreatOverview:
    def __init__(self, db, policy):
        self.db, self.policy = db, policy
        self.cache = {}
        self.lock = threading.RLock()

    def invalidate(self):
        with self.lock:
            self.cache.clear()

    def _cached(self, key, ttl, build):
        with self.lock:
            cached = self.cache.get(key)
            if cached and time.monotonic() - cached[0] < ttl:
                return cached[1]
            value = build()
            self.cache[key] = (time.monotonic(), value)
            return value

    def geography(self, period="all"):
        def build():
            countries = (
                select(IOCGeoIP.country_code, func.max(IOCGeoIP.country_name), func.count())
                .join(IOC, IOC.id == IOCGeoIP.ioc_id)
                .where(IOC.ioc_type.in_(("ipv4", "ipv6")), IOCGeoIP.country_code.is_not(None))
            )
            asns = (
                select(IOCGeoIP.asn, func.max(IOCGeoIP.asn_organization), func.count())
                .join(IOC, IOC.id == IOCGeoIP.ioc_id)
                .where(IOC.ioc_type.in_(("ipv4", "ipv6")), IOCGeoIP.asn.is_not(None))
            )
            if period == "30d":
                cutoff = utcnow() - timedelta(days=30)
                countries = countries.where(IOC.last_seen >= cutoff)
                asns = asns.where(IOC.last_seen >= cutoff)
            with self.db.session() as session:
                country_rows = session.execute(
                    countries.group_by(IOCGeoIP.country_code).order_by(
                        func.count().desc(), IOCGeoIP.country_code
                    )
                ).all()
                asn_rows = session.execute(
                    asns.group_by(IOCGeoIP.asn)
                    .order_by(func.count().desc(), IOCGeoIP.asn)
                    .limit(10)
                ).all()
            return dict(
                period=period,
                timestamp=utcnow().isoformat(),
                countries=[
                    dict(country_code=code, country_name=name or code, count=count)
                    for code, name, count in country_rows
                ],
                asns=[
                    dict(asn=asn, organization=org or "Unknown network", count=count)
                    for asn, org, count in asn_rows
                ],
            )

        return self._cached(("geo", period), 60, build)

    def context(self):
        def build():
            with self.db.session() as session:
                source_rows = session.execute(
                    select(Observation.source, func.count(func.distinct(Observation.ioc_id)))
                    .group_by(Observation.source)
                    .order_by(
                        func.count(func.distinct(Observation.ioc_id)).desc(), Observation.source
                    )
                ).all()
                family = func.trim(Observation.malware_family)
                family_rows = session.execute(
                    select(family, func.count(func.distinct(Observation.ioc_id)))
                    .where(
                        Observation.malware_family.is_not(None),
                        func.lower(family).not_in(("", "unknown", "null", "n/a")),
                    )
                    .group_by(family)
                    .order_by(func.count(func.distinct(Observation.ioc_id)).desc(), family)
                    .limit(10)
                ).all()
                # SQLite's JSON table function, capped strings and top-N result. Cache
                # this scan for five minutes; never transfer observation JSON to UI.
                tags = func.json_each(Observation.tags).table_valued("value", "type").alias("tag")
                tag = func.lower(func.trim(cast(tags.c.value, String)))
                tag_rows = session.execute(
                    select(tag, func.count(func.distinct(Observation.ioc_id)))
                    .select_from(Observation)
                    .join(tags, true())
                    .where(
                        tags.c.type == "text",
                        func.length(tag).between(1, 64),
                        tag.not_in(("unknown", "null", "n/a")),
                    )
                    .group_by(tag)
                    .order_by(func.count(func.distinct(Observation.ioc_id)).desc(), tag)
                    .limit(10)
                ).all()
            return dict(
                sources=[dict(name=name, count=count) for name, count in source_rows],
                malware=[dict(name=name, count=count) for name, count in family_rows],
                tags=[dict(name=name, count=count) for name, count in tag_rows],
            )

        return self._cached("context", 300, build)

    def metrics(self):
        # Policy edits must not display the old blocked total until cache expiry.
        signature = (
            self.policy.settings.policy.model_dump_json(),
            self.policy.settings.providers.model_dump_json(),
            self.policy.allowlist,
        )

        def build():
            now = utcnow()
            with self.db.session() as session:
                types = dict(
                    session.execute(select(IOC.ioc_type, func.count()).group_by(IOC.ioc_type)).all()
                )
                active = (
                    session.scalar(
                        select(func.count(func.distinct(Observation.ioc_id))).where(
                            Observation.active.is_(True),
                            Observation.expires_at > now,
                            Observation.last_seen
                            > now - timedelta(days=self.policy.settings.policy.expiration_days),
                        )
                    )
                    or 0
                )
                blocked = sum(
                    self.policy.evaluate(ioc, now).blocked
                    for ioc in session.scalars(
                        ioc_query().where(IOC.ioc_type.in_(("domain", "hostname")))
                    ).yield_per(250)
                )
            return dict(total=sum(types.values()), types=types, active=active, blocked=blocked)

        # Replace rather than accumulating cache entries after policy changes.
        with self.lock:
            previous = self.cache.get("policy_signature")
            if previous != signature:
                self.cache.pop("metrics", None)
                self.cache["policy_signature"] = signature
        return self._cached("metrics", 60, build)

    def recent(self):
        now = utcnow()
        with self.db.session() as session:
            observations = list(
                session.scalars(
                    select(Observation)
                    .order_by(Observation.fetched_at.desc(), Observation.id.desc())
                    .limit(15)
                )
            )
            ids = {o.ioc_id for o in observations}
            iocs = {ioc.id: ioc for ioc in session.scalars(ioc_query().where(IOC.id.in_(ids)))}
            return [
                dict(
                    id=o.ioc_id,
                    ioc=iocs[o.ioc_id].normalized_value,
                    type=iocs[o.ioc_id].ioc_type,
                    source=o.source,
                    context=o.malware_family or ", ".join(str(t)[:64] for t in o.tags[:3]),
                    first_seen=o.first_seen,
                    last_seen=o.last_seen,
                    fetched_at=o.fetched_at,
                    blocked=self.policy.evaluate(iocs[o.ioc_id], now).blocked,
                )
                for o in observations
            ]

    def map_countries(self, geography):
        counts = {c["country_code"]: c["count"] for c in geography["countries"]}
        return [
            {
                **country,
                "count": counts.get(country["code"], 0),
                "shade": (
                    1
                    if counts[country["code"]] == 1
                    else min(5, len(str(counts[country["code"]])) + 1)
                )
                if country["code"] in counts
                else 0,
            }
            for country in WORLD
        ]
