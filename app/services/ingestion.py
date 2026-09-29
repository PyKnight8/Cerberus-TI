import asyncio
import logging
import time
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import Settings
from app.database import Database
from app.feeds.base import FeedError, ParsedFeed, ThreatIntelProvider, utcnow
from app.models import IOC, Observation, ProviderState
from app.normalization import normalize

logger = logging.getLogger(__name__)


def store_feed(db: Database, settings: Settings, source: str, feed: ParsedFeed) -> dict:
    """Commit a whole provider batch atomically. External IDs preserve distinct evidence."""
    now = utcnow()
    counts = {
        "fetched": feed.fetched,
        "valid": 0,
        "rejected": feed.rejected,
        "ignored": feed.ignored,
        "new": 0,
        "updated": 0,
    }
    valid = []
    for candidate in feed.candidates:
        try:
            value, kind = normalize(candidate.value, candidate.ioc_type)
            valid.append((candidate, value, kind))
        except ValueError:
            counts["rejected"] += 1
    counts["valid"] = len(valid)
    if feed.candidates and not valid:
        raise FeedError("no_valid_indicators")
    with db.session.begin() as session:
        values = list({v for _, v, _ in valid})
        existing = {}
        for start in range(0, len(values), 500):
            rows = session.scalars(
                select(IOC)
                .where(IOC.normalized_value.in_(values[start : start + 500]))
                .options(selectinload(IOC.observations))
            )
            existing.update({r.normalized_value: r for r in rows})
        observations = {
            (value, o.source, o.external_id): o
            for value, ioc in existing.items()
            for o in ioc.observations
        }
        new_values, updated_values = set(), set()
        for candidate, value, kind in valid:
            ioc = existing.get(value)
            if ioc is None:
                ioc = IOC(
                    value=candidate.value,
                    normalized_value=value,
                    ioc_type=kind,
                    first_seen=candidate.first_seen,
                    last_seen=candidate.last_seen,
                    created_at=now,
                    updated_at=now,
                )
                session.add(ioc)
                existing[value] = ioc
                new_values.add(value)
            elif value not in new_values:
                updated_values.add(value)
            # Domain/hostname are one identity. Preserve the broader source classification.
            if kind == "domain":
                ioc.ioc_type = "domain"
            ioc.first_seen = min(ioc.first_seen, candidate.first_seen)
            ioc.last_seen = max(ioc.last_seen, candidate.last_seen)
            ioc.updated_at = now
            key = (value, source, candidate.external_id)
            observation = observations.get(key)
            if observation is None:
                observation = Observation(
                    ioc=ioc,
                    source=source,
                    external_id=candidate.external_id,
                    first_seen=candidate.first_seen,
                )
                session.add(observation)
                observations[key] = observation
            observation.first_seen = min(observation.first_seen, candidate.first_seen)
            observation.fetched_at = now
            # Ignore regressions in source evidence time, but accept status changes at equal time.
            if observation.last_seen is not None and candidate.last_seen < observation.last_seen:
                continue
            observation.last_seen = candidate.last_seen
            observation.reported_type = candidate.ioc_type
            observation.confidence = candidate.confidence
            observation.expires_at = candidate.last_seen + timedelta(
                days=settings.policy.expiration_days
            )
            observation.active = candidate.active
            observation.malware_family = candidate.malware_family
            observation.tags = candidate.tags
            observation.details = candidate.metadata
        counts["new"], counts["updated"] = len(new_values), len(updated_values)
        state = session.get(ProviderState, source)
        if state is None:
            state = ProviderState(source=source)
            session.add(state)
        state.last_success = now
        state.last_error = None
        state.counts = counts
    return counts


class UpdateService:
    """Single-process job owner shared by startup, scheduler and manual requests."""

    def __init__(
        self,
        db: Database,
        settings: Settings,
        providers: list[ThreatIntelProvider],
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.db, self.settings, self.providers = db, settings, providers
        self.transport = transport
        self.task: asyncio.Task | None = None
        self.last_result: dict | None = None

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    def trigger(self) -> bool:
        # Called only on the ASGI event loop; no await between check and reservation.
        if self.running:
            return False
        self.task = asyncio.create_task(self._run())
        return True

    def _reserve(self, source):
        now = utcnow()
        with self.db.session.begin() as session:
            state = session.get(ProviderState, source)
            if state is None:
                state = ProviderState(source=source)
                session.add(state)
            if state.next_allowed_at and state.next_allowed_at > now:
                return False
            state.last_attempt = now
            state.next_allowed_at = now + timedelta(minutes=5)
        return True

    def _failure(self, source, error):
        now = utcnow()
        with self.db.session.begin() as session:
            state = session.get(ProviderState, source)
            if state is None:
                state = ProviderState(source=source)
                session.add(state)
            state.last_failure = now
            state.last_error = error.code
            state.next_allowed_at = now + timedelta(seconds=error.retry_seconds)

    async def _run(self):
        start = time.monotonic()
        results = {}
        logger.info("update started")
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.http.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
                headers={"Accept-Encoding": "identity", "User-Agent": "Cerberus-TI/0.1"},
                transport=self.transport,
            ) as client:
                for provider in self.providers:
                    try:
                        if not await asyncio.to_thread(self._reserve, provider.name):
                            results[provider.name] = {"status": "cooldown"}
                            continue
                        logger.info("provider=%s update started", provider.name)
                        body = await provider.fetch(client)
                        feed = await asyncio.to_thread(provider.parse, body)
                        counts = await asyncio.to_thread(
                            store_feed, self.db, self.settings, provider.name, feed
                        )
                        results[provider.name] = {"status": "success", **counts}
                        logger.info(
                            "provider=%s fetched=%d valid=%d rejected=%d "
                            "ignored=%d new=%d updated=%d",
                            provider.name,
                            counts["fetched"],
                            counts["valid"],
                            counts["rejected"],
                            counts["ignored"],
                            counts["new"],
                            counts["updated"],
                        )
                    except Exception as exc:
                        error = exc if isinstance(exc, FeedError) else FeedError("processing_error")
                        # Do not log exception strings, URLs, response bodies, or credentials.
                        logger.warning("provider=%s error=%s", provider.name, error.code)
                        results[provider.name] = {"status": "failed", "error": error.code}
                        try:
                            await asyncio.to_thread(self._failure, provider.name, error)
                        except Exception:
                            logger.error("provider=%s error=state_write_failed", provider.name)
        except Exception:
            logger.error("update error=update_failed")
            results["update"] = {"status": "failed", "error": "update_failed"}
        finally:
            self.last_result = {
                "completed_at": utcnow().isoformat(),
                "providers": results,
                "duration_seconds": round(time.monotonic() - start, 3),
            }
            logger.info("update completed duration_seconds=%.3f", time.monotonic() - start)

    async def close(self):
        # Let a bounded in-flight fetch/transaction finish before disposing the database.
        if self.running:
            await self.task
