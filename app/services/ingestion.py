import asyncio
import logging
import time
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

from app.config import Settings
from app.database import Database
from app.feeds.base import FeedError, ParsedFeed, ThreatIntelProvider, utcnow
from app.feeds.otx import sync_plan
from app.management import record_event, runtime_setting_value
from app.models import IOC, Observation, ProviderState, ProviderUsage, RuntimeSetting
from app.normalization import normalize

logger = logging.getLogger(__name__)


def store_feed(
    db: Database,
    settings: Settings,
    source: str,
    feed: ParsedFeed,
    started: float | None = None,
    mark_success: bool = True,
    geoip=None,
) -> dict:
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
        if mark_success:
            state.last_success = now
            state.last_error = None
        if started is not None:
            counts["duration_seconds"] = round(time.monotonic() - started, 3)
        state.counts = counts
    if geoip is not None:
        # The feed transaction is committed first; geolocation never changes IOC policy.
        try:
            geoip.enrich_ids(
                [ioc.id for ioc in existing.values() if ioc.ioc_type in ("ipv4", "ipv6")]
            )
        except SQLAlchemyError:
            logger.warning("GeoIP cache persistence failed; committed feed data retained")

    return counts


class UpdateService:
    """Single-process job owner shared by startup, scheduler and manual requests."""

    def __init__(
        self,
        db: Database,
        settings: Settings,
        providers: list[ThreatIntelProvider],
        transport: httpx.AsyncBaseTransport | None = None,
        geoip=None,
    ):
        self.db, self.settings, self.providers = db, settings, providers
        self.transport = transport
        self.geoip = geoip
        self.task: asyncio.Task | None = None
        self.last_result: dict | None = None
        self.trigger_notice = ""
        for provider in providers:
            self._bind_retrieval_state(provider)

    def _store_feed(self, *args):
        return store_feed(*args, geoip=self.geoip)

    def account_request(self, source, successful, status):
        now = utcnow()
        values = {
            "source": source,
            "total_requests": 1,
            "successful_requests": int(successful),
            "failed_requests": int(not successful),
            "rate_limited_requests": int(status == 429),
            "last_request_at": now,
            "last_http_status": status,
            "last_success_at": now if successful else None,
            "last_failure_at": now if not successful else None,
        }
        # One atomic write avoids lost counts when key tests and enrichment overlap.
        changes = {
            key: getattr(ProviderUsage, key) + values[key]
            for key in (
                "total_requests",
                "successful_requests",
                "failed_requests",
                "rate_limited_requests",
            )
        }
        changes.update(last_request_at=now, last_http_status=status)
        changes["last_success_at" if successful else "last_failure_at"] = now
        with self.db.session.begin() as session:
            session.execute(
                insert(ProviderUsage)
                .values(**values)
                .on_conflict_do_update(index_elements=[ProviderUsage.source], set_=changes)
            )

    def _bind_retrieval_state(self, provider):
        if provider.name != "otx":
            return

        def read():
            with self.db.session() as session:
                row = session.get(RuntimeSetting, "otx.retrieval_state")
                return dict(runtime_setting_value(row, {}))

        def write(value):
            if not any(p.name == "otx" and p.key == provider.key for p in self.providers):
                return
            with self.db.session.begin() as session:
                row = session.get(RuntimeSetting, "otx.retrieval_state")
                if row is None:
                    row = RuntimeSetting(name="otx.retrieval_state")
                    session.add(row)
                row.value = {"value": value}

        provider.read_retrieval_state = read
        provider.write_retrieval_state = write

    def replace_provider(self, provider):
        self._bind_retrieval_state(provider)
        provider.account_request = self.account_request
        self.providers = [p for p in self.providers if p.name != provider.name] + [provider]

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    def trigger(self, source: str | None = None) -> bool:
        # Called only on the ASGI event loop; no await between check and reservation.
        if self.running:
            self.trigger_notice = "Update already running"
            return False
        snapshot = [p for p in self.providers if source is None or p.name == source]
        if source is not None and not snapshot:
            self.trigger_notice = "Provider disabled"
            return False
        if source is not None:
            retry_at = self.cooldown_until(source)
            if retry_at:
                self.trigger_notice = (
                    f"Provider {source} is in cooldown. Retry after {retry_at.isoformat()}"
                )
                logger.info(
                    "provider=%s update skipped reason=cooldown retry_at=%s",
                    source,
                    retry_at.isoformat(),
                )
                return False
            if not snapshot[0].key:
                self.trigger_notice = "No provider key configured"
                return False
        self.task = asyncio.create_task(self._run(snapshot))
        return True

    def cooldown_until(self, source):
        with self.db.session() as session:
            state = session.get(ProviderState, source)
            retry_at = state.next_allowed_at if state else None
        return retry_at if retry_at and retry_at > utcnow() else None

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
            state.counts = {
                **state.counts,
                "last_failure_diagnostics": getattr(error, "diagnostics", {}),
            }
            state.next_allowed_at = now + timedelta(seconds=error.retry_seconds)

    async def _run(self, providers=None):
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
                for provider in providers if providers is not None else list(self.providers):
                    provider_start = time.monotonic()
                    try:
                        if not await asyncio.to_thread(self._reserve, provider.name):
                            retry_at = await asyncio.to_thread(self.cooldown_until, provider.name)
                            results[provider.name] = {
                                "status": "cooldown",
                                "retry_at": retry_at.isoformat() if retry_at else None,
                            }
                            logger.info(
                                "provider=%s update skipped reason=cooldown retry_at=%s",
                                provider.name,
                                results[provider.name]["retry_at"],
                            )
                            continue
                        logger.info("provider=%s update started", provider.name)
                        provider_start = time.monotonic()
                        if hasattr(provider, "pages"):
                            counts = {
                                k: 0
                                for k in (
                                    "fetched",
                                    "valid",
                                    "rejected",
                                    "ignored",
                                    "new",
                                    "updated",
                                )
                            }
                            sync_started = utcnow()
                            modified_since = None
                            if provider.name == "otx":
                                with self.db.session() as session:
                                    checkpoint = session.get(RuntimeSetting, "otx.modified_since")
                                modified_since, mode = sync_plan(
                                    self.settings.providers.otx,
                                    checkpoint.value["value"] if checkpoint else None,
                                    sync_started,
                                )
                                logger.info(
                                    "provider=otx operation=sync_plan sync_mode=%s "
                                    "page_size=%s initial_lookback_days=%s",
                                    mode,
                                    provider.page_size,
                                    self.settings.providers.otx.initial_lookback_days,
                                )
                                pages = provider.pages(
                                    client, modified_since=modified_since, sync_mode=mode
                                )
                            else:
                                pages = provider.pages(client)
                            async for feed in pages:
                                batch = await asyncio.to_thread(
                                    self._store_feed,
                                    self.db,
                                    self.settings,
                                    provider.name,
                                    feed,
                                    None,
                                    False,
                                )
                                for key in counts:
                                    counts[key] += batch[key]
                            counts["duration_seconds"] = round(time.monotonic() - provider_start, 3)
                            with self.db.session.begin() as session:
                                state = session.get(ProviderState, provider.name)
                                state.counts = counts
                                state.last_success = utcnow()
                                state.last_error = None
                                current_provider = next(
                                    (p for p in self.providers if p.name == provider.name), None
                                )
                                if (
                                    provider.name == "otx"
                                    and current_provider
                                    and current_provider.key == provider.key
                                ):
                                    checkpoint = session.get(RuntimeSetting, "otx.modified_since")
                                    if checkpoint is None:
                                        checkpoint = RuntimeSetting(name="otx.modified_since")
                                        session.add(checkpoint)
                                    checkpoint.value = {
                                        "value": (
                                            sync_started
                                            - timedelta(
                                                minutes=self.settings.providers.otx.overlap_minutes
                                            )
                                        ).isoformat()
                                    }
                        else:
                            body = await provider.fetch(client)
                            feed = await asyncio.to_thread(provider.parse, body)
                            counts = await asyncio.to_thread(
                                self._store_feed,
                                self.db,
                                self.settings,
                                provider.name,
                                feed,
                                provider_start,
                            )
                        results[provider.name] = {"status": "success", **counts}
                        await asyncio.to_thread(
                            record_event, self.db, provider.name, "INFO", "Feed update completed"
                        )
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
                        logger.warning(
                            "provider=%s error=%s elapsed_seconds=%.3f",
                            provider.name,
                            error.code,
                            time.monotonic() - provider_start,
                        )
                        results[provider.name] = {"status": "failed", "error": error.code}
                        try:
                            await asyncio.to_thread(self._failure, provider.name, error)
                            await asyncio.to_thread(
                                record_event,
                                self.db,
                                provider.name,
                                "WARNING",
                                "Feed update "
                                + error.code
                                + (
                                    " timeout_category="
                                    + error.diagnostics.get("timeout_category", "not_applicable")
                                    + " operation="
                                    + error.diagnostics["operation"]
                                    + " page="
                                    + str(error.diagnostics["page"])
                                    + " elapsed_seconds="
                                    + str(error.diagnostics["elapsed_seconds"])
                                    if hasattr(error, "diagnostics")
                                    else ""
                                ),
                            )
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
