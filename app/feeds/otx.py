import asyncio
import hashlib
import json
import logging
import random
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urljoin, urlsplit

from pydantic import ValidationError

from app.config import OTXConfig
from app.feeds.base import (
    Candidate,
    FeedError,
    ParsedFeed,
    ThreatIntelProvider,
    redact_provider_data,
    utcnow,
)
from app.normalization import normalize, url_indicator

logger = logging.getLogger(__name__)


def sync_plan(config, checkpoint, started):
    """One plan shared by ingestion and the Feeds UI; no checkpoint writes here."""
    if checkpoint and config.incremental:
        return checkpoint, "incremental"
    prefix = "resync" if checkpoint else "initial"
    if config.initial_lookback_days is not None:
        since = started - timedelta(days=config.initial_lookback_days)
        return since.isoformat(), prefix + "_lookback"
    return None, prefix + "_full"


class OTXProvider(ThreatIntelProvider):
    name = "otx"
    endpoint = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    def __init__(self, key, limits, max_pages=100, page_size=10, *, config=None):
        super().__init__(key, limits)
        self.max_pages = max_pages
        self.page_size = page_size
        self.config = config or OTXConfig()
        self.timeouts = self.config.http

    activity_endpoint = "https://otx.alienvault.com/api/v1/pulses/activity"

    def next_params(self, link, current_page, modified_since, endpoint=None):
        endpoint = endpoint or self.endpoint
        # Follow official pagination parameters, but never send credentials off-endpoint.
        if not isinstance(link, str) or len(link) > 4096:
            raise FeedError("invalid_pagination")
        url = urlsplit(urljoin(endpoint, link))
        if (
            url.scheme != "https"
            or url.netloc != "otx.alienvault.com"
            or url.path.rstrip("/") != urlsplit(endpoint).path
            or url.fragment
        ):
            raise FeedError("invalid_pagination")
        query = parse_qs(url.query, keep_blank_values=True)
        if set(query) - {"page", "limit", "modified_since"} or any(
            len(v) != 1 for v in query.values()
        ):
            raise FeedError("invalid_pagination")
        try:
            page = int(query["page"][0])
            limit = int(query.get("limit", [str(self.page_size)])[0])
        except (ValueError, KeyError):
            raise FeedError("invalid_pagination") from None
        if page <= current_page or not 1 <= limit <= 100:
            raise FeedError("invalid_pagination")
        params = {"page": page, "limit": limit}
        if "modified_since" in query and query["modified_since"][0] != modified_since:
            raise FeedError("invalid_pagination")
        if modified_since:
            params["modified_since"] = modified_since
        return params

    async def _wait_before_retry(self, seconds):
        await asyncio.sleep(seconds)

    async def page_request(self, client, params, sync_mode, endpoint=None):
        endpoint = endpoint or self.endpoint
        operation = "activity_pulses" if endpoint == self.activity_endpoint else "subscribed_pulses"
        # Only transient gateway/service responses are retried. Key tests, 429s,
        # authentication errors, malformed payloads and local timeouts stay unchanged.
        for attempt in range(1, self.config.transient_retries + 2):
            logger.info(
                "provider=otx operation=%s sync_mode=%s page=%s "
                "page_size=%s attempt=%s request started",
                operation,
                sync_mode,
                params["page"],
                params["limit"],
                attempt,
            )
            try:
                return await self.request(
                    client,
                    "GET",
                    endpoint,
                    operation=operation,
                    page=params["page"],
                    headers={"X-OTX-API-KEY": self.key},
                    params=params,
                )
            except FeedError as error:
                error.diagnostics = {
                    **getattr(error, "diagnostics", {}),
                    "page_size": params["limit"],
                    "sync_mode": sync_mode,
                    "attempt": attempt,
                }
                if (
                    error.code not in ("http_error_502", "http_error_503", "http_error_504")
                    or attempt > self.config.transient_retries
                ):
                    raise
                base_delay = min(self.config.retry_backoff_seconds * 2 ** (attempt - 1), 60)
                delay = base_delay + random.uniform(0, min(base_delay / 2, 60 - base_delay))
                logger.warning(
                    "provider=otx operation=%s sync_mode=%s page=%s "
                    "page_size=%s attempt=%s error=%s retry_attempt=%s retry_in_seconds=%.3f",
                    operation,
                    sync_mode,
                    params["page"],
                    params["limit"],
                    attempt,
                    error.code,
                    attempt + 1,
                    delay,
                )
                await self._wait_before_retry(delay)

    async def pages(self, client, modified_since=None, sync_mode=None):
        if sync_mode is None:
            if modified_since:
                sync_mode = "incremental"
            else:
                modified_since, sync_mode = sync_plan(self.config, None, utcnow())
        state = (
            await asyncio.to_thread(self.read_retrieval_state)
            if hasattr(self, "read_retrieval_state")
            else {}
        )
        retry_after = state.get("subscribed_retry_after")
        cooling = bool(retry_after and datetime.fromisoformat(retry_after) > utcnow())
        strategy = self.config.retrieval_strategy
        fallback = strategy == "auto" and cooling
        endpoint = self.activity_endpoint if strategy == "activity" or fallback else self.endpoint

        async def save_state():
            state["retrieval"] = (
                "activity fallback"
                if fallback
                else ("activity" if endpoint == self.activity_endpoint else "subscribed")
            )
            if hasattr(self, "write_retrieval_state"):
                await asyncio.to_thread(self.write_retrieval_state, dict(state))

        if fallback:
            logger.info(
                "provider=otx retrieval=activity_fallback reason=endpoint_cooldown "
                "subscribed_retry_after=%s",
                retry_after,
            )
        await save_state()
        records = 0
        pages = 0
        params = {"page": 1, "limit": self.page_size}
        if modified_since:
            params["modified_since"] = modified_since
        while pages < self.max_pages:
            try:
                body = await self.page_request(client, params, sync_mode, endpoint)
            except FeedError as error:
                if (
                    strategy != "auto"
                    or endpoint != self.endpoint
                    or error.code not in ("http_error_502", "http_error_503", "http_error_504")
                ):
                    raise
                fallback = True
                endpoint = self.activity_endpoint
                state["subscribed_retry_after"] = (
                    utcnow() + timedelta(minutes=self.config.endpoint_cooldown_minutes)
                ).isoformat()
                logger.warning(
                    "provider=otx retrieval=activity_fallback reason=%s subscribed_retry_after=%s",
                    error.code,
                    state["subscribed_retry_after"],
                )
                await save_state()
                params = {"page": 1, "limit": self.page_size}
                if modified_since:
                    params["modified_since"] = modified_since
                continue
            pages += 1
            payload = self.decode(body)
            if "next" not in payload:
                raise FeedError("invalid_response")
            records += sum(
                len(p.get("indicators", []))
                for p in payload["results"]
                if isinstance(p, dict) and isinstance(p.get("indicators"), list)
            )
            if records > self.limits.max_records:
                raise FeedError("too_many_records")
            logger.info(
                "provider=otx operation=%s sync_mode=%s page=%s page_size=%s response received",
                "activity_pulses" if endpoint == self.activity_endpoint else "subscribed_pulses",
                sync_mode,
                params["page"],
                params["limit"],
            )
            yield self.parse(body)
            if payload["next"] is None or payload["next"] == "":
                if endpoint == self.endpoint:
                    state.pop("subscribed_retry_after", None)
                    await save_state()
                return
            params = self.next_params(payload["next"], params["page"], modified_since, endpoint)
        raise FeedError("pagination_limit")

    @staticmethod
    def decode(body):
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                raise ValueError
            return payload
        except (ValueError, TypeError):
            raise FeedError("invalid_response") from None

    async def fetch(self, client):
        return await self.request(
            client,
            "GET",
            self.endpoint,
            headers={"X-OTX-API-KEY": self.key},
            params={"page": 1, "limit": 1},
            operation="validate_key",
            page=1,
        )

    def parse(self, body):
        feed = ParsedFeed()
        for pulse in redact_provider_data(self.decode(body)["results"], self.key):
            if not isinstance(pulse, dict) or not isinstance(pulse.get("indicators"), list):
                feed.rejected += 1
                continue
            for indicator in pulse["indicators"]:
                feed.fetched += 1
                if feed.fetched > self.limits.max_records:
                    raise FeedError("too_many_records")
                try:
                    kind = indicator["type"].lower()
                    value = indicator["indicator"]
                    if kind == "url":
                        value, kind = url_indicator(value)
                    elif kind not in ("domain", "hostname", "ipv4", "ipv6"):
                        feed.ignored += 1
                        continue
                    value, kind = normalize(value, kind)
                    created = indicator.get("created") or (
                        pulse.get("created") or pulse["modified"]
                    )
                    modified = pulse.get("modified") or created
                    tags = pulse.get("tags") or []
                    details = {
                        k: pulse[k]
                        for k in (
                            "id",
                            "name",
                            "description",
                            "author_name",
                            "author",
                            "TLP",
                            "attack_ids",
                            "industries",
                            "targeted_countries",
                            "groups",
                            "in_group",
                            "public",
                            "revision",
                            "is_subscribing",
                            "tags",
                            "created",
                            "modified",
                            "adversary",
                            "malware_families",
                            "references",
                        )
                        if k in pulse
                    }
                    details["indicator"] = {
                        k: indicator[k]
                        for k in (
                            "id",
                            "created",
                            "description",
                            "expiration",
                            "is_active",
                            "title",
                            "content",
                        )
                        if k in indicator
                    }
                    details["indicator_type"] = indicator["type"]
                    if "created" in indicator:
                        details["indicator_created"] = indicator["created"]
                    if indicator["type"].lower() == "url":
                        details["url"] = indicator["indicator"]
                    identity = (
                        str(pulse["id"])
                        + ":"
                        + str(
                            indicator.get("id")
                            or hashlib.sha256(indicator["indicator"].encode()).hexdigest()
                        )
                    )
                    feed.candidates.append(
                        Candidate(
                            value=value,
                            ioc_type=kind,
                            external_id=identity,
                            first_seen=created,
                            last_seen=modified,
                            tags=tags,
                            metadata=details,
                        )
                    )
                except (ValueError, TypeError, KeyError, AttributeError, ValidationError):
                    feed.rejected += 1
        return feed
