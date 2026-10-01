import asyncio
from datetime import timedelta

import httpx

from app.feeds.base import FeedError, redact_provider_data, utcnow
from app.feeds.registry import make_provider
from app.management import get_key, record_event
from app.models import IOCEnrichment, RuntimeSetting


class EnrichmentService:
    def __init__(self, state):
        self.state = state
        self.lock = asyncio.Lock()

    def cached(self, ioc_id):
        with self.state.db.session() as session:
            return session.get(IOCEnrichment, (ioc_id, "virustotal"))

    async def query(self, ioc, refresh=False):
        async with self.lock:
            cached = self.cached(ioc.id)
            if cached and cached.expires_at > utcnow() and not refresh:
                return "Cached VirusTotal enrichment"
            with self.state.db.session() as session:
                limit = session.get(RuntimeSetting, "enrichment.virustotal.next_allowed_at")
                next_allowed = limit.value["value"] if limit else None
            if next_allowed and next_allowed > utcnow().isoformat():
                return "VirusTotal rate limit reached. Try again later."
            key = get_key(self.state.db, self.state.settings, "virustotal", self.state.crypto)
            if not key:
                return "VirusTotal enrichment is not configured."
            provider = make_provider("virustotal", key, self.state.settings)
            provider.account_request = self.state.updates.account_request
            try:
                async with httpx.AsyncClient(
                    timeout=self.state.settings.http.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    headers={"Accept-Encoding": "identity"},
                    transport=self.state.updates.transport,
                ) as client:
                    result = provider.parse(
                        await provider.lookup(client, ioc.normalized_value, ioc.ioc_type)
                    )
                # Prevent credentials echoed by a malicious response from being persisted/rendered.
                result = redact_provider_data(result, key)
                now = utcnow()
                with self.state.db.session.begin() as session:
                    row = session.get(IOCEnrichment, (ioc.id, "virustotal"))
                    if row is None:
                        row = IOCEnrichment(ioc_id=ioc.id, provider="virustotal")
                        session.add(row)
                    row.result = result
                    row.queried_at = now
                    row.expires_at = now + timedelta(
                        hours=self.state.settings.enrichment.cache_ttl_hours
                    )
                    row.last_error = None
                record_event(self.state.db, "virustotal", "INFO", "Enrichment queried")
                return "Live / freshly queried VirusTotal enrichment"
            except (FeedError, ValueError) as error:
                exc = error if isinstance(error, FeedError) else FeedError("invalid_indicator")
                if exc.code == "rate_limited":
                    from app.management import save_runtime_setting

                    save_runtime_setting(
                        self.state.db,
                        "enrichment.virustotal.next_allowed_at",
                        (utcnow() + timedelta(seconds=exc.retry_seconds)).isoformat(),
                    )
                record_event(self.state.db, "virustotal", "WARNING", "Enrichment query " + exc.code)
                if cached:
                    with self.state.db.session.begin() as session:
                        row = session.get(IOCEnrichment, (ioc.id, "virustotal"))
                        row.last_error = exc.code
                message = (
                    "VirusTotal rate limit reached. Try again later."
                    if exc.code == "rate_limited"
                    else "VirusTotal query failed. Try again later."
                )
                return message + (" Previous cached result retained." if cached else "")
