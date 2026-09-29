from dataclasses import dataclass
from datetime import datetime, timedelta

from app.config import Settings
from app.models import IOC, Observation
from app.normalization import safe_indicator


@dataclass(frozen=True)
class Decision:
    active: bool
    blocked: bool
    reasons: list[str]


class BlockingPolicy:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.allowlist = frozenset(settings.allowlist.domains)

    def allowlisted(self, value: str) -> bool:
        labels = value.split(".")
        return any(".".join(labels[n:]) in self.allowlist for n in range(len(labels)))

    def live(self, observation: Observation, now: datetime) -> bool:
        # Recompute the configured TTL as well, so shortening it takes effect after restart.
        expiry = min(
            observation.expires_at,
            observation.last_seen + timedelta(days=self.settings.policy.expiration_days),
        )
        return observation.active and expiry > now

    def evidence_reason(self, observation: Observation, now: datetime) -> str:
        if not self.live(observation, now):
            return "inactive_or_expired"
        if observation.last_seen <= now - timedelta(days=self.settings.policy.max_age_days):
            return "stale"
        rule = self.settings.policy.sources.get(observation.source)
        provider = getattr(self.settings.providers, observation.source, None)
        if not rule or not rule.enabled or not provider or not provider.enabled:
            return "source_not_enabled"
        if observation.confidence is None:
            return "eligible" if rule.allow_unknown_confidence else "unknown_confidence"
        return "eligible" if observation.confidence >= rule.min_confidence else "low_confidence"

    def evaluate(self, ioc: IOC, now: datetime) -> Decision:
        active = any(self.live(o, now) for o in ioc.observations)
        if not safe_indicator(ioc.normalized_value, ioc.ioc_type):
            return Decision(active, False, ["safety_exclusion"])
        if ioc.ioc_type not in ("domain", "hostname"):
            return Decision(active, False, ["ip_intelligence_only"])
        if self.allowlisted(ioc.normalized_value):
            return Decision(active, False, ["allowlisted"])
        reasons = {self.evidence_reason(o, now) for o in ioc.observations}
        eligible = "eligible" in reasons
        return Decision(
            active, eligible, ["eligible_source_evidence"] if eligible else sorted(reasons)
        )
