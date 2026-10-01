import json
from datetime import UTC, datetime
from itertools import islice
from urllib.parse import quote

from app.feeds.base import FeedError, ThreatIntelProvider
from app.normalization import normalize

CATEGORIES = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "timeout",
    "failure",
    "type-unsupported",
    "confirmed-timeout",
)
FIELDS = (
    "reputation",
    "asn",
    "as_owner",
    "network",
    "country",
    "registrar",
    "whois",
    "total_votes",
)
DATES = (
    "last_analysis_date",
    "last_modification_date",
    "creation_date",
    "first_submission_date",
    "whois_date",
)


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    async def fetch(self, client):
        # A small known domain report tests authentication without submitting anything.
        return await self.lookup(client, "virustotal.com", "domain")

    async def lookup(self, client, value, kind):
        value, kind = normalize(value, kind)
        collection = "domains" if kind in ("domain", "hostname") else "ip_addresses"
        return await self.request(
            client,
            "GET",
            "https://www.virustotal.com/api/v3/" + collection + "/" + quote(value, safe=""),
            headers={"x-apikey": self.key},
        )

    def parse(self, body):
        try:
            attributes = json.loads(body)["data"]["attributes"]
            if not isinstance(attributes, dict):
                raise ValueError
            stats = attributes.get("last_analysis_stats", {})
            if not isinstance(stats, dict):
                raise ValueError
            counts = {
                k: v
                for k, v in stats.items()
                if k in CATEGORIES and type(v) is int and 0 <= v <= 100000
            }
            engines = attributes.get("last_analysis_results", {})
            if not isinstance(engines, dict):
                raise ValueError
            rows = []
            for name, verdict in islice(engines.items(), 200):
                if isinstance(verdict, dict):
                    rows.append(
                        {
                            "engine": str(name)[:128],
                            "category": str(verdict.get("category", "unknown"))[:64],
                            "result": str(verdict.get("result") or "—")[:256],
                        }
                    )
            rows.sort(key=lambda r: (r["category"] not in ("malicious", "suspicious"), r["engine"]))
            context = {}
            for key in FIELDS:
                value = attributes.get(key)
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    context[key] = str(value)[: 4096 if key == "whois" else 256]
                elif key == "total_votes" and isinstance(value, dict):
                    for vote in ("harmless", "malicious"):
                        if type(value.get(vote)) is int:
                            context["community_" + vote] = value[vote]
            for key in DATES:
                value = attributes.get(key)
                if type(value) is int:
                    try:
                        context[key] = datetime.fromtimestamp(value, UTC).isoformat()
                    except (ValueError, OverflowError, OSError):
                        pass
            return {
                "stats": counts,
                "total": sum(counts.values()),
                "flagged": counts.get("malicious", 0) + counts.get("suspicious", 0),
                "engines": rows,
                "context": context,
            }
        except (ValueError, TypeError, KeyError):
            raise FeedError("invalid_response") from None
