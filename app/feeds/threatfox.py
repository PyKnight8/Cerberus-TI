import json

import httpx

from app.feeds.base import Candidate, FeedError, ParsedFeed, ThreatIntelProvider
from app.normalization import normalize_ip, url_indicator


class ThreatFoxProvider(ThreatIntelProvider):
    name = "threatfox"

    def __init__(self, key, limits, days=7):
        super().__init__(key, limits)
        self.days = days

    async def fetch(self, client: httpx.AsyncClient) -> bytes:
        return await self.request(
            client,
            "POST",
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": self.key},
            json={"query": "get_iocs", "days": self.days},
        )

    def parse(self, body: bytes) -> ParsedFeed:
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError, RecursionError):
            raise FeedError("invalid_response") from None
        if not isinstance(data, dict):
            raise FeedError("invalid_response")
        if data.get("query_status") == "no_result":
            return ParsedFeed()
        if data.get("query_status") != "ok" or not isinstance(data.get("data"), list):
            raise FeedError("invalid_api_status")
        rows = data["data"]
        if len(rows) > self.limits.max_records:
            raise FeedError("too_many_records")
        result = ParsedFeed(fetched=len(rows))
        for row in rows:
            try:
                if not isinstance(row, dict):
                    raise ValueError("invalid record")
                kind, value = row["ioc_type"], row["ioc"]
                metadata = {k: row.get(k) for k in ("threat_type", "reporter", "reference")}
                if kind == "url":
                    metadata["url"] = value
                    value, kind = url_indicator(value)
                elif kind == "ip:port":
                    address, separator, port = value.rpartition(":")
                    if (
                        not separator
                        or not port.isascii()
                        or not port.isdigit()
                        or not 1 <= int(port) <= 65535
                    ):
                        raise ValueError("invalid port")
                    value, kind = normalize_ip(address.removeprefix("[").removesuffix("]"))
                    metadata["port"] = int(port)
                elif kind not in ("domain", "hostname", "ipv4", "ipv6", "ip"):
                    result.ignored += 1
                    continue
                result.candidates.append(
                    Candidate(
                        value=value,
                        ioc_type=kind,
                        external_id=str(row["id"]),
                        confidence=row.get("confidence_level"),
                        first_seen=row["first_seen"],
                        last_seen=row.get("last_seen") or row["first_seen"],
                        malware_family=row.get("malware"),
                        tags=row.get("tags") or [],
                        metadata=metadata,
                    )
                )
            except (ValueError, TypeError, KeyError, AttributeError):
                result.rejected += 1
        if result.rejected and not result.candidates and not result.ignored:
            raise FeedError("invalid_records")
        return result
