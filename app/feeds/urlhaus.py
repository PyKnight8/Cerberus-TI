import csv
import io
from urllib.parse import quote

import httpx

from app.feeds.base import Candidate, FeedError, ParsedFeed, ThreatIntelProvider
from app.normalization import url_indicator


class URLhausProvider(ThreatIntelProvider):
    name = "urlhaus"

    async def fetch(self, client: httpx.AsyncClient) -> bytes:
        # Official v2 community export requires the credential in the path.
        # HTTP client logging is disabled by the app; never log this URL.
        url = (
            "https://urlhaus-api.abuse.ch/v2/files/exports/"
            + quote(self.key, safe="")
            + "/recent.csv"
        )
        return await self.request(client, "GET", url)

    def parse(self, body: bytes) -> ParsedFeed:
        result = ParsedFeed()
        try:
            text = body.decode("utf-8-sig")
            if text.lstrip().startswith(("<", "{")):
                raise FeedError("invalid_response")
            reader = csv.reader(io.StringIO(text), strict=True)
            for row in reader:
                if not row or row[0].lstrip().startswith("#"):
                    continue
                result.fetched += 1
                if result.fetched > self.limits.max_records:
                    raise FeedError("too_many_records")
                try:
                    if len(row) != 9 or row[3] not in ("online", "offline"):
                        raise ValueError("unexpected CSV record")
                    identifier, added, url, status, last_online, threat, tags, _, reporter = row
                    value, kind = url_indicator(url)
                    seen = last_online if last_online and last_online != "None" else added
                    result.candidates.append(
                        Candidate(
                            value=value,
                            ioc_type=kind,
                            external_id=identifier,
                            first_seen=added,
                            last_seen=seen,
                            active=status == "online",
                            tags=[] if tags in ("", "None") else tags.split(","),
                            metadata={
                                "url": url,
                                "url_status": status,
                                "threat": threat,
                                "reporter": reporter,
                            },
                        )
                    )
                except (ValueError, TypeError):
                    result.rejected += 1
        except (UnicodeError, csv.Error):
            raise FeedError("invalid_response") from None
        if not result.candidates:
            # Do not mark an HTML login page, format change, or empty body successful.
            raise FeedError("empty_or_invalid_export")
        return result
