import asyncio
import json
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator, model_validator

from app.config import HTTPConfig


def utcnow() -> datetime:
    return datetime.now(UTC)


class FeedError(Exception):
    """Only fixed, safe error codes may cross the feed boundary."""

    def __init__(self, code: str, retry_seconds: int = 300):
        super().__init__(code)
        self.code = code
        self.retry_seconds = retry_seconds


class Candidate(BaseModel):
    value: str = Field(min_length=1, max_length=8192)
    ioc_type: str
    external_id: str = Field(min_length=1, max_length=128)
    confidence: int | None = Field(default=None, ge=0, le=100, strict=True)
    first_seen: datetime
    last_seen: datetime
    active: bool = True
    malware_family: str | None = Field(default=None, max_length=256)
    tags: list[str] = Field(default_factory=list, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen", mode="before")
    @classmethod
    def timestamp(cls, value):
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace(" UTC", "+00:00").replace("Z", "+00:00"))
        if not isinstance(value, datetime):
            raise ValueError("invalid timestamp")
        # Both documented feeds use UTC, with URLhaus omitting the suffix.
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def bounded(self):
        if self.first_seen > self.last_seen or self.last_seen > utcnow() + timedelta(minutes=5):
            raise ValueError("invalid timestamp order")
        if any(len(t) > 128 for t in self.tags):
            raise ValueError("oversized tag")
        if len(json.dumps(self.metadata)) > 16384:
            raise ValueError("oversized metadata")
        return self


class ParsedFeed(BaseModel):
    candidates: list[Candidate] = Field(default_factory=list)
    fetched: int = 0
    rejected: int = 0
    ignored: int = 0


class ThreatIntelProvider(ABC):
    name: str

    def __init__(self, key: str, limits: HTTPConfig):
        self.key = key
        self.limits = limits

    async def request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> bytes:
        if not self.key:
            raise FeedError("missing_api_key")
        try:
            async with asyncio.timeout(self.limits.total_timeout_seconds):
                async with client.stream(method, url, **kwargs) as response:
                    if response.status_code == 429:
                        delay = 300
                        retry = response.headers.get("Retry-After", "")
                        try:
                            delay = int(retry)
                        except ValueError:
                            try:
                                delay = int(
                                    (parsedate_to_datetime(retry) - utcnow()).total_seconds()
                                )
                            except (ValueError, TypeError, OverflowError):
                                pass
                        raise FeedError("rate_limited", max(300, min(delay, 604800)))
                    if response.status_code != 200:
                        raise FeedError("http_error_" + str(response.status_code))
                    # Prevent decompression bombs: request identity and reject encodings anyway.
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise FeedError("unsupported_encoding")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > self.limits.max_response_bytes:
                            raise FeedError("response_too_large")
                        body.extend(chunk)
                    return bytes(body)
        except (httpx.TimeoutException, TimeoutError):
            raise FeedError("timeout") from None
        except httpx.HTTPError:
            raise FeedError("network_error") from None

    @abstractmethod
    async def fetch(self, client: httpx.AsyncClient) -> bytes:
        pass

    @abstractmethod
    def parse(self, body: bytes) -> ParsedFeed:
        pass
