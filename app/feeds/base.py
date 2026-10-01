import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator, model_validator

from app.config import HTTPConfig, ProviderTimeouts

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(UTC)


def redact_provider_data(value, key):
    """Remove a credential echoed anywhere in untrusted provider text."""
    if isinstance(value, str):
        return value.replace(key, "[redacted]") if key else value
    if isinstance(value, list):
        return [redact_provider_data(item, key) for item in value]
    if isinstance(value, dict):
        return {
            redact_provider_data(k, key): redact_provider_data(v, key) for k, v in value.items()
        }
    return value


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
        self.account_request = None
        self.timeouts = ProviderTimeouts()

    def http_timeout(self):
        values = {
            name: getattr(self.timeouts, name + "_timeout_seconds") or self.limits.timeout_seconds
            for name in ("connect", "read", "write", "pool")
        }
        return httpx.Timeout(**values)

    @property
    def total_timeout(self):
        return self.timeouts.total_timeout_seconds or self.limits.total_timeout_seconds

    async def request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        operation: str = "fetch",
        page: int | None = None,
        **kwargs,
    ) -> bytes:
        if not self.key:
            raise FeedError("missing_api_key")
        started = time.monotonic()
        status = None
        succeeded = False
        try:
            async with asyncio.timeout(self.total_timeout):
                async with client.stream(
                    method, url, timeout=self.http_timeout(), **kwargs
                ) as response:
                    status = response.status_code
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
                    result = bytes(body)
                    succeeded = True
                    return result
        except (httpx.TimeoutException, TimeoutError) as exc:
            category = next(
                (
                    name
                    for cls, name in (
                        (httpx.ConnectTimeout, "connect"),
                        (httpx.ReadTimeout, "read"),
                        (httpx.WriteTimeout, "write"),
                        (httpx.PoolTimeout, "pool"),
                        (TimeoutError, "total"),
                    )
                    if isinstance(exc, cls)
                ),
                "unknown",
            )
            elapsed = round(time.monotonic() - started, 3)
            logger.warning(
                "provider=%s operation=%s page=%s timeout_category=%s elapsed_seconds=%.3f",
                self.name,
                operation,
                page,
                category,
                elapsed,
            )
            error = FeedError("timeout")
            error.diagnostics = {
                "operation": operation,
                "page": page,
                "timeout_category": category,
                "elapsed_seconds": elapsed,
            }
            raise error from None
        except FeedError as error:
            error.diagnostics = {
                "operation": operation,
                "page": page,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            logger.warning(
                "provider=%s operation=%s page=%s error=%s elapsed_seconds=%.3f",
                self.name,
                operation,
                page,
                error.code,
                error.diagnostics["elapsed_seconds"],
            )
            raise
        except httpx.HTTPError:
            error = FeedError("network_error")
            error.diagnostics = {
                "operation": operation,
                "page": page,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            logger.warning(
                "provider=%s operation=%s page=%s error=network_error elapsed_seconds=%.3f",
                self.name,
                operation,
                page,
                error.diagnostics["elapsed_seconds"],
            )
            raise error from None
        finally:
            if self.account_request:
                await asyncio.to_thread(self.account_request, self.name, succeeded, status)

    @abstractmethod
    async def fetch(self, client: httpx.AsyncClient) -> bytes:
        pass

    @abstractmethod
    def parse(self, body: bytes) -> ParsedFeed:
        pass
