from datetime import datetime
from typing import Any

from pydantic import BaseModel


class SourceOut(BaseModel):
    name: str
    external_id: str
    reported_type: str
    confidence: int | None
    first_seen: datetime
    last_seen: datetime
    fetched_at: datetime
    expires_at: datetime
    active: bool
    policy_reason: str
    malware_family: str | None
    tags: list[str]
    metadata: dict[str, Any]


class IOCOut(BaseModel):
    id: int
    ioc: str
    value: str
    type: str
    active: bool
    blocked: bool
    policy_reasons: list[str]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None
    sources: list[SourceOut]


class IOCPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IOCOut]


class UpdateOut(BaseModel):
    status: str
    status_url: str = "/api/stats"
