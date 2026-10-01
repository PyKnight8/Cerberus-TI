from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, UTCDateTime


class IOC(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(8192))
    normalized_value: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    ioc_type: Mapped[str] = mapped_column(String(16), index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())
    observations: Mapped[list["Observation"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )
    __table_args__ = (CheckConstraint("ioc_type IN ('domain','hostname','ipv4','ipv6')"),)


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(128))
    reported_type: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    active: Mapped[bool] = mapped_column(Boolean)
    malware_family: Mapped[str | None] = mapped_column(String(256))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    ioc: Mapped[IOC] = relationship(back_populates="observations")
    __table_args__ = (
        UniqueConstraint("ioc_id", "source", "external_id"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 100)"),
        Index("ix_observation_policy", "active", "expires_at"),
    )


class ProviderState(Base):
    __tablename__ = "provider_states"
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_attempt: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_success: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_failure: Mapped[datetime | None] = mapped_column(UTCDateTime())
    next_allowed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_error: Mapped[str | None] = mapped_column(String(64))
    counts: Mapped[dict] = mapped_column(JSON, default=dict)


class ProviderCredential(Base):
    __tablename__ = "provider_credentials"
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(String(4096))


class ProviderUsage(Base):
    __tablename__ = "provider_usage"
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    successful_requests: Mapped[int] = mapped_column(Integer, default=0)
    failed_requests: Mapped[int] = mapped_column(Integer, default=0)
    rate_limited_requests: Mapped[int] = mapped_column(Integer, default=0)
    last_request_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_failure_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_http_status: Mapped[int | None] = mapped_column(Integer)


class ProviderKeyCheck(Base):
    __tablename__ = "provider_key_checks"
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime())
    status: Mapped[str] = mapped_column(String(32))


class ManagedAllowlist(Base):
    __tablename__ = "managed_allowlist"
    domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    note: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())


class AdminAccount(Base):
    __tablename__ = "admin_accounts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(512))


class OperationalEvent(Base):
    __tablename__ = "operational_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    level: Mapped[str] = mapped_column(String(16))
    component: Mapped[str] = mapped_column(String(32), index=True)
    message: Mapped[str] = mapped_column(String(256))


class RuntimeSetting(Base):
    __tablename__ = "runtime_settings"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer)


class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    result: Mapped[dict] = mapped_column(JSON)
    queried_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_error: Mapped[str | None] = mapped_column(String(64))
