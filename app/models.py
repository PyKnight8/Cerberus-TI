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
