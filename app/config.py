import os
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.normalization import normalize_domain


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SchedulerConfig(StrictModel):
    enabled: bool = True
    update_on_start: bool = True
    update_interval_minutes: int = Field(default=60, ge=5, le=10080)


class SourcePolicy(StrictModel):
    enabled: bool = True
    min_confidence: int = Field(default=80, ge=0, le=100)
    allow_unknown_confidence: bool = False


class PolicyConfig(StrictModel):
    max_age_days: int = Field(default=7, ge=1, le=365)
    expiration_days: int = Field(default=7, ge=1, le=365)
    sources: dict[str, SourcePolicy] = Field(
        default_factory=lambda: {
            "urlhaus": SourcePolicy(allow_unknown_confidence=True),
            "threatfox": SourcePolicy(),
        }
    )


class AllowlistConfig(StrictModel):
    domains: list[str] = Field(default_factory=list, max_length=10000)

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, values):
        return sorted({normalize_domain(v) for v in values})


class ProviderConfig(StrictModel):
    enabled: bool = True


class ThreatFoxConfig(ProviderConfig):
    days: int = Field(default=7, ge=1, le=7)


class ProvidersConfig(StrictModel):
    urlhaus: ProviderConfig = Field(default_factory=ProviderConfig)
    threatfox: ThreatFoxConfig = Field(default_factory=ThreatFoxConfig)


class HTTPConfig(StrictModel):
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    total_timeout_seconds: int = Field(default=120, ge=1, le=600)
    max_response_bytes: int = Field(default=50 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)
    max_records: int = Field(default=200000, ge=1, le=1000000)


class LoggingConfig(StrictModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


class Settings(StrictModel):
    database_url: str = "sqlite:///./data/cerberus.db"
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)
    providers: ProvidersConfig = Field(default_factory=ProvidersConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    urlhaus_auth_key: SecretStr = Field(default=SecretStr(""), exclude=True)
    threatfox_auth_key: SecretStr = Field(default=SecretStr(""), exclude=True)


def load_settings() -> Settings:
    load_dotenv(override=False)
    path = Path(os.getenv("CERBERUS_CONFIG", "config.yaml"))
    if not path.exists():
        raise ValueError("configuration file not found")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("configuration must be a mapping")
    if {"urlhaus_auth_key", "threatfox_auth_key"} & raw.keys():
        raise ValueError("credentials must be supplied through environment variables")
    overrides = {
        "CERBERUS_UPDATE_INTERVAL_MINUTES": ("scheduler", "update_interval_minutes"),
        "CERBERUS_SCHEDULER_ENABLED": ("scheduler", "enabled"),
        "CERBERUS_UPDATE_ON_START": ("scheduler", "update_on_start"),
        "CERBERUS_LOG_LEVEL": ("logging", "level"),
    }
    for env, (section, key) in overrides.items():
        if env in os.environ:
            raw.setdefault(section, {})[key] = os.environ[env]
    if "CERBERUS_DATABASE_URL" in os.environ:
        raw["database_url"] = os.environ["CERBERUS_DATABASE_URL"]
    raw["urlhaus_auth_key"] = SecretStr(os.getenv("URLHAUS_AUTH_KEY", ""))
    raw["threatfox_auth_key"] = SecretStr(os.getenv("THREATFOX_AUTH_KEY", ""))
    return Settings.model_validate(raw)
