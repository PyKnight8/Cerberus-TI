"""Small, single-process management services. Secrets never leave this boundary."""

import logging
import os
import secrets
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from pydantic import ValidationError
from sqlalchemy import select

from app.feeds.base import utcnow
from app.models import (
    AdminAccount,
    ManagedAllowlist,
    OperationalEvent,
    ProviderCredential,
    RuntimeSetting,
)

PASSWORDS = PasswordHasher()
PROVIDERS = ("urlhaus", "threatfox", "otx")
INTEGRATIONS = {
    **dict.fromkeys(PROVIDERS, "Automated threat intelligence"),
    "virustotal": "On-demand enrichment",
}


def cipher():
    value = os.getenv("CERBERUS_SECRET_KEY", "")
    if not value:
        return None
    try:
        return Fernet(value.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("CERBERUS_SECRET_KEY must be a Fernet key") from exc


def get_key(db, settings, source, crypto):
    with db.session() as session:
        row = session.get(ProviderCredential, source)
        if row:
            if crypto is None:
                raise RuntimeError(
                    "CERBERUS_SECRET_KEY is required to decrypt stored provider keys"
                )
            try:
                return crypto.decrypt(row.ciphertext.encode()).decode()
            except InvalidToken as exc:
                raise RuntimeError(
                    "Cannot decrypt provider key; check CERBERUS_SECRET_KEY"
                ) from exc
    return getattr(settings, f"{source}_auth_key").get_secret_value()


def mask(value):
    if not value:
        return ""
    return "••••••••••••" + (value[-4:] if len(value) > 4 else "")


def set_key(db, source, value, crypto):
    if source not in INTEGRATIONS or not value or len(value) > 2048:
        raise ValueError("invalid provider key")
    if crypto is None:
        raise RuntimeError("CERBERUS_SECRET_KEY is required to save provider keys")
    with db.session.begin() as session:
        row = session.get(ProviderCredential, source)
        if row is None:
            row = ProviderCredential(source=source)
            session.add(row)
        row.ciphertext = crypto.encrypt(value.encode()).decode()
        if source == "otx":
            for setting_name in ("otx.modified_since", "otx.retrieval_state"):
                checkpoint = session.get(RuntimeSetting, setting_name)
                if checkpoint:
                    session.delete(checkpoint)


def verify_password(db, password):
    with db.session() as session:
        account = session.get(AdminAccount, 1)
        if account is None:
            return False
        try:
            return PASSWORDS.verify(account.password_hash, password)
        except (VerifyMismatchError, ValueError):
            return False


def set_password(db, password):
    if len(password) < 12:
        raise ValueError("administrator password must contain at least 12 characters")
    with db.session.begin() as session:
        account = session.get(AdminAccount, 1)
        if account is None:
            account = AdminAccount(id=1)
            session.add(account)
        account.password_hash = PASSWORDS.hash(password)


def record_event(db, component, level, message):
    # Only caller-owned fixed messages belong here; never copy HTTP exceptions or bodies.
    with db.session.begin() as session:
        session.add(
            OperationalEvent(created_at=utcnow(), component=component, level=level, message=message)
        )
        cutoff = session.scalar(
            select(OperationalEvent.id).order_by(OperationalEvent.id.desc()).offset(999).limit(1)
        )
        if cutoff is not None:
            session.query(OperationalEvent).filter(OperationalEvent.id < cutoff).delete(
                synchronize_session=False
            )


def sync_allowlist(db, policy):
    with db.session() as session:
        managed = set(session.scalars(select(ManagedAllowlist.domain)))
    policy.allowlist = frozenset(set(policy.settings.allowlist.domains) | managed)


def runtime_setting_value(row, default=None):
    """Read the canonical envelope and the historical OTX state dictionary."""
    if row is None:
        return default
    if isinstance(row.value, dict) and "value" in row.value:
        return row.value["value"]
    return row.value


def load_runtime_settings(db, settings):
    """Normalize recognized persisted settings transactionally before consumers start.

    Earlier releases wrote OTX retrieval state as a bare dictionary. Scalar JSON
    values are also accepted for known settings; unknown rows are left untouched.
    Validation is per setting so one damaged override cannot discard other values.
    """
    targets = {
        **{
            f"provider.{name}.enabled": (getattr(settings.providers, name), "enabled")
            for name in PROVIDERS
        },
        "enrichment.cache_ttl_hours": (settings.enrichment, "cache_ttl_hours"),
        "scheduler.enabled": (settings.scheduler, "enabled"),
        "scheduler.interval": (settings.scheduler, "update_interval_minutes"),
        **{
            f"policy.otx.{field}": (settings.policy.otx, field)
            for field in type(settings.policy.otx).model_fields
        },
    }
    timestamps = {"otx.modified_since", "enrichment.virustotal.next_allowed_at"}
    with db.session.begin() as session:
        for row in session.scalars(select(RuntimeSetting)):
            if (
                row.name not in targets
                and row.name not in timestamps
                and row.name != "otx.retrieval_state"
            ):
                continue
            value = runtime_setting_value(row)
            target = targets.get(row.name)
            fallback = (
                getattr(target[0], target[1])
                if target
                else ({} if row.name == "otx.retrieval_state" else None)
            )
            try:
                if target:
                    model, field = target
                    # Pydantic handles bool strings correctly and enforces configured bounds.
                    if isinstance(value, bool) and not isinstance(fallback, bool):
                        raise ValueError("boolean is not an integer setting")
                    validated = type(model).model_validate({**model.model_dump(), field: value})
                    value = getattr(validated, field)
                elif row.name in timestamps:
                    if value is not None:
                        if not isinstance(value, str):
                            raise ValueError("timestamp must be a string")
                        if datetime.fromisoformat(value).tzinfo is None:
                            raise ValueError("timestamp must have a timezone")
                elif not isinstance(value, dict):
                    raise ValueError("retrieval state must be a dictionary")
                else:
                    if "retrieval" in value and value["retrieval"] not in (
                        "subscribed",
                        "activity",
                        "activity fallback",
                    ):
                        raise ValueError("invalid retrieval mode")
                    if "subscribed_retry_after" in value:
                        retry = value["subscribed_retry_after"]
                        if (
                            not isinstance(retry, str)
                            or datetime.fromisoformat(retry).tzinfo is None
                        ):
                            raise ValueError("invalid retry timestamp")
            except (ValidationError, ValueError, TypeError):
                logging.getLogger(__name__).warning(
                    "Invalid runtime setting %s; using configured/default value", row.name
                )
                value = fallback
            canonical = {"value": value}
            if row.value != canonical:
                row.value = canonical
            if target:
                setattr(target[0], target[1], value)


def save_runtime_setting(db, name, value):
    with db.session.begin() as session:
        row = session.get(RuntimeSetting, name)
        if row is None:
            row = RuntimeSetting(name=name)
            session.add(row)
        row.value = {"value": value}


def new_session():
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32), utcnow() + timedelta(hours=8)
