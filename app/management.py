"""Small, single-process management services. Secrets never leave this boundary."""

import os
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
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


def load_runtime_settings(db, settings):
    with db.session() as session:
        values = {r.name: r.value["value"] for r in session.scalars(select(RuntimeSetting))}
    for name in PROVIDERS:
        key = f"provider.{name}.enabled"
        if key in values:
            getattr(settings.providers, name).enabled = bool(values[key])
    if "enrichment.cache_ttl_hours" in values:
        settings.enrichment.cache_ttl_hours = int(values["enrichment.cache_ttl_hours"])
    if "scheduler.enabled" in values:
        settings.scheduler.enabled = bool(values["scheduler.enabled"])
    if "scheduler.interval" in values:
        settings.scheduler.update_interval_minutes = int(values["scheduler.interval"])


def save_runtime_setting(db, name, value):
    with db.session.begin() as session:
        row = session.get(RuntimeSetting, name)
        if row is None:
            row = RuntimeSetting(name=name)
            session.add(row)
        row.value = {"value": value}


def new_session():
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32), utcnow() + timedelta(hours=8)
