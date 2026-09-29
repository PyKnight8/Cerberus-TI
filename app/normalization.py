"""Pure normalization; never resolves DNS or follows an indicator URL."""

import ipaddress
import re
from urllib.parse import urlsplit

import idna

LOCAL_SUFFIXES = (
    "localhost",
    "local",
    "localdomain",
    "internal",
    "lan",
    "home",
    "home.arpa",
    "invalid",
    "test",
    "onion",
)


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if not value or len(value) > 1024 or any(c.isspace() for c in value):
        raise ValueError("invalid domain")
    if any(c in value for c in "/:@?#\\%"):
        raise ValueError("expected a domain, not a URL or IP")
    # A single root dot is valid; repeated root dots are malformed.
    if value.endswith("."):
        value = value[:-1]
    try:
        value = idna.encode(value, uts46=True, std3_rules=True).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError("invalid IDN") from exc
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
        raise ValueError("invalid hostname")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("invalid hostname label")
    return value


def normalize_ip(value: str) -> tuple[str, str]:
    if "%" in value:
        raise ValueError("scoped IPs are not supported")
    ip = ipaddress.ip_address(value.strip())
    return str(ip), "ipv4" if ip.version == 4 else "ipv6"


def normalize(value: str, kind: str) -> tuple[str, str]:
    if kind in ("domain", "hostname"):
        return normalize_domain(value), kind
    if kind in ("ip", "ipv4", "ipv6"):
        normalized, actual = normalize_ip(value)
        if kind != "ip" and actual != kind:
            raise ValueError("IP version mismatch")
        return normalized, actual
    raise ValueError("unsupported IOC type")


def url_indicator(value: str) -> tuple[str, str]:
    if len(value) > 8192 or any(c.isspace() for c in value) or "\\" in value:
        raise ValueError("invalid URL")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("invalid URL scheme or host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL credentials are not accepted")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ValueError("invalid port")
    try:
        return normalize_ip(parts.hostname)
    except ValueError:
        return normalize_domain(parts.hostname), "hostname"


def safe_indicator(value: str, kind: str) -> bool:
    try:
        normalized, actual = normalize(value, kind)
        if actual in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(normalized)
            return ip.is_global and not ip.is_multicast and not ip.is_reserved
        return not any(normalized == x or normalized.endswith("." + x) for x in LOCAL_SUFFIXES)
    except ValueError:
        return False
