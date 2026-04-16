from dataclasses import dataclass
from datetime import UTC, datetime
import math
import ssl
from typing import Any


@dataclass(frozen=True)
class TLSProbeData:
    tls_available: bool
    certificate_valid: bool | None
    certificate: dict[str, Any] | None
    tls_version: str | None
    error: str | None = None
    hostname_match: bool | None = None


def format_name(name_entries: tuple[tuple[tuple[str, str], ...], ...] | list | None) -> str | None:
    if not name_entries:
        return None

    parts: list[str] = []
    for entry in name_entries:
        for key, value in entry:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def extract_san(certificate: dict[str, Any] | None) -> list[str]:
    if not certificate:
        return []
    return [
        value
        for key, value in certificate.get("subjectAltName", [])
        if key == "DNS"
    ]


def parse_certificate_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        timestamp = ssl.cert_time_to_seconds(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC)


def calculate_days_to_expire(not_after: datetime | None) -> int | None:
    if not_after is None:
        return None
    delta = not_after - datetime.now(tz=UTC)
    return math.floor(delta.total_seconds() / 86400)


def certificate_expiry_label(days_to_expire: int | None) -> str:
    if days_to_expire is None:
        return "desconhecido"
    if days_to_expire < 0:
        return "expirado"
    if days_to_expire <= 30:
        return "proximo_expiracao"
    return "ok"


def guess_certificate_provider(
    issuer: str | None,
    subject: str | None,
    san: list[str],
) -> tuple[str | None, str]:
    combined = " ".join(part for part in [issuer, subject, *san] if part).lower()
    rules = [
        ("cloudflare", "Cloudflare", "alta"),
        ("cloudflaressl.com", "Cloudflare", "alta"),
        ("let's encrypt", "Let's Encrypt", "media"),
        ("google trust services", "Google Trust Services", "media"),
        ("gts", "Google Trust Services", "baixa"),
        ("digicert", "DigiCert", "media"),
        ("sectigo", "Sectigo", "media"),
        ("comodoca", "Sectigo", "media"),
        ("zerossl", "ZeroSSL", "media"),
        ("cloudfront.net", "Amazon CloudFront", "media"),
        ("amazon", "Amazon", "baixa"),
    ]
    for needle, label, confidence in rules:
        if needle in combined:
            return label, confidence
    return None, "baixa"
