from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class GeoIPLookupResult:
    available: bool
    source: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    timezone: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    isp: str | None = None
    organization: str | None = None
    anonymous_ip_flags: list[str] = field(default_factory=list)
    is_proxy_or_hosting_guess: bool | None = None
    confidence_note: str | None = None
    notes: list[str] = field(default_factory=list)


class GeoIPProvider(Protocol):
    source_name: str

    def is_configured(self) -> bool: ...

    def lookup(self, ip_address: str) -> GeoIPLookupResult: ...


class DisabledGeoIPProvider:
    source_name = "disabled"

    def is_configured(self) -> bool:
        return False

    def lookup(self, ip_address: str) -> GeoIPLookupResult:
        return GeoIPLookupResult(
            available=False,
            source=self.source_name,
            notes=["O provider GeoIP nao esta configurado neste ambiente."],
            confidence_note=(
                "Sem base MaxMind local ou credenciais de web service, a geolocalizacao ficou indisponivel."
            ),
        )
