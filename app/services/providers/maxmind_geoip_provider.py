from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.providers.geoip_provider import GeoIPLookupResult


@dataclass
class _ReaderBundle:
    city: Any | None = None
    asn: Any | None = None
    isp: Any | None = None
    anonymous: Any | None = None


class MaxMindGeoIPProvider:
    """Enriches IPs through MaxMind databases or, when configured, the web service."""

    source_name = "maxmind"

    def __init__(
        self,
        *,
        city_db_path: str | None = None,
        asn_db_path: str | None = None,
        isp_db_path: str | None = None,
        anonymous_db_path: str | None = None,
        account_id: str | None = None,
        license_key: str | None = None,
        host: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.city_db_path = city_db_path
        self.asn_db_path = asn_db_path
        self.isp_db_path = isp_db_path
        self.anonymous_db_path = anonymous_db_path
        self.account_id = account_id
        self.license_key = license_key
        self.host = host
        self.timeout_seconds = timeout_seconds or settings.geoip_timeout_seconds
        self._reader_bundle: _ReaderBundle | None = None

    def is_configured(self) -> bool:
        return any(
            [
                self.city_db_path,
                self.asn_db_path,
                self.isp_db_path,
                self.anonymous_db_path,
                self.account_id and self.license_key,
            ]
        )

    def lookup(self, ip_address: str) -> GeoIPLookupResult:
        if not self.is_configured():
            return GeoIPLookupResult(
                available=False,
                source=self.source_name,
                notes=["MaxMind nao esta configurado para enriquecer o IP observado."],
                confidence_note="Geolocalizacao de IP ficou indisponivel neste ambiente.",
            )

        notes: list[str] = [
            "Geolocalizacao de IP e aproximada e pode refletir borda, CDN, proxy ou provedor intermediario."
        ]
        payload = GeoIPLookupResult(
            available=False,
            source=self.source_name,
            notes=[],
        )

        try:
            city_response = self._lookup_city(ip_address)
            asn_response = self._lookup_asn(ip_address)
            isp_response = self._lookup_isp(ip_address)
            anonymous_response = self._lookup_anonymous(ip_address)
        except Exception as exc:  # pragma: no cover - optional dependency/runtime path
            return GeoIPLookupResult(
                available=False,
                source=self.source_name,
                notes=["A consulta MaxMind falhou e a analise seguiu sem enriquecimento geografico."],
                confidence_note=str(exc),
            )

        source_parts: list[str] = []
        if city_response is not None:
            source_parts.append("city")
        if asn_response is not None:
            source_parts.append("asn")
        if isp_response is not None:
            source_parts.append("isp")
        if anonymous_response is not None:
            source_parts.append("anonymous")

        anonymous_flags = self._anonymous_flags(anonymous_response)
        if anonymous_flags:
            notes.append(
                "Flags de anonimidade ou hospedagem vieram de base MaxMind e indicam contexto de rede, nao atribuicao definitiva."
            )

        organization = self._pick_first(
            self._safe_get(isp_response, "organization"),
            self._safe_get(city_response, "traits.organization"),
        )

        confidence_note = (
            "Dados MaxMind podem retornar campos ausentes e nao identificam um endereco fisico exato."
        )
        if city_response is None:
            notes.append("Nenhuma base City ou web service MaxMind respondeu com localizacao para este IP.")

        country_name = self._safe_get(city_response, "country.name")
        country_code = self._safe_get(city_response, "country.iso_code")
        usage_type = self._derive_usage_type(
            isp=self._safe_get(isp_response, "isp"),
            organization=organization,
            anonymous_flags=anonymous_flags,
        )

        return GeoIPLookupResult(
            available=city_response is not None or asn_response is not None or isp_response is not None,
            source=f"{self.source_name}:{'+'.join(source_parts)}" if source_parts else self.source_name,
            country=country_name or country_code,
            country_name=country_name,
            country_code=country_code,
            region=self._safe_get(city_response, "subdivisions.most_specific.name"),
            city=self._safe_get(city_response, "city.name"),
            timezone=self._safe_get(city_response, "location.time_zone"),
            asn=self._stringify_asn(self._safe_get(asn_response, "autonomous_system_number")),
            asn_org=self._safe_get(asn_response, "autonomous_system_organization"),
            isp=self._safe_get(isp_response, "isp"),
            organization=organization,
            usage_type=usage_type,
            anonymous_ip_flags=anonymous_flags,
            is_proxy_or_hosting_guess=True if anonymous_flags else None,
            confidence_note=confidence_note,
            notes=notes,
        )

    def _lookup_city(self, ip_address: str):
        readers = self._ensure_readers()
        if readers.city is not None:
            return self._safe_reader_call(readers.city, "city", ip_address)
        if self.account_id and self.license_key:
            return self._safe_webservice_call(ip_address)
        return None

    def _lookup_asn(self, ip_address: str):
        readers = self._ensure_readers()
        if readers.asn is None:
            return None
        return self._safe_reader_call(readers.asn, "asn", ip_address)

    def _lookup_isp(self, ip_address: str):
        readers = self._ensure_readers()
        if readers.isp is None:
            return None
        return self._safe_reader_call(readers.isp, "isp", ip_address)

    def _lookup_anonymous(self, ip_address: str):
        readers = self._ensure_readers()
        if readers.anonymous is None:
            return None
        return self._safe_reader_call(readers.anonymous, "anonymous_ip", ip_address)

    def _ensure_readers(self) -> _ReaderBundle:
        if self._reader_bundle is not None:
            return self._reader_bundle

        try:
            geoip2_database = import_module("geoip2.database")
        except Exception:  # pragma: no cover - optional dependency/runtime path
            self._reader_bundle = _ReaderBundle()
            return self._reader_bundle

        self._reader_bundle = _ReaderBundle(
            city=self._open_reader(geoip2_database, self.city_db_path),
            asn=self._open_reader(geoip2_database, self.asn_db_path),
            isp=self._open_reader(geoip2_database, self.isp_db_path),
            anonymous=self._open_reader(geoip2_database, self.anonymous_db_path),
        )
        return self._reader_bundle

    @staticmethod
    def _open_reader(module: Any, path_value: str | None):
        if not path_value:
            return None
        path = Path(path_value)
        if not path.is_file():
            return None
        return module.Reader(str(path))

    def _safe_webservice_call(self, ip_address: str):
        try:
            geoip2_webservice = import_module("geoip2.webservice")
        except Exception:  # pragma: no cover - optional dependency/runtime path
            return None

        kwargs = {}
        if self.host:
            kwargs["host"] = self.host

        try:
            with geoip2_webservice.Client(int(self.account_id), self.license_key, **kwargs) as client:
                return client.city(ip_address)
        except Exception:  # pragma: no cover - optional dependency/runtime path
            return None

    @staticmethod
    def _safe_reader_call(reader: Any, method_name: str, ip_address: str):
        try:
            method = getattr(reader, method_name)
            return method(ip_address)
        except Exception:  # pragma: no cover - optional dependency/runtime path
            return None

    @staticmethod
    def _safe_get(obj: Any, path: str) -> str | None:
        current = obj
        for part in path.split("."):
            if current is None:
                return None
            current = getattr(current, part, None)
        if current is None:
            return None
        cleaned = str(current).strip()
        return cleaned or None

    @staticmethod
    def _pick_first(*values: str | None) -> str | None:
        for value in values:
            if value:
                return value
        return None

    @staticmethod
    def _anonymous_flags(response: Any) -> list[str]:
        if response is None:
            return []
        mapping = {
            "is_anonymous": "anonymous",
            "is_anonymous_vpn": "anonymous_vpn",
            "is_hosting_provider": "hosting_provider",
            "is_public_proxy": "public_proxy",
            "is_residential_proxy": "residential_proxy",
            "is_tor_exit_node": "tor_exit_node",
        }
        flags: list[str] = []
        for attribute, label in mapping.items():
            if getattr(response, attribute, False):
                flags.append(label)
        return flags

    @staticmethod
    def _stringify_asn(value: str | None) -> str | None:
        if not value:
            return None
        return value if value.startswith("AS") else f"AS{value}"

    @staticmethod
    def _derive_usage_type(
        *,
        isp: str | None,
        organization: str | None,
        anonymous_flags: list[str],
    ) -> str | None:
        if "hosting_provider" in anonymous_flags:
            return "hosting"

        combined = " ".join(part.lower() for part in (isp, organization) if part)
        if not combined:
            return None

        if any(token in combined for token in ("cloud", "hosting", "cdn", "datacenter", "data center")):
            return "hosting"
        if any(token in combined for token in ("residential", "broadband", "fiber", "cable", "wireless", "mobile")):
            return "residential"
        if any(token in combined for token in ("business", "enterprise", "corporate")):
            return "business"
        return None
