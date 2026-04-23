from __future__ import annotations

from importlib import import_module
from typing import Any

from app.core.config import settings
from app.core.exceptions import DNSLookupError
from app.schemas.analysis import IPIntelligenceResult, ResolvedIPAddress
from app.services.dns_service import DNSLookupService, IPAddressValue
from app.services.providers.geoip_provider import DisabledGeoIPProvider, GeoIPLookupResult, GeoIPProvider
from app.services.providers.maxmind_geoip_provider import MaxMindGeoIPProvider


class IPIntelligenceService:
    """Resolves website IPs, reverse DNS, and enriches the primary public address when possible."""

    def __init__(
        self,
        *,
        dns_service: DNSLookupService | None = None,
        geoip_provider: GeoIPProvider | None = None,
        ipwhois_lookup_func=None,
    ) -> None:
        self.dns_service = dns_service or DNSLookupService()
        self.geoip_provider = geoip_provider or self._build_provider()
        self.ipwhois_lookup_func = ipwhois_lookup_func or self._lookup_ipwhois

    def analyze(self, domain: str) -> IPIntelligenceResult:
        try:
            resolved = self.dns_service.get_ip_records(domain)
        except DNSLookupError as exc:
            return IPIntelligenceResult(
                message="Nao foi possivel resolver enderecos IP do website por indisponibilidade temporaria de DNS.",
                notes=[str(exc), "A analise principal seguiu sem o bloco de inteligencia de IP."],
                source="DNS",
            )

        reverse_dns_map = {item.address: self._safe_reverse_dns(item.address) for item in resolved}
        serialized = [
            self._serialize_record(item, reverse_dns=reverse_dns_map.get(item.address))
            for item in resolved
        ]
        if not resolved:
            return IPIntelligenceResult(
                resolved_ips=[],
                message="Nenhum registro A ou AAAA foi encontrado para o website analisado.",
                notes=["Sem IP resolvido, nao foi possivel aplicar geolocalizacao ou contexto adicional de IP."],
                source="DNS",
            )

        public_records = [item for item in resolved if item.is_public]
        primary = public_records[0] if public_records else resolved[0]
        reverse_dns = reverse_dns_map.get(primary.address)
        geo_result = self._lookup_geo(primary.address, is_public=primary.is_public)

        if primary.is_public and not geo_result.available:
            geo_result = self._merge_lookup_results(
                geo_result,
                self.ipwhois_lookup_func(primary.address),
            )

        country_name = geo_result.country_name or geo_result.country
        country_code = geo_result.country_code
        country = country_name or country_code
        usage_type = geo_result.usage_type or self._guess_usage_type(
            isp=geo_result.isp,
            organization=geo_result.organization or geo_result.asn_org,
            anonymous_flags=geo_result.anonymous_ip_flags,
        )

        notes = [
            "Dados geograficos de IP sao aproximados e podem representar borda, CDN, proxy reverso ou provedor intermediario."
        ]
        if len(public_records) > 1:
            notes.append(
                "Mais de um IP publico foi resolvido; o IP principal exibido representa apenas um dos endpoints observados."
            )
        if any(item.reverse_dns for item in serialized):
            notes.append(
                "O reverse DNS reflete apenas o hostname devolvido por cada IP observado, nao a topologia completa da infraestrutura."
            )
        if geo_result.is_proxy_or_hosting_guess:
            notes.append(
                "Sinais de proxy, hosting ou anonimidade indicam contexto do IP observado, nao atribuicao definitiva da infraestrutura."
            )
        if geo_result.source and "ipwhois" in geo_result.source:
            notes.append(
                "ASN, organizacao e pais vieram do fallback ipwhois; cidade e ISP podem ficar indisponiveis sem MaxMind."
            )
        elif geo_result.source and geo_result.source.startswith("maxmind"):
            notes.append("ASN, geolocalizacao e contexto de rede vieram do MaxMind configurado neste ambiente.")
        notes.extend(geo_result.notes)

        if not public_records:
            return IPIntelligenceResult(
                resolved_ips=serialized,
                primary_ip=primary.address,
                ip_version=primary.version,
                is_public=primary.is_public,
                has_public_ip=False,
                multiple_public_ips=False,
                reverse_dns=reverse_dns,
                message="Os IPs resolvidos nao sao publicos ou utilizaveis para geolocalizacao externa.",
                notes=self._dedupe_notes(notes),
                source="DNS",
                confidence_note="Sem IP publico, a inteligencia de IP ficou limitada ao resultado DNS observado.",
            )

        provider_guess = geo_result.isp or geo_result.organization or geo_result.asn_org
        reputation_summary = None
        if geo_result.anonymous_ip_flags:
            reputation_summary = (
                "A base observada sinalizou: " + ", ".join(sorted(geo_result.anonymous_ip_flags)) + "."
            )

        return IPIntelligenceResult(
            resolved_ips=serialized,
            primary_ip=primary.address,
            ip_version=primary.version,
            is_public=True,
            has_public_ip=True,
            multiple_public_ips=len(public_records) > 1,
            reverse_dns=reverse_dns,
            asn=geo_result.asn,
            asn_org=geo_result.asn_org,
            asn_name=geo_result.asn_org,
            isp=geo_result.isp,
            organization=geo_result.organization or geo_result.asn_org,
            provider_guess=provider_guess,
            country=country,
            country_name=country_name,
            country_code=country_code,
            region=geo_result.region,
            city=geo_result.city,
            timezone=geo_result.timezone,
            usage_type=usage_type,
            anonymous_ip_flags=geo_result.anonymous_ip_flags,
            is_proxy_or_hosting_guess=geo_result.is_proxy_or_hosting_guess,
            reputation_source=geo_result.source if geo_result.anonymous_ip_flags else None,
            reputation_summary=reputation_summary,
            reputation_tags=list(geo_result.anonymous_ip_flags),
            source=geo_result.source or "DNS",
            confidence=self._confidence_for_source(geo_result),
            confidence_note=geo_result.confidence_note,
            message=self._build_message(primary.address, len(public_records), geo_result),
            notes=self._dedupe_notes(notes),
        )

    def _lookup_geo(self, ip_address: str, *, is_public: bool) -> GeoIPLookupResult:
        if not is_public:
            return GeoIPLookupResult(
                available=False,
                source="DNS",
                notes=["O IP principal resolvido nao e publico; o enriquecimento geografico foi omitido."],
                confidence_note="Geolocalizacao de IP privado, local ou reservado nao foi tentada.",
            )
        return self.geoip_provider.lookup(ip_address)

    def _lookup_ipwhois(self, ip_address: str) -> GeoIPLookupResult:
        try:
            ipwhois_module = import_module("ipwhois")
        except Exception as exc:  # pragma: no cover - optional dependency/runtime path
            return GeoIPLookupResult(
                available=False,
                source="ipwhois",
                notes=["O fallback ipwhois nao esta instalado no ambiente atual."],
                confidence_note=str(exc),
            )

        try:
            payload = ipwhois_module.IPWhois(ip_address).lookup_rdap()
        except Exception as exc:
            return GeoIPLookupResult(
                available=False,
                source="ipwhois:rdap",
                notes=["O fallback ipwhois nao conseguiu enriquecer o IP observado."],
                confidence_note=str(exc),
            )

        network = payload.get("network") or {}
        country_code = self._clean_text(network.get("country")) or self._clean_text(payload.get("asn_country_code"))
        country_name = self._country_name_from_code(country_code)
        asn_org = self._clean_text(payload.get("asn_description"))
        organization = self._clean_text(network.get("name")) or asn_org
        usage_type = self._guess_usage_type(
            isp=None,
            organization=organization,
            anonymous_flags=[],
        )

        return GeoIPLookupResult(
            available=any([payload.get("asn"), asn_org, organization, country_code]),
            source="ipwhois:rdap",
            country=country_name or country_code,
            country_name=country_name,
            country_code=country_code,
            asn=self._stringify_asn(payload.get("asn")),
            asn_org=asn_org,
            organization=organization,
            usage_type=usage_type,
            is_proxy_or_hosting_guess=True if usage_type == "hosting" else None,
            confidence_note=(
                "O fallback ipwhois prioriza ASN, organizacao e pais e normalmente nao informa cidade ou ISP detalhados."
            ),
            notes=["O fallback ipwhois foi usado para complementar ASN, organizacao e pais do IP observado."],
        )

    def _safe_reverse_dns(self, address: str) -> str | None:
        try:
            return self.dns_service.get_reverse_dns(address)
        except DNSLookupError:
            return None

    @staticmethod
    def _serialize_record(record: IPAddressValue, *, reverse_dns: str | None) -> ResolvedIPAddress:
        return ResolvedIPAddress(
            ip=record.address,
            version=record.version,
            source_record_type=record.source_record_type,
            is_public=record.is_public,
            reverse_dns=reverse_dns,
        )

    @staticmethod
    def _merge_lookup_results(primary_result: GeoIPLookupResult, fallback_result: GeoIPLookupResult) -> GeoIPLookupResult:
        if not fallback_result.available:
            return GeoIPLookupResult(
                available=primary_result.available,
                source=primary_result.source or fallback_result.source,
                country=primary_result.country,
                country_name=primary_result.country_name,
                country_code=primary_result.country_code,
                region=primary_result.region,
                city=primary_result.city,
                timezone=primary_result.timezone,
                asn=primary_result.asn,
                asn_org=primary_result.asn_org,
                isp=primary_result.isp,
                organization=primary_result.organization,
                usage_type=primary_result.usage_type,
                anonymous_ip_flags=primary_result.anonymous_ip_flags,
                is_proxy_or_hosting_guess=primary_result.is_proxy_or_hosting_guess,
                confidence_note=primary_result.confidence_note or fallback_result.confidence_note,
                notes=IPIntelligenceService._dedupe_notes(primary_result.notes + fallback_result.notes),
            )

        source = fallback_result.source
        if primary_result.source and primary_result.source != fallback_result.source:
            source = f"{primary_result.source}+{fallback_result.source}"

        return GeoIPLookupResult(
            available=True,
            source=source,
            country=primary_result.country or fallback_result.country,
            country_name=primary_result.country_name or fallback_result.country_name,
            country_code=primary_result.country_code or fallback_result.country_code,
            region=primary_result.region or fallback_result.region,
            city=primary_result.city or fallback_result.city,
            timezone=primary_result.timezone or fallback_result.timezone,
            asn=primary_result.asn or fallback_result.asn,
            asn_org=primary_result.asn_org or fallback_result.asn_org,
            isp=primary_result.isp or fallback_result.isp,
            organization=primary_result.organization or fallback_result.organization,
            usage_type=primary_result.usage_type or fallback_result.usage_type,
            anonymous_ip_flags=primary_result.anonymous_ip_flags or fallback_result.anonymous_ip_flags,
            is_proxy_or_hosting_guess=(
                primary_result.is_proxy_or_hosting_guess
                if primary_result.is_proxy_or_hosting_guess is not None
                else fallback_result.is_proxy_or_hosting_guess
            ),
            confidence_note=primary_result.confidence_note or fallback_result.confidence_note,
            notes=IPIntelligenceService._dedupe_notes(primary_result.notes + fallback_result.notes),
        )

    @staticmethod
    def _confidence_for_source(geo_result: GeoIPLookupResult) -> str | None:
        if not geo_result.available:
            return None
        if geo_result.source and geo_result.source.startswith("maxmind"):
            return "media"
        return "baixa"

    @staticmethod
    def _build_message(primary_ip: str, public_count: int, geo_result: GeoIPLookupResult) -> str:
        if geo_result.source and "ipwhois" in geo_result.source:
            suffix = " com ASN e pais obtidos via fallback ipwhois."
        elif geo_result.available:
            suffix = " com contexto GeoIP disponivel."
        else:
            suffix = "."
        if public_count > 1:
            return f"Foram resolvidos {public_count} IPs publicos; o IP principal exibido e {primary_ip}{suffix}"
        return f"O IP publico principal observado para o website foi {primary_ip}{suffix}"

    @staticmethod
    def _guess_usage_type(
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

    @staticmethod
    def _clean_text(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _stringify_asn(value: Any) -> str | None:
        if value in {None, "", "NA"}:
            return None
        text = str(value).strip()
        if not text:
            return None
        return text if text.startswith("AS") else f"AS{text}"

    @staticmethod
    def _country_name_from_code(country_code: str | None) -> str | None:
        if not country_code:
            return None
        try:
            pycountry = import_module("pycountry")
        except Exception:
            return None
        match = pycountry.countries.get(alpha_2=country_code.upper())
        if match is None:
            return None
        return str(match.name)

    @staticmethod
    def _dedupe_notes(notes: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in notes:
            if not item or item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    @staticmethod
    def _build_provider() -> GeoIPProvider:
        if not settings.geoip_enabled:
            return DisabledGeoIPProvider()
        if settings.geoip_provider == "maxmind":
            return MaxMindGeoIPProvider(
                city_db_path=settings.geoip_city_db_path,
                asn_db_path=settings.geoip_asn_db_path,
                isp_db_path=settings.geoip_isp_db_path,
                anonymous_db_path=settings.geoip_anonymous_db_path,
                account_id=settings.geoip_account_id,
                license_key=settings.geoip_license_key,
                host=settings.geoip_host,
                timeout_seconds=settings.geoip_timeout_seconds,
            )
        return DisabledGeoIPProvider()
