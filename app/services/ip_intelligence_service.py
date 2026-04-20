from __future__ import annotations

from app.core.config import settings
from app.core.exceptions import DNSLookupError
from app.schemas.analysis import IPIntelligenceResult, ResolvedIPAddress
from app.services.dns_service import DNSLookupService, IPAddressValue
from app.services.providers.geoip_provider import DisabledGeoIPProvider, GeoIPLookupResult, GeoIPProvider
from app.services.providers.maxmind_geoip_provider import MaxMindGeoIPProvider


class IPIntelligenceService:
    """Resolves website IPs and enriches the primary public address when possible."""

    def __init__(
        self,
        *,
        dns_service: DNSLookupService | None = None,
        geoip_provider: GeoIPProvider | None = None,
    ) -> None:
        self.dns_service = dns_service or DNSLookupService()
        self.geoip_provider = geoip_provider or self._build_provider()

    def analyze(self, domain: str) -> IPIntelligenceResult:
        try:
            resolved = self.dns_service.get_ip_records(domain)
        except DNSLookupError as exc:
            return IPIntelligenceResult(
                message="Nao foi possivel resolver enderecos IP do website por indisponibilidade temporaria de DNS.",
                notes=[str(exc), "A analise principal seguiu sem o bloco de inteligencia de IP."],
                source="DNS",
            )

        serialized = [self._serialize_record(item) for item in resolved]
        if not resolved:
            return IPIntelligenceResult(
                resolved_ips=[],
                message="Nenhum registro A ou AAAA foi encontrado para o website analisado.",
                notes=["Sem IP resolvido, nao foi possivel aplicar geolocalizacao ou contexto adicional de IP."],
                source="DNS",
            )

        public_records = [item for item in resolved if item.is_public]
        primary = public_records[0] if public_records else resolved[0]
        reverse_dns = self._safe_reverse_dns(primary.address)
        geo_result = self._lookup_geo(primary.address, is_public=primary.is_public)

        notes = [
            "Dados geograficos de IP sao aproximados e podem representar borda, CDN, proxy reverso ou provedor intermediario."
        ]
        if len(public_records) > 1:
            notes.append(
                "Mais de um IP publico foi resolvido; o IP principal exibido representa apenas um dos endpoints observados."
            )
        if reverse_dns:
            notes.append(
                "O reverse DNS mostra apenas o hostname devolvido pelo IP observado, nao a topologia completa da infraestrutura."
            )
        if geo_result.is_proxy_or_hosting_guess:
            notes.append(
                "Sinais de proxy, hosting ou anonimidade indicam contexto do IP observado, nao atribuicao definitiva da infraestrutura."
            )
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
                "A base MaxMind sinalizou: " + ", ".join(sorted(geo_result.anonymous_ip_flags)) + "."
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
            isp=geo_result.isp,
            organization=geo_result.organization or geo_result.asn_org,
            provider_guess=provider_guess,
            country=geo_result.country,
            region=geo_result.region,
            city=geo_result.city,
            timezone=geo_result.timezone,
            anonymous_ip_flags=geo_result.anonymous_ip_flags,
            is_proxy_or_hosting_guess=geo_result.is_proxy_or_hosting_guess,
            reputation_source=geo_result.source if geo_result.anonymous_ip_flags else None,
            reputation_summary=reputation_summary,
            reputation_tags=list(geo_result.anonymous_ip_flags),
            source=geo_result.source or "DNS",
            confidence="media" if geo_result.available else None,
            confidence_note=geo_result.confidence_note,
            message=self._build_message(primary.address, len(public_records), geo_result.available),
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

    def _safe_reverse_dns(self, address: str) -> str | None:
        try:
            return self.dns_service.get_reverse_dns(address)
        except DNSLookupError:
            return None

    @staticmethod
    def _serialize_record(record: IPAddressValue) -> ResolvedIPAddress:
        return ResolvedIPAddress(
            ip=record.address,
            version=record.version,
            source_record_type=record.source_record_type,
            is_public=record.is_public,
        )

    @staticmethod
    def _build_message(primary_ip: str, public_count: int, geo_available: bool) -> str:
        suffix = " com contexto GeoIP disponivel." if geo_available else "."
        if public_count > 1:
            return f"Foram resolvidos {public_count} IPs publicos; o IP principal exibido e {primary_ip}{suffix}"
        return f"O IP publico principal observado para o website foi {primary_ip}{suffix}"

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
