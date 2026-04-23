from app.services.dns_service import IPAddressValue
from app.services.ip_intelligence_service import IPIntelligenceService
from app.services.providers.geoip_provider import DisabledGeoIPProvider, GeoIPLookupResult
from tests.fakes import StubDNSService


class StubGeoIPProvider:
    def __init__(self, result: GeoIPLookupResult) -> None:
        self.result = result
        self.calls: list[str] = []

    def lookup(self, ip_address: str) -> GeoIPLookupResult:
        self.calls.append(ip_address)
        return self.result


def test_ip_intelligence_selects_public_primary_and_enriches_context():
    dns_service = StubDNSService(
        ip_records=[
            IPAddressValue(address="10.0.0.4", version="ipv4", source_record_type="A", is_public=False),
            IPAddressValue(address="93.184.216.34", version="ipv4", source_record_type="A", is_public=True),
            IPAddressValue(
                address="2606:2800:220:1:248:1893:25c8:1946",
                version="ipv6",
                source_record_type="AAAA",
                is_public=True,
            ),
        ],
        reverse_dns_map={
            "10.0.0.4": None,
            "93.184.216.34": "edge.example.net",
            "2606:2800:220:1:248:1893:25c8:1946": "edge-v6.example.net",
        },
    )
    geoip_provider = StubGeoIPProvider(
        GeoIPLookupResult(
            available=True,
            source="maxmind:city+asn+isp+anonymous",
            asn="AS64500",
            asn_org="Example Networks",
            isp="Example Edge",
            organization="Example Edge",
            country="United States",
            country_name="United States",
            country_code="US",
            region="California",
            city="Los Angeles",
            timezone="America/Los_Angeles",
            usage_type="hosting",
            anonymous_ip_flags=["hosting_provider"],
            is_proxy_or_hosting_guess=True,
            confidence_note="Dados MaxMind sao aproximados.",
        )
    )
    service = IPIntelligenceService(dns_service=dns_service, geoip_provider=geoip_provider)

    result = service.analyze("example.com")

    assert geoip_provider.calls == ["93.184.216.34"]
    assert result.primary_ip == "93.184.216.34"
    assert result.ip_version == "ipv4"
    assert result.has_public_ip is True
    assert result.multiple_public_ips is True
    assert result.reverse_dns == "edge.example.net"
    assert result.resolved_ips[1].reverse_dns == "edge.example.net"
    assert result.resolved_ips[2].reverse_dns == "edge-v6.example.net"
    assert result.asn_name == "Example Networks"
    assert result.isp == "Example Edge"
    assert result.country_name == "United States"
    assert result.country_code == "US"
    assert result.usage_type == "hosting"
    assert result.anonymous_ip_flags == ["hosting_provider"]
    assert any("MaxMind" in item or "aproximada" in item for item in result.notes)


def test_ip_intelligence_gracefully_handles_missing_geoip_configuration():
    dns_service = StubDNSService(
        ip_records=[
            IPAddressValue(address="93.184.216.34", version="ipv4", source_record_type="A", is_public=True),
        ],
        reverse_dns="edge.example.net",
    )
    service = IPIntelligenceService(
        dns_service=dns_service,
        geoip_provider=DisabledGeoIPProvider(),
        ipwhois_lookup_func=lambda ip: GeoIPLookupResult(
            available=False,
            source="ipwhois",
            notes=["Fallback indisponivel."],
        ),
    )

    result = service.analyze("example.com")

    assert result.primary_ip == "93.184.216.34"
    assert result.has_public_ip is True
    assert result.organization is None
    assert result.source == "disabled"
    assert result.message.startswith("O IP publico principal observado")


def test_ip_intelligence_uses_ipwhois_fallback_when_geoip_is_unavailable():
    dns_service = StubDNSService(
        ip_records=[
            IPAddressValue(address="93.184.216.34", version="ipv4", source_record_type="A", is_public=True),
        ],
        reverse_dns="edge.example.net",
    )
    service = IPIntelligenceService(
        dns_service=dns_service,
        geoip_provider=DisabledGeoIPProvider(),
        ipwhois_lookup_func=lambda ip: GeoIPLookupResult(
            available=True,
            source="ipwhois:rdap",
            asn="AS15169",
            asn_org="Google LLC",
            organization="GOGL",
            country="United States",
            country_name="United States",
            country_code="US",
            usage_type="hosting",
            confidence_note="Fallback com foco em ASN e pais.",
        ),
    )

    result = service.analyze("example.com")

    assert result.source == "disabled+ipwhois:rdap"
    assert result.asn == "AS15169"
    assert result.asn_name == "Google LLC"
    assert result.country_code == "US"
    assert result.usage_type == "hosting"
    assert any("fallback ipwhois" in item for item in result.notes)


def test_ip_intelligence_skips_geoip_for_non_public_ip():
    dns_service = StubDNSService(
        ip_records=[
            IPAddressValue(address="10.0.0.4", version="ipv4", source_record_type="A", is_public=False),
        ],
    )
    geoip_provider = StubGeoIPProvider(
        GeoIPLookupResult(
            available=True,
            source="maxmind",
            country_name="United States",
            country_code="US",
        )
    )
    service = IPIntelligenceService(dns_service=dns_service, geoip_provider=geoip_provider)

    result = service.analyze("example.com")

    assert geoip_provider.calls == []
    assert result.has_public_ip is False
    assert "nao sao publicos" in result.message
