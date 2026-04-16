from datetime import UTC, datetime, timedelta

from app.services.website_tls_service import WebsiteTLSService
from app.utils.tls_helpers import TLSProbeData


def test_website_tls_service_serializes_valid_certificate():
    now = datetime.now(tz=UTC)
    certificate = {
        "issuer": ((("organizationName", "Cloudflare"),),),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notBefore": (now - timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": (now + timedelta(days=45)).strftime("%b %d %H:%M:%S %Y GMT"),
    }
    service = WebsiteTLSService(
        probe_func=lambda host, port: TLSProbeData(
            tls_available=True,
            certificate_valid=True,
            certificate=certificate,
            tls_version="TLSv1.3",
        )
    )

    result = service.analyze("example.com")

    assert result.ssl_active is True
    assert result.certificate_valid is True
    assert result.provider_guess == "Cloudflare"
    assert result.confidence == "alta"
    assert result.expiry_status == "ok"
    assert "HTTPS esta ativo" in result.message


def test_website_tls_service_handles_inactive_https():
    service = WebsiteTLSService(
        probe_func=lambda host, port: TLSProbeData(
            tls_available=False,
            certificate_valid=None,
            certificate=None,
            tls_version=None,
            error="Falha ao negociar HTTPS: conexao recusada",
        )
    )

    result = service.analyze("example.com")

    assert result.ssl_active is False
    assert result.error == "Falha ao negociar HTTPS: conexao recusada"
    assert result.expiry_status == "desconhecido"
