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
    assert result.issuer == "Cloudflare"
    assert result.subject == "example.com"
    assert result.provider_guess == "Cloudflare"
    assert result.confidence == "alta"
    assert result.expiry_status == "ok"
    assert result.tls_version == "TLSv1.3"
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


def test_website_tls_service_flags_certificate_close_to_expiry():
    now = datetime.now(tz=UTC)
    certificate = {
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"),),
        "notBefore": (now - timedelta(days=20)).strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": (now + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT"),
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
    assert result.issuer == "Let's Encrypt"
    assert result.expiry_status == "proximo_expiracao"
    assert result.days_to_expire <= 10
    assert "proximo da expiracao" in result.message
