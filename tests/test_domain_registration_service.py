from datetime import UTC, datetime, timedelta

from app.services.domain_registration_service import DomainRegistrationService


def test_domain_registration_service_extracts_whois_fields():
    now = datetime.now(tz=UTC)
    payload = {
        "creation_date": [now - timedelta(days=400)],
        "expiration_date": [now + timedelta(days=30)],
        "registrar": "Example Registrar",
        "status": ["active", "clientTransferProhibited"],
    }
    service = DomainRegistrationService(fetcher=lambda domain: payload)

    result = service.analyze("example.com")

    assert result.available is True
    assert result.whois_available is True
    assert result.rdap_available is True
    assert result.source == "WHOIS"
    assert result.registrar == "Example Registrar"
    assert result.expiry_status == "proximo_expiracao"
    assert len(result.status) == 2


def test_domain_registration_service_handles_fetch_failure():
    service = DomainRegistrationService(
        fetcher=lambda domain: (_ for _ in ()).throw(RuntimeError("WHOIS indisponivel"))
    )

    result = service.analyze("example.com")

    assert result.available is False
    assert result.whois_available is False
    assert "Nao foi possivel obter dados WHOIS" in result.message
    assert result.error == "WHOIS indisponivel"
