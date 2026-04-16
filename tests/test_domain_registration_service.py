from datetime import UTC, datetime, timedelta

from app.services.domain_registration_service import DomainRegistrationService


def test_domain_registration_service_extracts_rdap_fields():
    now = datetime.now(tz=UTC)
    payload = {
        "events": [
            {"eventAction": "registration", "eventDate": (now - timedelta(days=400)).isoformat()},
            {"eventAction": "expiration", "eventDate": (now + timedelta(days=30)).isoformat()},
        ],
        "status": ["active", "clientTransferProhibited"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }
        ],
    }
    service = DomainRegistrationService(fetcher=lambda domain: payload)

    result = service.analyze("example.com")

    assert result.rdap_available is True
    assert result.registrar == "Example Registrar"
    assert result.expiry_status == "proximo_expiracao"
    assert len(result.status) == 2


def test_domain_registration_service_handles_fetch_failure():
    service = DomainRegistrationService(fetcher=lambda domain: (_ for _ in ()).throw(RuntimeError("RDAP indisponivel")))

    result = service.analyze("example.com")

    assert result.rdap_available is False
    assert "Nao foi possivel obter dados RDAP" in result.message
    assert result.error == "RDAP indisponivel"
