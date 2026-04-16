from datetime import UTC, datetime, timedelta

from app.services.dns_service import MXRecordValue
from app.services.email_tls_service import EmailTLSService


def test_email_tls_service_reports_starttls_and_certificate():
    now = datetime.now(tz=UTC)

    def probe(host: str, port: int):
        return {
            "mx1.example.com": {
                "host": host,
                "port": port,
                "starttls_supported": True,
                "has_tls_data": True,
                "certificate_valid": True,
                "issuer": "Let's Encrypt",
                "subject": "CN=mx1.example.com",
                "not_before": now - timedelta(days=5),
                "not_after": now + timedelta(days=50),
                "days_to_expire": 50,
                "expiry_status": "ok",
                "tls_version": "TLSv1.3",
                "hostname_match": True,
                "error": None,
            }
        }[host]

    service = EmailTLSService(probe_func=lambda host, port: service_result_from_dict(probe(host, port)))

    result = service.analyze([MXRecordValue(preference=10, exchange="mx1.example.com")])

    assert result.mx_results[0].starttls_supported is True
    assert result.mx_results[0].has_tls_data is True
    assert result.mx_results[0].certificate_valid is True
    assert result.mx_results[0].hostname_match is True
    assert result.has_email_tls_data is True
    assert "certificados validos" in result.message


def test_email_tls_service_handles_missing_starttls():
    service = EmailTLSService(
        probe_func=lambda host, port: service_result_from_dict(
            {
                "host": host,
                "port": port,
                "starttls_supported": False,
                "has_tls_data": False,
                "certificate_valid": None,
                "issuer": None,
                "subject": None,
                "not_before": None,
                "not_after": None,
                "days_to_expire": None,
                "expiry_status": "desconhecido",
                "tls_version": None,
                "hostname_match": None,
                "error": None,
            }
        )
    )

    result = service.analyze([MXRecordValue(preference=10, exchange="mx1.example.com")])

    assert result.mx_results[0].starttls_supported is False
    assert result.mx_results[0].has_tls_data is False
    assert result.has_email_tls_data is False
    assert "Nenhum MX testado anunciou STARTTLS" in result.message


def service_result_from_dict(payload: dict):
    from app.schemas.analysis import EmailTLSMXResult

    return EmailTLSMXResult(**payload)
