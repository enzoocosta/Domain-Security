from datetime import UTC, datetime, timedelta

import pytest

from app.core.exceptions import DNSTimeoutError
from app.schemas.analysis import DomainRegistrationResult, EmailTLSMXResult, EmailTLSResult, WebsiteTLSResult
from app.services.analysis_service import DomainAnalysisService
from app.services.dns_service import MXRecordValue
from app.utils.input_parser import normalize_target
from tests.fakes import (
    StubDNSService,
    StubDomainRegistrationService,
    StubEmailTLSService,
    StubWebsiteTLSService,
)


def _website_tls_ok() -> WebsiteTLSResult:
    now = datetime.now(tz=UTC)
    return WebsiteTLSResult(
        ssl_active=True,
        certificate_valid=True,
        issuer="Let's Encrypt",
        subject="CN=example.com",
        san=["example.com", "www.example.com"],
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=80),
        days_to_expire=80,
        expiry_status="ok",
        tls_version="TLSv1.3",
        provider_guess="Cloudflare",
        confidence="media",
        message="HTTPS esta ativo com certificado valido.",
    )


def _email_tls_ok() -> EmailTLSResult:
    now = datetime.now(tz=UTC)
    return EmailTLSResult(
        mx_results=[
            EmailTLSMXResult(
                host="mail.example.com",
                port=25,
                starttls_supported=True,
                has_tls_data=True,
                certificate_valid=True,
                issuer="Google Trust Services",
                subject="CN=mail.example.com",
                not_before=now - timedelta(days=7),
                not_after=now + timedelta(days=60),
                days_to_expire=60,
                expiry_status="ok",
                tls_version="TLSv1.3",
                hostname_match=True,
            )
        ],
        has_email_tls_data=True,
        message="Os MX testados anunciaram STARTTLS e apresentaram certificados validos.",
        note="O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal.",
    )


def _registration_ok() -> DomainRegistrationResult:
    now = datetime.now(tz=UTC)
    return DomainRegistrationResult(
        rdap_available=True,
        created_at=now - timedelta(days=365),
        expires_at=now + timedelta(days=120),
        days_to_expire=120,
        expiry_status="ok",
        registrar="Example Registrar",
        status=["active"],
        message="Dados RDAP obtidos com datas de criacao e expiracao.",
        source="RDAP",
    )


def test_normalize_target_extracts_domain_from_email():
    normalized = normalize_target("Admin@Example.com")

    assert normalized.target_type == "email"
    assert normalized.analysis_domain == "example.com"
    assert normalized.normalized_input == "Admin@example.com"


def test_analysis_service_builds_scored_result():
    service = DomainAnalysisService(
        dns_service=StubDNSService(
            mx_records=[MXRecordValue(preference=10, exchange="mail.example.com")],
            txt_records={
                "example.com": [
                    "google-site-verification=token",
                    "v=spf1 include:_spf.example.net -all",
                ],
                "_dmarc.example.com": [
                    "v=DMARC1; p=reject; rua=mailto:reports@example.com; pct=100; adkim=s; aspf=s",
                ],
                "default._domainkey.example.com": [
                    "v=DKIM1; k=rsa; p=MIIB",
                ],
            },
        ),
        website_tls_service=StubWebsiteTLSService(_website_tls_ok()),
        email_tls_service=StubEmailTLSService(_email_tls_ok()),
        domain_registration_service=StubDomainRegistrationService(_registration_ok()),
    )

    result = service.analyze_target("Example.com")

    assert result.status == "concluido"
    assert result.normalized.analysis_domain == "example.com"
    assert result.checks.mx.status == "presente"
    assert result.checks.spf.final_all == "-all"
    assert result.checks.spf.posture == "restritivo"
    assert result.checks.dmarc.policy == "reject"
    assert result.checks.dmarc.policy_strength == "forte"
    assert result.checks.dkim.status == "provavelmente_presente"
    assert result.website_tls.ssl_active is True
    assert result.email_tls.has_email_tls_data is True
    assert result.email_tls.mx_results[0].starttls_supported is True
    assert result.domain_registration.rdap_available is True
    assert result.score >= 85
    assert result.severity in {"bom", "excelente"}
    assert result.score_breakdown.spf_score >= 90
    assert any(item.category == "tls_site" for item in result.findings)
    assert "HTTPS ativo" in result.summary


def test_analysis_service_marks_transport_and_registration_risks():
    website_tls = WebsiteTLSResult(
        ssl_active=True,
        certificate_valid=False,
        issuer="Self Signed",
        subject="CN=example.com",
        san=["example.com"],
        days_to_expire=-1,
        expiry_status="expirado",
        tls_version="TLSv1.2",
        provider_guess="desconhecido",
        confidence="baixa",
        message="HTTPS esta ativo, mas o certificado do site esta expirado.",
    )
    email_tls = EmailTLSResult(
        mx_results=[
            EmailTLSMXResult(
                host="mx1.example.com",
                port=25,
                starttls_supported=False,
                has_tls_data=False,
                expiry_status="desconhecido",
            )
        ],
        has_email_tls_data=False,
        message="Nenhum MX testado anunciou STARTTLS com sucesso.",
        note="O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal.",
    )
    registration = DomainRegistrationResult(
        rdap_available=True,
        days_to_expire=10,
        expiry_status="proximo_expiracao",
        registrar="Example Registrar",
        status=["clientTransferProhibited"],
        message="Dados RDAP obtidos parcialmente; algumas datas nao foram publicadas.",
        source="RDAP",
    )
    service = DomainAnalysisService(
        dns_service=StubDNSService(
            txt_records={
                "example.com": ["v=spf1 include:_spf.example.net +all"],
                "_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:reports@example.com"],
            },
        ),
        website_tls_service=StubWebsiteTLSService(website_tls),
        email_tls_service=StubEmailTLSService(email_tls),
        domain_registration_service=StubDomainRegistrationService(registration),
    )

    result = service.analyze_target("example.com")

    assert result.checks.mx.status == "ausente"
    assert result.checks.spf.final_all == "+all"
    assert result.score_breakdown.spf_score == 5
    assert result.checks.dmarc.policy == "none"
    assert result.email_tls.has_email_tls_data is False
    assert any(item.category == "tls_site" and item.severity == "critico" for item in result.findings)
    assert any(item.category == "tls_email" and item.severity == "alto" for item in result.findings)
    assert any(item.category == "registro_dominio" and item.priority == "alta" for item in result.recommendations)


def test_analysis_service_propagates_dns_timeout():
    service = DomainAnalysisService(
        dns_service=StubDNSService(
            mx_exception=DNSTimeoutError("Timeout DNS."),
        )
    )

    with pytest.raises(DNSTimeoutError):
        service.analyze_target("example.com")
