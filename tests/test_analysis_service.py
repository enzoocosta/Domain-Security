from datetime import UTC, datetime, timedelta
from time import perf_counter, sleep

from app.core.analysis_cache import AnalysisCache
from app.core.exceptions import DNSTimeoutError
from app.schemas.analysis import DomainRegistrationResult, EmailTLSMXResult, EmailTLSResult, WebsiteTLSResult
from app.services.analysis_service import DomainAnalysisService
from app.services.dns_service import MXRecordValue
from app.services.email_auth_service import EmailAuthenticationService
from app.utils.input_parser import normalize_target
from tests.fakes import (
    StubAnalysisHistoryService,
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
        history_service=StubAnalysisHistoryService(),
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
    assert result.changes.has_previous_snapshot is False
    assert result.score >= 85
    assert result.severity in {"bom", "excelente"}
    assert result.score_breakdown.spf_score >= 90
    assert result.performance.cache_hit is False
    assert result.performance.total_ms >= result.performance.normalize_ms
    assert result.performance.mx_ms >= 0
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
        history_service=StubAnalysisHistoryService(),
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


def test_analysis_service_returns_partial_result_on_dns_timeout():
    service = DomainAnalysisService(
        dns_service=StubDNSService(
            mx_exception=DNSTimeoutError("Timeout DNS."),
            txt_exceptions={
                "example.com": DNSTimeoutError("Timeout SPF."),
                "_dmarc.example.com": DNSTimeoutError("Timeout DMARC."),
            },
        )
    )

    result = service.analyze_target("example.com")

    assert result.checks.mx.lookup_error == "Timeout DNS."
    assert result.checks.spf.lookup_error == "Timeout SPF."
    assert result.checks.dmarc.lookup_error == "Timeout DMARC."
    assert result.email_tls.has_email_tls_data is False
    assert result.performance.cache_hit is False
    assert any(item.title == "MX inconclusivo" for item in result.findings)
    assert any("resultado parcial" in item for item in result.notes)


def test_analysis_service_uses_short_lived_cache():
    dns_service = StubDNSService(
        mx_records=[MXRecordValue(preference=10, exchange="mail.example.com")],
        txt_records={
            "example.com": ["v=spf1 include:_spf.example.net -all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:reports@example.com"],
            "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIB"],
        },
    )
    website_tls_service = StubWebsiteTLSService(_website_tls_ok())
    email_tls_service = StubEmailTLSService(_email_tls_ok())
    domain_registration_service = StubDomainRegistrationService(_registration_ok())
    history_service = StubAnalysisHistoryService()
    service = DomainAnalysisService(
        dns_service=dns_service,
        website_tls_service=website_tls_service,
        email_tls_service=email_tls_service,
        domain_registration_service=domain_registration_service,
        history_service=history_service,
        analysis_cache=AnalysisCache(ttl_seconds=300),
    )

    first = service.analyze_target("example.com")
    second = service.analyze_target("Admin@Example.com")

    assert first.performance.cache_hit is False
    assert second.performance.cache_hit is True
    assert second.normalized.target_type == "email"
    assert dns_service.mx_call_count == 1
    assert website_tls_service.call_count == 1
    assert email_tls_service.call_count == 1
    assert domain_registration_service.call_count == 1
    assert history_service.record_call_count == 1


class SlowDNSService(StubDNSService):
    def __init__(self, *args, delay_seconds: float = 0.07, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.delay_seconds = delay_seconds

    def get_mx_records(self, domain: str) -> list[MXRecordValue]:
        sleep(self.delay_seconds)
        return super().get_mx_records(domain)

    def get_txt_records(self, name: str, *, missing_on_nxdomain: bool = False) -> list[str]:
        sleep(self.delay_seconds)
        return super().get_txt_records(name, missing_on_nxdomain=missing_on_nxdomain)


class SlowWebsiteTLSService(StubWebsiteTLSService):
    def __init__(self, result: WebsiteTLSResult, delay_seconds: float = 0.07) -> None:
        super().__init__(result)
        self.delay_seconds = delay_seconds

    def analyze(self, domain: str) -> WebsiteTLSResult:
        sleep(self.delay_seconds)
        return super().analyze(domain)


class SlowEmailTLSService(StubEmailTLSService):
    def __init__(self, result: EmailTLSResult, delay_seconds: float = 0.07) -> None:
        super().__init__(result)
        self.delay_seconds = delay_seconds

    def analyze(self, mx_records: list[MXRecordValue]) -> EmailTLSResult:
        sleep(self.delay_seconds)
        return super().analyze(mx_records)


class SlowDomainRegistrationService(StubDomainRegistrationService):
    def __init__(self, result: DomainRegistrationResult, delay_seconds: float = 0.07) -> None:
        super().__init__(result)
        self.delay_seconds = delay_seconds

    def analyze(self, domain: str) -> DomainRegistrationResult:
        sleep(self.delay_seconds)
        return super().analyze(domain)


def test_analysis_service_parallelizes_independent_stages():
    service = DomainAnalysisService(
        dns_service=SlowDNSService(
            mx_records=[MXRecordValue(preference=10, exchange="mail.example.com")],
            txt_records={
                "example.com": ["v=spf1 include:_spf.example.net -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:reports@example.com"],
                "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIB"],
            },
        ),
        email_auth_service=EmailAuthenticationService(dkim_selectors=("default",)),
        website_tls_service=SlowWebsiteTLSService(_website_tls_ok()),
        email_tls_service=SlowEmailTLSService(_email_tls_ok()),
        domain_registration_service=SlowDomainRegistrationService(_registration_ok()),
        history_service=StubAnalysisHistoryService(),
        analysis_cache=AnalysisCache(ttl_seconds=0),
    )

    started_at = perf_counter()
    result = service.analyze_target("example.com")
    elapsed = perf_counter() - started_at

    assert elapsed < 0.32
    assert result.checks.dkim.status == "provavelmente_presente"
    assert result.performance.mx_ms >= 50
    assert result.performance.website_tls_ms >= 50
    assert result.performance.email_tls_ms >= 50
