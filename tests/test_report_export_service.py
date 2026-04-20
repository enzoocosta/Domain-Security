from datetime import UTC, datetime, timedelta

from app.schemas.analysis import DomainRegistrationResult, EmailTLSResult, IPIntelligenceResult, WebsiteTLSResult
from app.services.analysis_service import DomainAnalysisService
from app.services.dns_service import MXRecordValue
from app.services.report_export_service import ReportExportService
from tests.fakes import (
    FakePDFRenderer,
    StubAnalysisHistoryService,
    StubDNSService,
    StubDomainRegistrationService,
    StubEmailTLSService,
    StubIPIntelligenceService,
    StubWebsiteTLSService,
)


def _website_tls_result() -> WebsiteTLSResult:
    now = datetime.now(tz=UTC)
    return WebsiteTLSResult(
        ssl_active=True,
        certificate_valid=True,
        issuer="Example CA",
        subject="CN=example.com",
        san=["example.com"],
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=80),
        days_to_expire=80,
        expiry_status="ok",
        tls_version="TLSv1.3",
        provider_guess="Edge CDN",
        confidence="media",
        message="HTTPS esta ativo com certificado valido.",
    )


def _registration_result() -> DomainRegistrationResult:
    now = datetime.now(tz=UTC)
    return DomainRegistrationResult(
        rdap_available=True,
        created_at=now - timedelta(days=400),
        expires_at=now + timedelta(days=120),
        days_to_expire=120,
        expiry_status="ok",
        registrar="Example Registrar",
        status=["active"],
        message="Dados RDAP obtidos com datas de criacao e expiracao.",
        source="RDAP",
    )


def _ip_intelligence_result() -> IPIntelligenceResult:
    return IPIntelligenceResult(
        primary_ip="93.184.216.34",
        ip_version="ipv4",
        is_public=True,
        has_public_ip=True,
        provider_guess="Example Edge",
        country="US",
        city="Los Angeles",
        message="O IP publico principal observado para o website foi 93.184.216.34 com contexto GeoIP disponivel.",
    )


def test_report_export_service_builds_pdf_html_and_returns_bytes():
    analysis_service = DomainAnalysisService(
        dns_service=StubDNSService(
            mx_records=[MXRecordValue(preference=10, exchange="mail.example.com")],
            txt_records={
                "example.com": ["v=spf1 include:_spf.example.net -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
                "default._domainkey.example.com": ["v=DKIM1; p=MIIB"],
            },
        ),
        website_tls_service=StubWebsiteTLSService(_website_tls_result()),
        email_tls_service=StubEmailTLSService(
            EmailTLSResult(
                mx_results=[],
                has_email_tls_data=False,
                message="Nenhum MX testado anunciou STARTTLS com sucesso.",
                note="O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal.",
            )
        ),
        domain_registration_service=StubDomainRegistrationService(_registration_result()),
        ip_intelligence_service=StubIPIntelligenceService(_ip_intelligence_result()),
        history_service=StubAnalysisHistoryService(),
    )
    renderer = FakePDFRenderer(content=b"%PDF-test")
    service = ReportExportService(
        analysis_service=analysis_service,
        history_service=StubAnalysisHistoryService(),
        renderer=renderer,
    )

    filename, content = service.export_latest_pdf("example.com")

    assert filename == "example_com_report.pdf"
    assert content == b"%PDF-test"
    assert renderer.calls
    assert "example.com" in renderer.calls[0]["html"]
    assert "Relatorio executivo e tecnico" in renderer.calls[0]["html"]
