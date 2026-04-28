from datetime import UTC, datetime, timedelta
import inspect
import os

from app.api.routes import analysis as analysis_route
from app.api.routes import asset_discovery_web as asset_discovery_web_route
from app.api.routes import discovery as discovery_route
from app.api.routes import history as history_route
from app.api.routes import report_web as report_web_route
from app.api.routes import web as web_route
from app.api.routes import wordpress_analysis as wordpress_analysis_route
from app.db.models import TrafficEvent
from app.db.session import SessionLocal
from app.core.exceptions import DNSDomainNotFoundError
from app.schemas.analysis import (
    DomainRegistrationResult,
    EmailTLSMXResult,
    EmailTLSResult,
    IPIntelligenceResult,
    ResolvedIPAddress,
    WebsiteTLSResult,
)
from app.schemas.history import DomainHistoryResponse, HistoryItem
from app.schemas.wordpress import (
    WordPressAnalysisOptions,
    WordPressAnalysisResponse,
    WordPressAnalysisSummary,
    WordPressDetectionResult,
    WordPressDetectionSignal,
    WordPressItemAnalysis,
    WordPressVersionDetection,
    WordPressVulnerability,
)
from app.services.analysis_service import DomainAnalysisService
from app.services.billing_service import BillingService
from app.services.asset_discovery_service import AssetDiscoveryService
from app.services.monitoring_service import MonitoringService
from app.services.premium_ingest_token_service import PremiumIngestTokenService
from app.services.report_export_service import ReportExportService
from app.services.dns_service import MXRecordValue
from tests.fakes import (
    FakePDFRenderer,
    StubAnalysisHistoryService,
    StubDNSService,
    StubDomainRegistrationService,
    StubEmailTLSService,
    StubIPIntelligenceService,
    StubWebsiteTLSService,
)


class StubAmassRunner:
    provider_name = "amass"

    def __init__(self, result) -> None:
        self.result = result
        self.calls: list[str] = []

    def discover(self, domain: str):
        self.calls.append(domain)
        return self.result


def _website_tls_result() -> WebsiteTLSResult:
    now = datetime.now(tz=UTC)
    return WebsiteTLSResult(
        ssl_active=True,
        certificate_valid=True,
        issuer="Google Trust Services",
        subject="CN=example.com",
        san=["example.com", "www.example.com"],
        not_before=now - timedelta(days=5),
        not_after=now + timedelta(days=70),
        days_to_expire=70,
        expiry_status="ok",
        tls_version="TLSv1.3",
        provider_guess="Cloudflare",
        confidence="media",
        message="HTTPS esta ativo com certificado valido.",
    )


def _email_tls_result() -> EmailTLSResult:
    now = datetime.now(tz=UTC)
    return EmailTLSResult(
        mx_results=[
            EmailTLSMXResult(
                host="mail.example.com",
                port=25,
                starttls_supported=True,
                has_tls_data=True,
                certificate_valid=True,
                issuer="Let's Encrypt",
                subject="CN=mail.example.com",
                not_before=now - timedelta(days=12),
                not_after=now + timedelta(days=45),
                days_to_expire=45,
                expiry_status="ok",
                tls_version="TLSv1.3",
                hostname_match=True,
            )
        ],
        has_email_tls_data=True,
        message="Os MX testados anunciaram STARTTLS e apresentaram certificados validos.",
        note="O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal.",
    )


def _registration_result() -> DomainRegistrationResult:
    now = datetime.now(tz=UTC)
    return DomainRegistrationResult(
        available=True,
        whois_available=True,
        rdap_available=True,
        created_at=now - timedelta(days=400),
        expires_at=now + timedelta(days=150),
        days_to_expire=150,
        expiry_status="ok",
        registrar="Example Registrar",
        status=["active"],
        message="Dados de registro obtidos com datas de criacao e expiracao.",
        source="WHOIS",
    )


def _ip_intelligence_result() -> IPIntelligenceResult:
    return IPIntelligenceResult(
        resolved_ips=[
            ResolvedIPAddress(
                ip="93.184.216.34",
                version="ipv4",
                source_record_type="A",
                is_public=True,
            )
        ],
        primary_ip="93.184.216.34",
        ip_version="ipv4",
        is_public=True,
        has_public_ip=True,
        reverse_dns="edge.example.net",
        asn="AS64500",
        asn_org="Example Networks",
        asn_name="Example Networks",
        isp="Example Edge",
        organization="Example Edge",
        provider_guess="Example Edge",
        country="United States",
        country_name="United States",
        country_code="US",
        region="California",
        city="Los Angeles",
        timezone="America/Los_Angeles",
        usage_type="hosting",
        confidence="media",
        message="O IP publico principal observado para o website foi 93.184.216.34 com enriquecimento externo disponivel.",
        notes=[
            "Dados geograficos de IP sao aproximados e podem representar borda, CDN ou provedor intermediario."
        ],
        source="maxmind:city+asn+isp",
    )


def _install_stub_service(
    monkeypatch,
    dns_service: StubDNSService,
    *,
    email_tls_result: EmailTLSResult | None = None,
    history_response: DomainHistoryResponse | None = None,
    registration_result: DomainRegistrationResult | None = None,
    website_tls_result: WebsiteTLSResult | None = None,
    ip_intelligence_result: IPIntelligenceResult | None = None,
) -> None:
    history_service = StubAnalysisHistoryService(history_response=history_response)
    pdf_renderer = FakePDFRenderer(content=b"%PDF-fake-report")
    service = DomainAnalysisService(
        dns_service=dns_service,
        website_tls_service=StubWebsiteTLSService(
            website_tls_result or _website_tls_result()
        ),
        email_tls_service=StubEmailTLSService(email_tls_result or _email_tls_result()),
        domain_registration_service=StubDomainRegistrationService(
            registration_result or _registration_result()
        ),
        ip_intelligence_service=StubIPIntelligenceService(
            ip_intelligence_result or _ip_intelligence_result()
        ),
        history_service=history_service,
    )
    monkeypatch.setattr(analysis_route, "service", service)
    monkeypatch.setattr(web_route, "service", service)
    monkeypatch.setattr(web_route, "history_service", history_service)
    monkeypatch.setattr(history_route, "service", history_service)
    monkeypatch.setattr(
        report_web_route,
        "service",
        ReportExportService(
            history_service=history_service,
            analysis_service=service,
            renderer=pdf_renderer,
        ),
    )


def _install_stub_discovery_service(monkeypatch) -> StubAmassRunner:
    from app.services.providers.amass_runner import (
        AssetDiscoveryResult,
        DiscoveredAssetRecord,
    )

    runner = StubAmassRunner(
        AssetDiscoveryResult(
            provider="amass",
            status="completed",
            assets=[
                DiscoveredAssetRecord(fqdn="api.example.com", source="amass"),
                DiscoveredAssetRecord(fqdn="mail.example.com", source="amass"),
            ],
        )
    )
    service = AssetDiscoveryService(runner=runner)
    monkeypatch.setattr(asset_discovery_web_route, "discovery_service", service)
    monkeypatch.setattr(discovery_route, "service", service)
    return runner


def _wordpress_analysis_response() -> WordPressAnalysisResponse:
    return WordPressAnalysisResponse(
        targetUrl="https://example.com/",
        scannedUrl="https://example.com/",
        siteConfirmed=True,
        cacheHit=False,
        detection=WordPressDetectionResult(
            isWordPress=True,
            confidence="confirmed",
            signals=[
                WordPressDetectionSignal(
                    layer=1,
                    name="Meta Generator",
                    detected=True,
                    value="WordPress 6.4.2",
                )
            ],
            wordpressVersion="6.4.2",
            versionHidden=False,
        ),
        versionDetection=WordPressVersionDetection(
            version="6.4.2", source="meta_generator"
        ),
        items=[
            WordPressItemAnalysis(
                slug="wordpress-core",
                nome="WordPress Core",
                tipo="core",
                versaoDetectada="6.4.2",
                vulnerabilidades=[
                    WordPressVulnerability(
                        id="CVE-2025-0001",
                        titulo="Falha conhecida no core",
                        severidade="high",
                        cvssScore=8.1,
                        cve="CVE-2025-0001",
                        corrigidoNaVersao="> 6.4.2",
                        referencia="https://www.wpvulnerability.net/core/6.4.2",
                    )
                ],
                status="critico",
                referencia="https://www.wpvulnerability.net/core/6.4.2",
            )
        ],
        summary=WordPressAnalysisSummary(
            totalItemsAnalisados=1,
            totalVulnerabilidades=1,
            vulnerabilidadesPorSeveridade={
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
            },
            scoreGeral=85,
            classificacao="seguro",
        ),
        warnings=[],
        progressSteps=[
            "Carregando pagina principal...",
            "Consultando vulnerabilidades do core...",
        ],
    )


def test_healthcheck(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_home_page_renders(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "Domain Security Checker" in response.text


def test_base_template_uses_versioned_static_assets(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "css/tokens.css?v=" in response.text
    assert "js/theme.js?v=" in response.text
    assert "img/logo.svg?v=" in response.text


def test_home_page_nav_shows_wordpress_and_hides_developer_items_for_client(client):
    client.post(
        "/auth/register",
        data={"email": "client-nav@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    response = client.get("/")

    assert response.status_code == 200
    assert "WordPress" in response.text
    assert "Asset discovery" not in response.text
    assert "API docs" not in response.text


def test_home_page_nav_shows_developer_items_for_developer_role(client):
    from app.services.auth_service import AuthenticationService

    auth_service = AuthenticationService()
    auth_service.register_user(
        "developer-nav@example.com", "supersecret", role="developer"
    )
    client.post(
        "/auth/login",
        data={"email": "developer-nav@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    response = client.get("/")

    assert response.status_code == 200
    assert "WordPress" in response.text
    assert "Asset discovery" in response.text
    assert "API docs" in response.text


def test_wordpress_page_renders_selector_with_technical_and_common_modes(client):
    response = client.get("/wordpress")

    assert response.status_code == 200
    assert "Verifique a segurança do seu site WordPress" in response.text
    assert "Sou usuário comum" in response.text
    assert "Sou técnico de TI" in response.text
    assert "Verificar meu site agora" in response.text
    assert "O que fazer?" not in response.text
    assert "Iniciar Análise Técnica" in response.text
    assert "Verificar versão do WordPress exposta" in response.text
    assert "Abrir relatório técnico completo" in response.text
    assert "Exportar PDF técnico" in response.text
    assert "Copiar JSON" in response.text
    assert "Gerar relatório para o cliente" in response.text
    assert "Verificar outro site" not in response.text
    assert "Top 5 vulnerabilidades principais" in response.text
    assert "Pipeline de verificação" in response.text
    assert "Resultados tecnicos" not in response.text
    assert 'id="secao-escolha"' in response.text
    assert 'id="bloco-comum"' in response.text
    assert 'id="bloco-tecnico"' in response.text
    assert 'id="wordpress-profile-panels"' in response.text
    assert "data-wp-tech-loader" in response.text
    assert "data-wp-tech-step-list" in response.text
    assert "hidden" in response.text


def test_wordpress_technical_report_page_renders_empty_state_shell(client):
    response = client.get("/wordpress/relatorio-tecnico")

    assert response.status_code == 200
    assert (
        "Relatório de Segurança WordPress - Análise Técnica Completa" in response.text
    )
    assert "Nenhum relatório técnico disponível" in response.text
    assert "Exportar PDF" in response.text
    assert "Voltar à análise" in response.text
    assert "Mapa de Risco" in response.text
    assert "Itens Seguros" in response.text
    assert "Recomendações" in response.text


def test_wordpress_analysis_endpoint_returns_backend_payload(client, monkeypatch):
    class StubWordPressSecurityService:
        def __init__(self) -> None:
            self.calls: list[tuple[str, WordPressAnalysisOptions]] = []

        def analyze_site(
            self, url: str, options: WordPressAnalysisOptions | None = None
        ) -> WordPressAnalysisResponse:
            self.calls.append((url, options or WordPressAnalysisOptions()))
            return _wordpress_analysis_response()

    service = StubWordPressSecurityService()
    monkeypatch.setattr(wordpress_analysis_route, "service", service)

    response = client.post(
        "/api/v1/wordpress/analyze",
        json={
            "url": "https://example.com",
            "options": {
                "detect_core": True,
                "detect_plugins": True,
                "detect_themes": True,
            },
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["siteConfirmed"] is True
    assert payload["detection"]["isWordPress"] is True
    assert payload["detection"]["confidence"] == "confirmed"
    assert payload["versionDetection"]["version"] == "6.4.2"
    assert payload["items"][0]["slug"] == "wordpress-core"
    assert payload["items"][0]["vulnerabilidades"][0]["cve"] == "CVE-2025-0001"
    assert payload["summary"]["scoreGeral"] == 85
    assert service.calls[0][0] == "https://example.com"


def test_analysis_endpoint_returns_payload_with_tls_and_registration(
    client, monkeypatch
):
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_records=[MXRecordValue(preference=10, exchange="mail.example.com")],
            txt_records={
                "example.com": ["v=spf1 include:_spf.example.net -all"],
                "_dmarc.example.com": [
                    "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
                ],
                "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIB"],
            },
        ),
    )

    response = client.post("/api/v1/analyze", json={"target": "Admin@Example.com"})
    payload = response.json()

    assert response.status_code == 200
    assert payload["normalized"]["target_type"] == "email"
    assert payload["normalized"]["analysis_domain"] == "example.com"
    assert payload["checks"]["spf"]["final_all"] == "-all"
    assert payload["checks"]["dmarc"]["policy"] == "reject"
    assert payload["checks"]["dkim"]["status"] == "provavelmente_presente"
    assert payload["website_tls"]["ssl_active"] is True
    assert payload["website_tls"]["provider_guess"] == "Cloudflare"
    assert payload["email_tls"]["has_email_tls_data"] is True
    assert payload["email_tls"]["mx_results"][0]["starttls_supported"] is True
    assert payload["domain_registration"]["whois_available"] is True
    assert payload["domain_registration"]["source"] == "WHOIS"
    assert payload["email_policies"]["dnssec"]["status"] == "nao_implementado"
    assert payload["ip_intelligence"]["primary_ip"] == "93.184.216.34"
    assert payload["ip_intelligence"]["country_code"] == "US"
    assert payload["changes"]["has_previous_snapshot"] is False
    assert payload["performance"]["cache_hit"] is False
    assert payload["performance"]["total_ms"] >= 0
    assert payload["score"] >= 80
    assert payload["severity"] in {"bom", "excelente"}
    assert {item["category"] for item in payload["findings"]} == {
        "mx",
        "spf",
        "dkim",
        "dmarc",
    }


def test_analysis_endpoint_returns_404_for_nonexistent_domain(client, monkeypatch):
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_exception=DNSDomainNotFoundError(
                "O dominio 'inexistente.invalid' nao foi encontrado no DNS."
            ),
        ),
    )

    response = client.post("/api/v1/analyze", json={"target": "inexistente.invalid"})

    assert response.status_code == 404
    assert "nao foi encontrado" in response.json()["detail"]


def test_form_submission_renders_new_sections(client, monkeypatch):
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_records=[MXRecordValue(preference=5, exchange="mx1.example.com")],
            txt_records={
                "example.com": ["v=spf1 mx ~all"],
                "_dmarc.example.com": ["v=DMARC1; p=none"],
            },
        ),
    )

    response = client.post("/analyze", data={"target": "example.com"})

    assert response.status_code == 200
    assert "Resultado da análise" in response.text
    assert "WHOIS / Registro" in response.text
    assert "SSL do website" in response.text
    assert "IP Intelligence" in response.text
    assert "Detalhamento do score" in response.text
    assert "Mudanças desde a última análise" in response.text
    assert "Recomendações" in response.text
    assert "Mail Transport Policies" not in response.text
    assert "Technical Notes" not in response.text
    assert "SPF em softfail" in response.text
    assert "DMARC em none" in response.text


def test_form_submission_renders_frozen_domain_banner(client, monkeypatch):
    registration = _registration_result().model_copy(update={"status": ["clientHold"]})
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_records=[MXRecordValue(preference=5, exchange="mx1.example.com")],
            txt_records={
                "example.com": ["v=spf1 mx -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
                "default._domainkey.example.com": ["v=DKIM1; p=MIIB"],
            },
        ),
        registration_result=registration,
    )

    response = client.post("/analyze", data={"target": "example.com"})

    assert response.status_code == 200
    assert "Dominio possivelmente congelado ou suspenso" in response.text
    assert "clientHold" in response.text
    assert "SUSPENSO" in response.text


def test_form_submission_renders_monitoring_plus_offer_for_authenticated_user(
    client, monkeypatch
):
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_records=[MXRecordValue(preference=5, exchange="mx1.example.com")],
            txt_records={
                "example.com": ["v=spf1 mx -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            },
        ),
    )
    client.post(
        "/auth/register",
        data={"email": "premium-owner@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    response = client.post("/analyze", data={"target": "example.com"})

    assert response.status_code == 200
    assert "Monitoring Plus" in response.text
    assert "/monitoring-plus/activate" in response.text


def test_form_submission_hides_empty_email_tls_details(client, monkeypatch):
    empty_email_tls = EmailTLSResult(
        mx_results=[
            EmailTLSMXResult(
                host="mx1.example.com",
                port=25,
                starttls_supported=False,
                has_tls_data=False,
                expiry_status="desconhecido",
                error="Timeout ao testar STARTTLS: timed out",
            )
        ],
        has_email_tls_data=False,
        message="Nenhum MX testado anunciou STARTTLS com sucesso.",
        note="O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal.",
    )
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_records=[MXRecordValue(preference=5, exchange="mx1.example.com")],
            txt_records={
                "example.com": ["v=spf1 mx ~all"],
                "_dmarc.example.com": ["v=DMARC1; p=none"],
            },
        ),
        email_tls_result=empty_email_tls,
    )

    response = client.post("/analyze", data={"target": "example.com"})

    assert response.status_code == 200
    assert (
        "Nao foi possivel obter informacoes de TLS/SSL dos registros MX do dominio example.com."
        in response.text
    )
    assert "O certificado de e-mail pertence ao servidor MX" not in response.text
    assert "porta 25" not in response.text
    assert "Timeout ao testar STARTTLS" not in response.text


def test_monitoring_plus_activation_flow_renders_domain_detail(client):
    client.post(
        "/auth/register",
        data={"email": "plus-owner@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    response = client.post(
        "/monitoring-plus/activate",
        data={
            "domain": "example.com",
            "monitoring_frequency": "daily",
            "input_label": "Dominio premium",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Dominio premium" in response.text
    assert "Ingestão de tráfego" in response.text
    assert "Endpoint de ingestão" in response.text


def test_traffic_ingest_endpoint_accepts_valid_premium_token(client):
    from app.services.auth_service import AuthenticationService

    auth_service = AuthenticationService()
    user = auth_service.register_user("ingest-owner@example.com", "supersecret")
    monitoring_domain = MonitoringService().create_monitored_domain(
        user_id=user.id,
        domain="example.com",
        monitoring_frequency="daily",
        input_label="API",
    )
    BillingService().start_trial(
        user_id=user.id,
        monitored_domain_id=monitoring_domain.id,
    )
    token = PremiumIngestTokenService().create_token(
        user_id=user.id,
        monitored_domain_id=monitoring_domain.id,
        name="edge-prod",
    )

    response = client.post(
        "/api/ingest/v1/traffic",
        json={
            "events": [
                {
                    "client_ip": "203.0.113.5",
                    "method": "GET",
                    "path": "/health",
                    "status_code": 200,
                }
            ]
        },
        headers={"Authorization": f"Bearer {token.token}"},
    )

    assert response.status_code == 202
    assert response.json() == {
        "accepted": 1,
        "rejected": 0,
        "monitored_domain_id": monitoring_domain.id,
    }

    with SessionLocal() as db:
        stored = db.query(TrafficEvent).all()

    assert len(stored) == 1
    assert stored[0].path == "/health"


def test_traffic_ingest_endpoint_rejects_invalid_premium_token(client):
    response = client.post(
        "/api/ingest/v1/traffic",
        json={"events": []},
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Token de ingestao invalido."


def test_history_endpoint_returns_items(client, monkeypatch):
    history_response = DomainHistoryResponse(
        domain="example.com",
        items=[
            HistoryItem(
                id=1,
                created_at=datetime.now(tz=UTC),
                input_target="example.com",
                analysis_domain="example.com",
                score=82,
                severity="bom",
                summary="Resumo da analise salva.",
            )
        ],
    )
    _install_stub_service(
        monkeypatch,
        StubDNSService(),
        history_response=history_response,
    )

    response = client.get("/api/v1/history/example.com")

    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert len(response.json()["items"]) == 1


def test_history_page_renders_items(client, monkeypatch):
    history_response = DomainHistoryResponse(
        domain="example.com",
        items=[
            HistoryItem(
                id=1,
                created_at=datetime.now(tz=UTC),
                input_target="example.com",
                analysis_domain="example.com",
                score=82,
                severity="bom",
                summary="Resumo da analise salva.",
            )
        ],
    )
    _install_stub_service(
        monkeypatch,
        StubDNSService(),
        history_response=history_response,
    )

    response = client.get("/history/example.com")

    assert response.status_code == 200
    assert "Histórico de análises" in response.text
    assert "Resumo da analise salva." in response.text


def test_report_pdf_export_returns_pdf(client, monkeypatch):
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_records=[MXRecordValue(preference=10, exchange="mail.example.com")],
            txt_records={
                "example.com": ["v=spf1 include:_spf.example.net -all"],
                "_dmarc.example.com": [
                    "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
                ],
                "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIB"],
            },
        ),
    )

    response = client.get("/reports/example.com.pdf")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF-fake")


def test_monitoring_route_requires_authentication(client):
    response = client.get("/monitoring", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/login")


def test_register_login_and_create_monitored_domain(client):
    register_response = client.post(
        "/auth/register",
        data={"email": "owner@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    assert register_response.status_code == 200
    assert "Monitoramento autenticado" in register_response.text

    dashboard_response = client.post(
        "/monitoring/domains",
        data={
            "domain": "Example.com",
            "monitoring_frequency": "daily",
            "input_label": "Dominio principal",
        },
        follow_redirects=True,
    )

    assert dashboard_response.status_code == 200
    assert "example.com" in dashboard_response.text
    assert "Dominio principal" in dashboard_response.text
    assert "24 horas" in dashboard_response.text

    logout_response = client.post("/auth/logout", follow_redirects=True)
    assert logout_response.status_code == 200
    assert "Diagnóstico para segurança de Domínio" in logout_response.text

    login_response = client.post(
        "/auth/login",
        data={"email": "owner@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    assert login_response.status_code == 200
    assert "Monitoramento autenticado" in login_response.text


def test_external_monitoring_api_accepts_valid_token(client):
    from app.services.api_token_service import ApiTokenService
    from app.services.auth_service import AuthenticationService

    auth_service = AuthenticationService()
    token_service = ApiTokenService()
    user = auth_service.register_user("api-owner@example.com", "supersecret")
    token = token_service.create_token(user_id=user.id, name="api-monitoring")

    response = client.post(
        "/api/external/v1/monitoring",
        json={
            "domain": "example.com",
            "monitoring_frequency": "daily",
            "input_label": "API",
        },
        headers={"Authorization": f"Bearer {token.token}"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["item"]["normalized_domain"] == "example.com"
    assert payload["item"]["monitoring_status"] == "active"


def test_external_monitoring_api_rejects_invalid_token(client):
    response = client.get(
        "/api/external/v1/monitoring",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Token invalido."


def test_internal_run_checks_endpoint_requires_valid_secret_token(client, monkeypatch):
    previous_token = os.environ.get("DSC_INTERNAL_RUN_CHECKS_TOKEN")
    os.environ["DSC_INTERNAL_RUN_CHECKS_TOKEN"] = "internal-secret"
    from app.api.routes import internal_monitoring as internal_monitoring_route
    from app.core.config import settings

    settings.__dict__["internal_run_checks_token"] = "internal-secret"
    monkeypatch.setattr(
        internal_monitoring_route.monitoring_service,
        "run_pending_checks",
        lambda: type("Result", (), {"processed": 2, "succeeded": 1, "failed": 1})(),
    )

    unauthorized = client.post("/internal/run-checks")
    authorized = client.post(
        "/internal/run-checks",
        headers={"X-Internal-Token": "internal-secret"},
    )

    if previous_token is None:
        os.environ.pop("DSC_INTERNAL_RUN_CHECKS_TOKEN", None)
        settings.__dict__["internal_run_checks_token"] = None
    else:
        os.environ["DSC_INTERNAL_RUN_CHECKS_TOKEN"] = previous_token
        settings.__dict__["internal_run_checks_token"] = previous_token

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    assert authorized.json()["processed"] == 2
    assert authorized.json()["failed"] == 1


def test_asset_discovery_web_and_api_routes_work_for_authenticated_user(
    client, monkeypatch
):
    runner = _install_stub_discovery_service(monkeypatch)

    client.post(
        "/auth/register",
        data={"email": "discovery-owner@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    web_response = client.post(
        "/discovery/runs",
        data={"domain": "example.com"},
        follow_redirects=True,
    )

    assert web_response.status_code == 200
    assert "api.example.com" in web_response.text
    assert "mail.example.com" in web_response.text

    api_response = client.get("/api/v1/discovery")

    assert api_response.status_code == 200
    assert api_response.json()[0]["normalized_domain"] == "example.com"
    assert runner.calls == ["example.com"]


def test_web_and_api_analysis_routes_are_sync():
    assert inspect.iscoroutinefunction(web_route.analyze_from_form) is False
    assert inspect.iscoroutinefunction(analysis_route.analyze) is False
    assert inspect.iscoroutinefunction(history_route.get_history) is False
