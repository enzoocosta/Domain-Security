from datetime import UTC, datetime, timedelta
import inspect

from app.api.routes import analysis as analysis_route
from app.api.routes import history as history_route
from app.api.routes import web as web_route
from app.core.exceptions import DNSDomainNotFoundError
from app.schemas.analysis import DomainRegistrationResult, EmailTLSMXResult, EmailTLSResult, WebsiteTLSResult
from app.schemas.history import DomainHistoryResponse, HistoryItem
from app.services.analysis_service import DomainAnalysisService
from app.services.dns_service import MXRecordValue
from tests.fakes import (
    StubAnalysisHistoryService,
    StubDNSService,
    StubDomainRegistrationService,
    StubEmailTLSService,
    StubWebsiteTLSService,
)


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
        rdap_available=True,
        created_at=now - timedelta(days=400),
        expires_at=now + timedelta(days=150),
        days_to_expire=150,
        expiry_status="ok",
        registrar="Example Registrar",
        status=["active"],
        message="Dados RDAP obtidos com datas de criacao e expiracao.",
        source="RDAP",
    )


def _install_stub_service(
    monkeypatch,
    dns_service: StubDNSService,
    *,
    email_tls_result: EmailTLSResult | None = None,
    history_response: DomainHistoryResponse | None = None,
) -> None:
    history_service = StubAnalysisHistoryService(history_response=history_response)
    service = DomainAnalysisService(
        dns_service=dns_service,
        website_tls_service=StubWebsiteTLSService(_website_tls_result()),
        email_tls_service=StubEmailTLSService(email_tls_result or _email_tls_result()),
        domain_registration_service=StubDomainRegistrationService(_registration_result()),
        history_service=history_service,
    )
    monkeypatch.setattr(analysis_route, "service", service)
    monkeypatch.setattr(web_route, "service", service)
    monkeypatch.setattr(web_route, "history_service", history_service)
    monkeypatch.setattr(history_route, "service", history_service)


def test_healthcheck(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_home_page_renders(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "Domain Security Checker" in response.text


def test_analysis_endpoint_returns_payload_with_tls_and_registration(client, monkeypatch):
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_records=[MXRecordValue(preference=10, exchange="mail.example.com")],
            txt_records={
                "example.com": ["v=spf1 include:_spf.example.net -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
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
    assert payload["domain_registration"]["rdap_available"] is True
    assert payload["changes"]["has_previous_snapshot"] is False
    assert payload["performance"]["cache_hit"] is False
    assert payload["performance"]["total_ms"] >= 0
    assert payload["score"] >= 80
    assert payload["severity"] in {"bom", "excelente"}
    assert any(item["category"] == "tls_site" for item in payload["findings"])


def test_analysis_endpoint_returns_404_for_nonexistent_domain(client, monkeypatch):
    _install_stub_service(
        monkeypatch,
        StubDNSService(
            mx_exception=DNSDomainNotFoundError("O dominio 'inexistente.invalid' nao foi encontrado no DNS."),
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
    assert "Resultado da analise" in response.text
    assert "TLS do website" in response.text
    assert "Seguranca de transporte de e-mail" in response.text
    assert "Registro do dominio" in response.text
    assert "Detalhamento do score" in response.text
    assert "Mudancas desde a ultima analise" in response.text
    assert "Recomendacoes" in response.text


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
    assert "Nao foi possivel obter informacoes de TLS/SSL dos registros MX do dominio example.com." in response.text
    assert "O certificado de e-mail pertence ao servidor MX" not in response.text
    assert "porta 25" not in response.text
    assert "Timeout ao testar STARTTLS" not in response.text


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
    assert "Historico de analises" in response.text
    assert "Resumo da analise salva." in response.text


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
    assert "daily" in dashboard_response.text

    logout_response = client.post("/auth/logout", follow_redirects=True)
    assert logout_response.status_code == 200
    assert "Diagnostico para seguranca de dominio" in logout_response.text

    login_response = client.post(
        "/auth/login",
        data={"email": "owner@example.com", "password": "supersecret"},
        follow_redirects=True,
    )

    assert login_response.status_code == 200
    assert "Monitoramento autenticado" in login_response.text


def test_web_and_api_analysis_routes_are_sync():
    assert inspect.iscoroutinefunction(web_route.analyze_from_form) is False
    assert inspect.iscoroutinefunction(analysis_route.analyze) is False
    assert inspect.iscoroutinefunction(history_route.get_history) is False
