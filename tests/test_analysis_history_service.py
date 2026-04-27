from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.schemas.analysis import (
    AnalysisChecks,
    AnalysisPerformance,
    AnalysisResponse,
    DKIMCheckResult,
    DMARCCheckResult,
    DomainRegistrationResult,
    EmailTLSResult,
    Finding,
    IPIntelligenceResult,
    MXCheckResult,
    NormalizedTarget,
    Recommendation,
    SPFCheckResult,
    ScoreBreakdown,
    WebsiteTLSResult,
)
from app.schemas.history import AnalysisDiffSummary
from app.services.analysis_history_service import AnalysisHistoryService


def _build_response(
    *,
    domain: str,
    score: int,
    severity: str,
    spf_posture: str,
    dkim_status: str,
    dmarc_policy: str | None,
    dmarc_strength: str,
    website_tls_active: bool,
    email_tls_data: bool,
    registration_expiry_status: str,
    registration_days_to_expire: int | None,
    findings: list[str],
) -> AnalysisResponse:
    return AnalysisResponse(
        normalized=NormalizedTarget(
            original=domain,
            normalized_input=domain,
            target_type="domain",
            analysis_domain=domain,
        ),
        score=score,
        severity=severity,
        summary=f"Resumo para {domain}.",
        checks=AnalysisChecks(
            mx=MXCheckResult(
                checked_name=domain,
                status="presente",
                message="O dominio publica registros MX.",
                accepts_mail=True,
                is_null_mx=False,
            ),
            spf=SPFCheckResult(
                checked_name=domain,
                status="presente",
                message="SPF encontrado.",
                final_all="-all",
                posture=spf_posture,
            ),
            dkim=DKIMCheckResult(
                checked_name=domain,
                status=dkim_status,
                message="DKIM analisado.",
                confidence_note="Heuristica aplicada.",
            ),
            dmarc=DMARCCheckResult(
                checked_name=f"_dmarc.{domain}",
                status="presente",
                message="DMARC encontrado.",
                policy=dmarc_policy,
                policy_strength=dmarc_strength,
            ),
        ),
        website_tls=WebsiteTLSResult(
            ssl_active=website_tls_active,
            message="TLS do website analisado.",
        ),
        email_tls=EmailTLSResult(
            mx_results=[],
            has_email_tls_data=email_tls_data,
            message="TLS de e-mail analisado.",
            note="O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal.",
        ),
        domain_registration=DomainRegistrationResult(
            rdap_available=True,
            days_to_expire=registration_days_to_expire,
            expiry_status=registration_expiry_status,
            message="Registro do dominio analisado.",
            source="RDAP",
        ),
        ip_intelligence=IPIntelligenceResult(
            primary_ip="93.184.216.34",
            ip_version="ipv4",
            is_public=True,
            has_public_ip=True,
            message="O IP publico principal observado para o website foi 93.184.216.34.",
        ),
        score_breakdown=ScoreBreakdown(
            dns_score=100,
            mx_score=100,
            spf_score=90,
            dkim_score=75,
            dmarc_score=90,
            consistency_score=85,
        ),
        performance=AnalysisPerformance(
            total_ms=5,
            normalize_ms=1,
            mx_ms=1,
            spf_ms=1,
            dmarc_ms=1,
            dkim_ms=1,
            website_tls_ms=0,
            email_tls_ms=0,
            rdap_ms=0,
            cache_hit=False,
        ),
        changes=AnalysisDiffSummary(
            has_previous_snapshot=False,
            message="Esta e a primeira analise salva para este dominio.",
            current_score=score,
            current_severity=severity,
        ),
        findings=[
            Finding(
                category="spf", severity="medio", title=item, detail=f"Detalhe {item}."
            )
            for item in findings
        ],
        recommendations=[
            Recommendation(
                category="spf",
                priority="media",
                title="Recomendacao",
                action="Ajustar postura.",
                rationale="Mantem a consistencia.",
            )
        ],
        notes=["Nota de teste."],
    )


def _build_service() -> AnalysisHistoryService:
    from app.db import models  # noqa: F401

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
    )
    Base.metadata.create_all(bind=engine)
    return AnalysisHistoryService(session_factory=TestingSessionLocal)


def test_history_service_creates_tracked_domain_and_snapshot():
    service = _build_service()

    result = service.record_analysis(
        _build_response(
            domain="example.com",
            score=82,
            severity="bom",
            spf_posture="restritivo",
            dkim_status="provavelmente_presente",
            dmarc_policy="reject",
            dmarc_strength="forte",
            website_tls_active=True,
            email_tls_data=True,
            registration_expiry_status="ok",
            registration_days_to_expire=100,
            findings=["SPF restritivo"],
        ),
        input_target="example.com",
    )

    history = service.list_history("example.com")

    assert result.changes.has_previous_snapshot is False
    assert len(history.items) == 1
    assert history.items[0].analysis_domain == "example.com"
    assert history.items[0].score == 82


def test_history_service_get_or_create_reuses_domain():
    service = _build_service()

    with service.session_factory() as db:
        first = service.get_or_create_tracked_domain(db, "example.com")
        second = service.get_or_create_tracked_domain(db, "example.com")
        db.commit()

    assert first.id == second.id


def test_history_service_lists_latest_first():
    service = _build_service()
    first = _build_response(
        domain="example.com",
        score=70,
        severity="atencao",
        spf_posture="permissivo",
        dkim_status="desconhecido",
        dmarc_policy="none",
        dmarc_strength="fraco",
        website_tls_active=True,
        email_tls_data=False,
        registration_expiry_status="ok",
        registration_days_to_expire=120,
        findings=["Primeiro achado"],
    )
    second = _build_response(
        domain="example.com",
        score=80,
        severity="bom",
        spf_posture="restritivo",
        dkim_status="provavelmente_presente",
        dmarc_policy="reject",
        dmarc_strength="forte",
        website_tls_active=True,
        email_tls_data=True,
        registration_expiry_status="ok",
        registration_days_to_expire=150,
        findings=["Segundo achado"],
    )

    service.record_analysis(first, input_target="example.com")
    service.record_analysis(second, input_target="example.com")
    history = service.list_history("example.com")

    assert len(history.items) == 2
    assert history.items[0].score == 80
    assert history.items[1].score == 70


def test_history_service_generates_diff_with_changed_checks_and_findings():
    service = _build_service()
    service.record_analysis(
        _build_response(
            domain="example.com",
            score=85,
            severity="bom",
            spf_posture="restritivo",
            dkim_status="provavelmente_presente",
            dmarc_policy="reject",
            dmarc_strength="forte",
            website_tls_active=True,
            email_tls_data=True,
            registration_expiry_status="ok",
            registration_days_to_expire=120,
            findings=["Achado antigo", "Achado comum"],
        ),
        input_target="example.com",
    )

    updated = service.record_analysis(
        _build_response(
            domain="example.com",
            score=60,
            severity="atencao",
            spf_posture="permissivo",
            dkim_status="desconhecido",
            dmarc_policy="none",
            dmarc_strength="fraco",
            website_tls_active=False,
            email_tls_data=False,
            registration_expiry_status="proximo_expiracao",
            registration_days_to_expire=10,
            findings=["Achado comum", "Achado novo"],
        ),
        input_target="example.com",
    )

    assert updated.changes.has_previous_snapshot is True
    assert updated.changes.score_delta == -25
    assert updated.changes.severity_changed is True
    labels = {item.label for item in updated.changes.changed_checks}
    assert "Postura SPF" in labels
    assert "Status DKIM" in labels
    assert "TLS do website" in labels
    assert "Dados uteis de TLS de e-mail" in labels
    assert "Achado novo: Detalhe Achado novo." in updated.changes.added_findings
    assert "Achado antigo: Detalhe Achado antigo." in updated.changes.removed_findings


def test_history_service_returns_empty_history_for_unknown_domain():
    service = _build_service()

    history = service.list_history("unknown.example")

    assert history.domain == "unknown.example"
    assert history.items == []
