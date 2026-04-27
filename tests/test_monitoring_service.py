from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.exceptions import AuthorizationError, InputValidationError
from app.db.base import Base
from app.db.models import AlertEvent, MonitoredDomain, MonitoringRun
from app.schemas.analysis import (
    AnalysisChecks,
    AnalysisPerformance,
    AnalysisResponse,
    DKIMCheckResult,
    DMARCCheckResult,
    DomainRegistrationResult,
    EmailTLSResult,
    IPIntelligenceResult,
    MXCheckResult,
    NormalizedTarget,
    SPFCheckResult,
    ScoreBreakdown,
    WebsiteTLSResult,
)
from app.schemas.history import AnalysisDiffSummary
from app.services.auth_service import AuthenticationService
from app.services.email_delivery_service import EmailDeliveryService
from app.services.monitoring_schedule_service import MonitoringScheduleService
from app.services.notification_email_service import NotificationEmailService
from app.services.monitoring_service import MonitoringService


def _build_response(
    *,
    domain: str,
    score: int,
    severity: str,
    spf_status: str = "presente",
    spf_posture: str = "restritivo",
    dkim_status: str = "provavelmente_presente",
    dmarc_status: str = "presente",
    dmarc_policy: str | None = "reject",
    website_tls_active: bool = True,
    website_tls_valid: bool | None = True,
    registration_expiry_status: str = "ok",
    findings: list[tuple[str, str, str, str]] | None = None,
) -> AnalysisResponse:
    findings_payload = findings or []
    from app.schemas.analysis import Finding, Recommendation

    return AnalysisResponse(
        normalized=NormalizedTarget(
            original=domain,
            normalized_input=domain,
            target_type="domain",
            analysis_domain=domain,
        ),
        score=score,
        severity=severity,
        summary=f"Resumo de {domain}.",
        checks=AnalysisChecks(
            mx=MXCheckResult(
                checked_name=domain,
                status="presente",
                message="MX publicado.",
                accepts_mail=True,
                is_null_mx=False,
                records=[],
            ),
            spf=SPFCheckResult(
                checked_name=domain,
                status=spf_status,
                message="SPF analisado.",
                posture=spf_posture,
                final_all="-all" if spf_status == "presente" else None,
            ),
            dkim=DKIMCheckResult(
                checked_name=domain,
                status=dkim_status,
                message="DKIM analisado.",
                confidence_note="Heuristica aplicada.",
            ),
            dmarc=DMARCCheckResult(
                checked_name=f"_dmarc.{domain}",
                status=dmarc_status,
                message="DMARC analisado.",
                policy=dmarc_policy,
                policy_strength="forte" if dmarc_policy == "reject" else "fraco",
            ),
        ),
        website_tls=WebsiteTLSResult(
            ssl_active=website_tls_active,
            certificate_valid=website_tls_valid,
            expiry_status="ok",
            message="TLS do website analisado.",
        ),
        email_tls=EmailTLSResult(
            mx_results=[],
            has_email_tls_data=True,
            message="TLS de e-mail analisado.",
            note="O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal.",
        ),
        domain_registration=DomainRegistrationResult(
            rdap_available=True,
            expiry_status=registration_expiry_status,
            days_to_expire=10
            if registration_expiry_status == "proximo_expiracao"
            else 180,
            message="Registro analisado.",
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
            spf_score=95,
            dkim_score=75,
            dmarc_score=95,
            consistency_score=90,
        ),
        performance=AnalysisPerformance(
            total_ms=10,
            normalize_ms=1,
            mx_ms=1,
            spf_ms=1,
            dmarc_ms=1,
            dkim_ms=1,
            website_tls_ms=1,
            email_tls_ms=1,
            rdap_ms=1,
            cache_hit=False,
        ),
        changes=AnalysisDiffSummary(
            has_previous_snapshot=False,
            message="Primeira analise.",
            current_score=score,
            current_severity=severity,
        ),
        findings=[
            Finding(category=category, severity=level, title=title, detail=detail)
            for category, level, title, detail in findings_payload
        ],
        recommendations=[
            Recommendation(
                category="consistencia",
                priority="baixa",
                title="Manter acompanhamento",
                action="Continuar monitorando.",
                rationale="Cobertura basica.",
            )
        ],
        notes=["Nota de teste."],
    )


class StubMonitoringAnalysisService:
    def __init__(self, responses: list[AnalysisResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, bool]] = []

    def analyze_target(
        self, target: str, *, force_refresh: bool = False
    ) -> AnalysisResponse:
        self.calls.append((target, force_refresh))
        return self.responses.pop(0)


class StubMonitoringHistoryService:
    def __init__(self) -> None:
        self.next_id = 1

    def get_latest_snapshot_for_domain(self, domain: str):
        current_id = self.next_id
        self.next_id += 1
        return SimpleNamespace(id=current_id)


def _build_services():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
    )
    Base.metadata.create_all(bind=engine)
    auth_service = AuthenticationService(session_factory=TestingSessionLocal)
    return TestingSessionLocal, auth_service


class FailingEmailSender:
    provider_name = "smtp"

    def send(self, message):
        from app.services.email_delivery_service import EmailSendResult

        return EmailSendResult(
            attempted=True,
            delivered=False,
            provider=self.provider_name,
            error="SMTP offline",
        )


class SuccessfulEmailSender:
    provider_name = "smtp"

    def send(self, message):
        from app.services.email_delivery_service import EmailSendResult

        return EmailSendResult(
            attempted=True,
            delivered=True,
            provider=self.provider_name,
        )


def test_monitoring_schedule_calculates_next_runs():
    service = MonitoringScheduleService()
    base = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)

    assert service.calculate_next_run_at(
        "daily", reference_time=base
    ) == base + timedelta(days=1)
    assert service.calculate_next_run_at(
        "weekly", reference_time=base
    ) == base + timedelta(days=7)
    assert service.calculate_next_run_at(
        "monthly",
        reference_time=datetime(2026, 1, 31, 12, 0, tzinfo=UTC),
    ) == datetime(2026, 2, 28, 12, 0, tzinfo=UTC)


def test_monitoring_service_creates_monitored_domain():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    service = MonitoringService(session_factory=session_factory)

    created = service.create_monitored_domain(
        user_id=user.id,
        domain="Admin@Example.com",
        monitoring_frequency="weekly",
        input_label="Dominio principal",
    )

    assert created.normalized_domain == "example.com"
    assert created.monitoring_frequency == "weekly"
    assert created.open_alert_count == 0
    assert created.monitoring_status == "active"


def test_monitoring_service_runs_due_domain_and_generates_base_alerts():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    analysis_service = StubMonitoringAnalysisService(
        [
            _build_response(
                domain="example.com",
                score=40,
                severity="alto",
                spf_status="ausente",
                dmarc_status="ausente",
                dmarc_policy=None,
                registration_expiry_status="proximo_expiracao",
            )
        ]
    )
    service = MonitoringService(
        session_factory=session_factory,
        analysis_service=analysis_service,
        analysis_history_service=StubMonitoringHistoryService(),
    )
    service.create_monitored_domain(
        user_id=user.id, domain="example.com", monitoring_frequency="daily"
    )

    processed = service.run_due_monitors()

    assert processed == 1
    assert analysis_service.calls == [("example.com", True)]
    with session_factory() as db:
        run = db.scalar(select(MonitoringRun))
        domain = db.scalar(select(MonitoredDomain))
        alerts = db.scalars(
            select(AlertEvent).order_by(AlertEvent.alert_type.asc())
        ).all()

    assert run is not None
    assert run.run_status == "success"
    assert domain is not None
    assert domain.last_status == "success"
    assert domain.next_run_at > domain.last_run_at
    assert {alert.alert_type for alert in alerts} >= {
        "dmarc_missing",
        "spf_missing",
        "domain_expiry_risk",
    }


def test_monitoring_service_generates_diff_based_alerts():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    analysis_service = StubMonitoringAnalysisService(
        [
            _build_response(domain="example.com", score=95, severity="excelente"),
            _build_response(
                domain="example.com",
                score=60,
                severity="atencao",
                dmarc_policy="none",
                findings=[
                    ("spf", "critico", "SPF permissivo demais", "Novo risco critico.")
                ],
            ),
        ]
    )
    service = MonitoringService(
        session_factory=session_factory,
        analysis_service=analysis_service,
        analysis_history_service=StubMonitoringHistoryService(),
    )
    created = service.create_monitored_domain(
        user_id=user.id, domain="example.com", monitoring_frequency="daily"
    )

    assert service.run_due_monitors() == 1
    with session_factory() as db:
        monitored_domain = db.get(MonitoredDomain, created.id)
        monitored_domain.next_run_at = datetime.now(tz=UTC) - timedelta(minutes=1)
        db.commit()

    assert service.run_due_monitors() == 1
    with session_factory() as db:
        alerts = db.scalars(select(AlertEvent).where(AlertEvent.status == "open")).all()

    alert_types = {alert.alert_type for alert in alerts}
    assert "dmarc_regressed" in alert_types
    assert "score_drop" in alert_types
    assert "severity_worsened" in alert_types
    assert "critical_email_auth_finding" in alert_types


def test_monitoring_service_can_pause_resume_and_delete_domains():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    service = MonitoringService(session_factory=session_factory)
    created = service.create_monitored_domain(
        user_id=user.id, domain="example.com", monitoring_frequency="daily"
    )

    paused = service.pause_monitored_domain(
        user_id=user.id, monitored_domain_id=created.id
    )
    resumed = service.resume_monitored_domain(
        user_id=user.id, monitored_domain_id=created.id
    )
    deleted = service.delete_monitored_domain(
        user_id=user.id, monitored_domain_id=created.id
    )

    assert paused.monitoring_status == "paused"
    assert paused.is_active is False
    assert resumed.monitoring_status == "active"
    assert resumed.is_active is True
    assert deleted.monitoring_status == "deleted"
    assert deleted.is_active is False


def test_monitoring_service_retries_in_15_minutes_without_losing_last_valid_state():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    analysis_service = StubMonitoringAnalysisService(
        [
            _build_response(domain="example.com", score=88, severity="bom"),
        ]
    )

    class FailingAnalysisService:
        def __init__(self) -> None:
            self.calls: list[tuple[str, bool]] = []

        def analyze_target(self, target: str, *, force_refresh: bool = False):
            self.calls.append((target, force_refresh))
            raise RuntimeError("dns timeout")

    service = MonitoringService(
        session_factory=session_factory,
        analysis_service=analysis_service,
        analysis_history_service=StubMonitoringHistoryService(),
    )
    created = service.create_monitored_domain(
        user_id=user.id, domain="example.com", monitoring_frequency="daily"
    )
    assert service.run_due_monitors() == 1

    failing = FailingAnalysisService()
    service.analysis_service = failing
    with session_factory() as db:
        monitored_domain = db.get(MonitoredDomain, created.id)
        monitored_domain.next_check_at = datetime.now(tz=UTC) - timedelta(minutes=1)
        monitored_domain.next_run_at = monitored_domain.next_check_at
        last_valid_run_at = monitored_domain.last_run_at
        db.commit()

    assert service.run_due_monitors() == 1

    with session_factory() as db:
        monitored_domain = db.get(MonitoredDomain, created.id)
        runs = db.scalars(
            select(MonitoringRun)
            .where(MonitoringRun.monitored_domain_id == created.id)
            .order_by(MonitoringRun.id.asc())
        ).all()

    assert failing.calls == [("example.com", True)]
    assert monitored_domain is not None
    assert monitored_domain.last_run_at == last_valid_run_at
    assert monitored_domain.last_status == "success"
    assert runs[-1].run_status == "error"
    retry_delta = monitored_domain.next_check_at - runs[-1].completed_at
    assert 14 * 60 <= retry_delta.total_seconds() <= 16 * 60


def test_monitoring_service_deduplicates_repeated_alert_reasons():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    analysis_service = StubMonitoringAnalysisService(
        [
            _build_response(
                domain="example.com",
                score=40,
                severity="alto",
                spf_status="ausente",
                dmarc_status="ausente",
                dmarc_policy=None,
            ),
            _build_response(
                domain="example.com",
                score=39,
                severity="alto",
                spf_status="ausente",
                dmarc_status="ausente",
                dmarc_policy=None,
            ),
        ]
    )
    service = MonitoringService(
        session_factory=session_factory,
        analysis_service=analysis_service,
        analysis_history_service=StubMonitoringHistoryService(),
        notification_service=NotificationEmailService(
            email_delivery_service=EmailDeliveryService(sender=SuccessfulEmailSender())
        ),
    )
    created = service.create_monitored_domain(
        user_id=user.id, domain="example.com", monitoring_frequency="daily"
    )

    assert service.run_due_monitors() == 1
    with session_factory() as db:
        monitored_domain = db.get(MonitoredDomain, created.id)
        first_reason = monitored_domain.last_alert_reason
        first_sent_at = monitored_domain.last_alert_sent_at
        monitored_domain.next_check_at = datetime.now(tz=UTC) - timedelta(minutes=1)
        monitored_domain.next_run_at = monitored_domain.next_check_at
        db.commit()

    assert service.run_due_monitors() == 1

    with session_factory() as db:
        monitored_domain = db.get(MonitoredDomain, created.id)
        open_alerts = db.scalars(
            select(AlertEvent).where(
                AlertEvent.monitored_domain_id == created.id,
                AlertEvent.status == "open",
            )
        ).all()

    assert monitored_domain is not None
    assert monitored_domain.last_alert_reason == first_reason
    assert monitored_domain.last_alert_sent_at == first_sent_at
    assert open_alerts
    assert all(
        alert.email_delivery_status in {"sent", "skipped"} for alert in open_alerts
    )


def test_standard_plan_rejects_sub_hour_intervals_and_plus_allows_manual_run():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    service = MonitoringService(session_factory=session_factory)

    try:
        service.create_monitored_domain(
            user_id=user.id,
            domain="example.com",
            check_interval_minutes=60,
            plan="standard",
        )
    except InputValidationError:
        rejected = True
    else:
        rejected = False

    created = service.create_monitored_domain(
        user_id=user.id,
        domain="example.org",
        check_interval_minutes=60,
        plan="plus",
        alert_contacts=["sec@example.org", "ops@example.org"],
    )

    assert rejected is True
    assert created.plan == "plus"
    assert created.check_interval_minutes == 60
    assert created.alert_contacts == ["sec@example.org", "ops@example.org"]


def test_run_check_now_requires_plus_plan():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    analysis_service = StubMonitoringAnalysisService(
        [_build_response(domain="example.org", score=91, severity="bom")]
    )
    service = MonitoringService(
        session_factory=session_factory,
        analysis_service=analysis_service,
        analysis_history_service=StubMonitoringHistoryService(),
    )
    standard = service.create_monitored_domain(
        user_id=user.id,
        domain="example.com",
        monitoring_frequency="daily",
    )
    plus = service.create_monitored_domain(
        user_id=user.id,
        domain="example.org",
        check_interval_minutes=60,
        plan="plus",
    )

    try:
        service.run_check_now(user_id=user.id, monitored_domain_id=standard.id)
    except AuthorizationError:
        blocked = True
    else:
        blocked = False

    run = service.run_check_now(user_id=user.id, monitored_domain_id=plus.id)

    assert blocked is True
    assert run.trigger_type == "manual"
    assert run.run_status == "success"


def test_scheduler_ignores_paused_monitoring():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    analysis_service = StubMonitoringAnalysisService(
        [_build_response(domain="example.com", score=90, severity="bom")]
    )
    service = MonitoringService(
        session_factory=session_factory,
        analysis_service=analysis_service,
        analysis_history_service=StubMonitoringHistoryService(),
    )
    created = service.create_monitored_domain(
        user_id=user.id, domain="example.com", monitoring_frequency="daily"
    )
    service.pause_monitored_domain(user_id=user.id, monitored_domain_id=created.id)

    processed = service.run_due_monitors()

    assert processed == 0
    assert analysis_service.calls == []


def test_monitoring_email_alert_failure_does_not_break_execution():
    session_factory, auth_service = _build_services()
    user = auth_service.register_user("owner@example.com", "supersecret")
    analysis_service = StubMonitoringAnalysisService(
        [
            _build_response(
                domain="example.com",
                score=40,
                severity="alto",
                spf_status="ausente",
                dmarc_status="ausente",
                dmarc_policy=None,
            )
        ]
    )
    notification_service = NotificationEmailService(
        email_delivery_service=EmailDeliveryService(sender=FailingEmailSender())
    )
    service = MonitoringService(
        session_factory=session_factory,
        analysis_service=analysis_service,
        analysis_history_service=StubMonitoringHistoryService(),
        notification_service=notification_service,
    )
    service.create_monitored_domain(
        user_id=user.id, domain="example.com", monitoring_frequency="daily"
    )

    processed = service.run_due_monitors()

    assert processed == 1
    with session_factory() as db:
        alerts = db.scalars(select(AlertEvent).where(AlertEvent.status == "open")).all()
    assert alerts
    assert all(alert.email_delivery_status == "failed" for alert in alerts)
