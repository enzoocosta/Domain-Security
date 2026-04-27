from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parseaddr

from pydantic import ValidationError
from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AuthorizationError,
    InputValidationError,
    ResourceConflictError,
)
from app.db.models import AlertEvent, MonitoredDomain, MonitoringRun, User
from app.db.session import SessionLocal
from app.schemas.analysis import AnalysisResponse
from app.schemas.monitoring import (
    AlertEventSummary,
    MonitoredDomainSummary,
    MonitoringDomainCreateInput,
    MonitoringDomainDetailResponse,
    MonitoringPlan,
    MonitoringRunSummary,
    MonitoringScorePoint,
    MonitoringStatus,
)
from app.services.analysis_history_service import AnalysisHistoryService
from app.services.analysis_service import DomainAnalysisService
from app.services.alert_service import check_and_fire_alerts
from app.services.monitoring_alert_service import MonitoringAlertService
from app.services.monitoring_schedule_service import MonitoringScheduleService
from app.services.notification_email_service import NotificationEmailService
from app.utils.input_parser import normalize_target


@dataclass(frozen=True)
class MonitoringBatchResult:
    processed: int
    succeeded: int
    failed: int


_UNSET = object()


class MonitoringService:
    """Owns monitored domains, recurring runs and alert generation."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session] | None = None,
        analysis_service: DomainAnalysisService | None = None,
        analysis_history_service: AnalysisHistoryService | None = None,
        schedule_service: MonitoringScheduleService | None = None,
        alert_service: MonitoringAlertService | None = None,
        notification_service: NotificationEmailService | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal
        self.analysis_service = analysis_service or DomainAnalysisService()
        self.analysis_history_service = (
            analysis_history_service
            or AnalysisHistoryService(session_factory=self.session_factory)
        )
        self.schedule_service = schedule_service or MonitoringScheduleService()
        self.alert_service = alert_service or MonitoringAlertService()
        self.notification_service = notification_service or NotificationEmailService()

    def create_monitored_domain(
        self,
        *,
        user_id: int,
        domain: str,
        monitoring_frequency: str | None = None,
        check_interval_minutes: int | None = None,
        input_label: str | None = None,
        plan: MonitoringPlan = "standard",
        alert_contacts: str | Iterable[str] | None = None,
    ) -> MonitoredDomainSummary:
        normalized_contacts = self._normalize_alert_contacts(alert_contacts)
        try:
            payload = MonitoringDomainCreateInput(
                domain=domain,
                monitoring_frequency=monitoring_frequency,
                check_interval_minutes=check_interval_minutes,
                input_label=input_label,
                plan=plan,
                alert_contacts=normalized_contacts,
            )
        except ValidationError as exc:
            raise InputValidationError(str(exc.errors()[0]["msg"])) from exc

        normalized_domain = normalize_target(payload.domain).analysis_domain
        interval_minutes = self._resolve_interval(
            payload.plan, payload.monitoring_frequency, payload.check_interval_minutes
        )
        effective_contacts = self._sanitize_contacts_for_plan(
            payload.plan, payload.alert_contacts
        )
        current_time = self._utcnow()

        with self.session_factory() as db:
            user = self._require_user(db, user_id)
            existing = self._get_monitored_domain_by_domain(
                db, user.id, normalized_domain
            )
            if existing is not None:
                if existing.monitoring_status == "deleted":
                    self._apply_domain_configuration(
                        existing,
                        plan=payload.plan,
                        input_label=payload.input_label,
                        interval_minutes=interval_minutes,
                        alert_contacts=effective_contacts,
                        next_check_at=current_time,
                    )
                    existing.is_active = True
                    existing.monitoring_status = "active"
                    existing.paused_at = None
                    existing.deleted_at = None
                    existing.last_status = "agendado"
                    existing.updated_at = current_time
                    db.commit()
                    db.refresh(existing)
                    return self._to_monitored_domain_summary(db, existing)
                raise ResourceConflictError(
                    "Este dominio ja esta cadastrado no monitoramento."
                )

            monitored_domain = MonitoredDomain(
                user_id=user.id,
                normalized_domain=normalized_domain,
                input_label=payload.input_label,
                monitoring_frequency=self.schedule_service.frequency_label_for_interval(
                    interval_minutes
                ),
                plan=payload.plan,
                check_interval_minutes=interval_minutes,
                is_active=True,
                monitoring_status="active",
                paused_at=None,
                deleted_at=None,
                next_check_at=current_time,
                next_run_at=current_time,
                last_status="agendado",
                alert_contacts=effective_contacts,
                created_at=current_time,
                updated_at=current_time,
            )
            db.add(monitored_domain)
            db.commit()
            db.refresh(monitored_domain)
            return self._to_monitored_domain_summary(db, monitored_domain)

    def update_monitored_domain_configuration(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
        plan: MonitoringPlan | None = None,
        monitoring_frequency: str | None = None,
        check_interval_minutes: int | None = None,
        input_label: str | None | object = _UNSET,
        alert_contacts: str | Iterable[str] | None | object = _UNSET,
    ) -> MonitoredDomainSummary:
        with self.session_factory() as db:
            monitored_domain = self._get_monitored_domain_for_user(
                db,
                user_id,
                monitored_domain_id,
                allow_deleted=False,
            )
            current_plan = plan or monitored_domain.plan
            if monitoring_frequency is not None or check_interval_minutes is not None:
                interval_minutes = self._resolve_interval(
                    current_plan, monitoring_frequency, check_interval_minutes
                )
            else:
                minimum_interval = self.schedule_service.minimum_interval_for_plan(
                    current_plan
                )
                interval_minutes = max(
                    monitored_domain.check_interval_minutes, minimum_interval
                )
            contacts = (
                self._sanitize_contacts_for_plan(
                    current_plan, self._normalize_alert_contacts(alert_contacts)
                )
                if alert_contacts is not _UNSET
                else self._sanitize_contacts_for_plan(
                    current_plan, monitored_domain.alert_contacts or []
                )
            )
            next_check_at = monitored_domain.next_check_at
            if (
                monitored_domain.monitoring_status == "active"
                and self._ensure_aware(next_check_at) < self._utcnow()
            ):
                next_check_at = self._utcnow()
            self._apply_domain_configuration(
                monitored_domain,
                plan=current_plan,
                input_label=monitored_domain.input_label
                if input_label is _UNSET
                else input_label,
                interval_minutes=interval_minutes,
                alert_contacts=contacts,
                next_check_at=next_check_at,
            )
            monitored_domain.updated_at = self._utcnow()
            db.commit()
            db.refresh(monitored_domain)
            return self._to_monitored_domain_summary(db, monitored_domain)

    def list_monitored_domains(
        self, *, user_id: int, include_deleted: bool = False
    ) -> list[MonitoredDomainSummary]:
        with self.session_factory() as db:
            user = self._require_user(db, user_id)
            stmt = (
                select(MonitoredDomain)
                .where(MonitoredDomain.user_id == user.id)
                .order_by(MonitoredDomain.created_at.desc(), MonitoredDomain.id.desc())
            )
            if not include_deleted:
                stmt = stmt.where(MonitoredDomain.monitoring_status != "deleted")
            domains = db.scalars(stmt).all()
            return [self._to_monitored_domain_summary(db, item) for item in domains]

    def get_dashboard(self, *, user_id: int):
        from app.schemas.monitoring import MonitoringDashboardResponse

        with self.session_factory() as db:
            user = self._require_user(db, user_id)
            domains = db.scalars(
                select(MonitoredDomain)
                .where(MonitoredDomain.user_id == user.id)
                .where(MonitoredDomain.monitoring_status != "deleted")
                .order_by(MonitoredDomain.created_at.desc(), MonitoredDomain.id.desc())
            ).all()
            summaries = [
                self._to_monitored_domain_summary(db, item) for item in domains
            ]
            open_alerts = db.scalars(
                select(AlertEvent)
                .join(
                    MonitoredDomain,
                    AlertEvent.monitored_domain_id == MonitoredDomain.id,
                )
                .where(
                    MonitoredDomain.user_id == user.id,
                    MonitoredDomain.monitoring_status != "deleted",
                    AlertEvent.status == "open",
                )
                .order_by(AlertEvent.created_at.desc(), AlertEvent.id.desc())
            ).all()
            warnings = [
                item.scheduler_warning for item in summaries if item.scheduler_warning
            ]
            scheduler_warning = None
            if warnings:
                scheduler_warning = (
                    "Existem checks atrasados alem da janela esperada. "
                    "O scheduler externo pode estar parado ou atrasado."
                )
            return MonitoringDashboardResponse(
                user_email=user.email,
                monitored_domains=summaries,
                open_alerts=[self._to_alert_summary(item) for item in open_alerts],
                scheduler_warning=scheduler_warning,
            )

    def get_domain_detail(
        self, *, user_id: int, monitored_domain_id: int
    ) -> MonitoringDomainDetailResponse:
        with self.session_factory() as db:
            monitored_domain = self._get_monitored_domain_for_user(
                db,
                user_id,
                monitored_domain_id,
                allow_deleted=False,
            )
            recent_runs = db.scalars(
                select(MonitoringRun)
                .where(MonitoringRun.monitored_domain_id == monitored_domain.id)
                .order_by(MonitoringRun.started_at.desc(), MonitoringRun.id.desc())
                .limit(20)
            ).all()
            open_alerts = db.scalars(
                select(AlertEvent)
                .where(
                    AlertEvent.monitored_domain_id == monitored_domain.id,
                    AlertEvent.status == "open",
                )
                .order_by(AlertEvent.created_at.desc(), AlertEvent.id.desc())
            ).all()
            summary = self._to_monitored_domain_summary(db, monitored_domain)
            scored_runs = [
                run for run in reversed(recent_runs) if run.score is not None
            ][-10:]
            score_history = [
                MonitoringScorePoint(
                    run_id=run.id,
                    score=int(run.score or 0),
                    run_status=run.run_status,
                    recorded_at=run.completed_at or run.started_at,
                )
                for run in scored_runs
            ]
            return MonitoringDomainDetailResponse(
                domain=summary,
                recent_runs=[self._to_run_summary(item) for item in recent_runs],
                open_alerts=[self._to_alert_summary(item) for item in open_alerts],
                score_history=score_history,
                scheduler_warning=summary.scheduler_warning,
            )

    def pause_monitored_domain(
        self, *, user_id: int, monitored_domain_id: int
    ) -> MonitoredDomainSummary:
        return self._set_monitoring_status(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
            target_status="paused",
        )

    def resume_monitored_domain(
        self, *, user_id: int, monitored_domain_id: int
    ) -> MonitoredDomainSummary:
        return self._set_monitoring_status(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
            target_status="active",
        )

    def delete_monitored_domain(
        self, *, user_id: int, monitored_domain_id: int
    ) -> MonitoredDomainSummary:
        return self._set_monitoring_status(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
            target_status="deleted",
        )

    def run_pending_checks(self, *, limit: int = 10) -> MonitoringBatchResult:
        now = self._utcnow()
        processed = 0
        succeeded = 0
        failed = 0
        with self.session_factory() as db:
            due_domains = db.scalars(self._due_domains_query(now).limit(limit)).all()
            for monitored_domain in due_domains:
                run = self._run_monitored_domain(
                    db,
                    monitored_domain,
                    now=now,
                    trigger_type="scheduled",
                )
                processed += 1
                if run.run_status == "error":
                    failed += 1
                else:
                    succeeded += 1
            db.commit()
        return MonitoringBatchResult(
            processed=processed, succeeded=succeeded, failed=failed
        )

    def run_due_monitors(self, *, limit: int = 10) -> int:
        return self.run_pending_checks(limit=limit).processed

    def run_check_now(
        self, *, user_id: int, monitored_domain_id: int
    ) -> MonitoringRunSummary:
        with self.session_factory() as db:
            monitored_domain = self._get_monitored_domain_for_user(
                db,
                user_id,
                monitored_domain_id,
                allow_deleted=False,
            )
            if monitored_domain.plan != "plus":
                raise AuthorizationError(
                    "Check imediato sob demanda esta disponivel apenas no Monitoring Plus."
                )
            if monitored_domain.monitoring_status != "active":
                raise InputValidationError(
                    "Apenas dominios ativos podem executar um check imediato."
                )
            run = self._run_monitored_domain(
                db,
                monitored_domain,
                now=self._utcnow(),
                trigger_type="manual",
            )
            db.commit()
            db.refresh(run)
            return self._to_run_summary(run)

    def _run_monitored_domain(
        self,
        db: Session,
        monitored_domain: MonitoredDomain,
        *,
        now: datetime,
        trigger_type: str,
    ) -> MonitoringRun:
        started_at = now
        previous_run = self._get_latest_scored_run(db, monitored_domain.id)
        previous_result = (
            self._deserialize_analysis(previous_run.snapshot_data)
            if previous_run
            else None
        )
        run = MonitoringRun(
            monitored_domain_id=monitored_domain.id,
            snapshot_data={},
            diff_data={},
            run_status="error",
            trigger_type=trigger_type,
            started_at=started_at,
        )
        db.add(run)
        db.flush()

        try:
            result = self.analysis_service.analyze_target(
                monitored_domain.normalized_domain, force_refresh=True
            )
            latest_snapshot = (
                self.analysis_history_service.get_latest_snapshot_for_domain(
                    monitored_domain.normalized_domain
                )
            )
            finished_at = self._utcnow()
            run.analysis_snapshot_id = (
                latest_snapshot.id if latest_snapshot is not None else None
            )
            run.snapshot_data = result.model_dump(mode="json")
            run.diff_data = result.changes.model_dump(mode="json")
            run.score = result.score
            run.severity = result.severity
            run.run_status = self._classify_run_status(result)
            run.error_message = None
            run.completed_at = finished_at
            run.check_duration_ms = max(
                0, int((finished_at - started_at).total_seconds() * 1000)
            )

            monitored_domain.last_run_at = finished_at
            monitored_domain.next_check_at = (
                self.schedule_service.calculate_next_check_at(
                    monitored_domain.check_interval_minutes,
                    reference_time=finished_at,
                )
            )
            monitored_domain.next_run_at = monitored_domain.next_check_at
            monitored_domain.last_status = run.run_status
            monitored_domain.updated_at = finished_at

            evaluation = self.alert_service.evaluate_alerts(
                result,
                previous_result=previous_result,
                last_alert_reason=monitored_domain.last_alert_reason,
            )
            synced_alerts = self.alert_service.synchronize_alerts(
                db,
                monitored_domain=monitored_domain,
                monitoring_run=run,
                candidates=evaluation.candidates,
            )
            if evaluation.primary_reason is None:
                monitored_domain.last_alert_reason = None
            delivered_alert_ids: list[str] = []
            if evaluation.should_notify:
                delivered_alert_ids = check_and_fire_alerts(
                    db,
                    monitored_domain,
                    run,
                    candidate_ids=[
                        candidate.alert_type for candidate in evaluation.candidates
                    ],
                )
            if delivered_alert_ids:
                delivered_alert_id_set = set(delivered_alert_ids)
                self._prepare_pending_alerts(
                    synced_alerts,
                    allowed_alert_types=delivered_alert_id_set,
                    attempted_at=finished_at,
                )
                dispatch = self.notification_service.deliver_pending_alerts(
                    db,
                    monitored_domain=monitored_domain,
                    monitoring_run=run,
                    analysis_result=result,
                    alert_events=synced_alerts,
                )
                if dispatch.delivered:
                    monitored_domain.last_alert_sent_at = finished_at
                    monitored_domain.last_alert_reason = "|".join(
                        sorted(delivered_alert_id_set)
                    )
            else:
                self._suppress_pending_alerts(synced_alerts, attempted_at=finished_at)
        except Exception as exc:
            finished_at = self._utcnow()
            run.run_status = "error"
            run.error_message = str(exc)
            run.completed_at = finished_at
            run.check_duration_ms = max(
                0, int((finished_at - started_at).total_seconds() * 1000)
            )
            monitored_domain.next_check_at = self.schedule_service.calculate_retry_at(
                reference_time=finished_at
            )
            monitored_domain.next_run_at = monitored_domain.next_check_at
            monitored_domain.updated_at = finished_at

        db.flush()
        return run

    @staticmethod
    def _prepare_pending_alerts(
        alert_events: list[AlertEvent],
        *,
        allowed_alert_types: set[str],
        attempted_at: datetime,
    ) -> None:
        for event in alert_events:
            if event.status != "open":
                continue
            if event.alert_type in allowed_alert_types:
                event.email_delivery_status = "pending"
                event.email_last_attempt_at = None
                event.email_sent_at = None
                event.email_last_error = None
                continue
            if event.email_delivery_status == "pending":
                event.email_delivery_status = "skipped"
                event.email_last_attempt_at = attempted_at
                event.email_last_error = "Suprimido por cooldown."

    @staticmethod
    def _suppress_pending_alerts(
        alert_events: list[AlertEvent], *, attempted_at: datetime
    ) -> None:
        for event in alert_events:
            if event.status != "open" or event.email_delivery_status != "pending":
                continue
            event.email_delivery_status = "skipped"
            event.email_last_attempt_at = attempted_at
            event.email_last_error = "Suprimido por deduplicacao."

    @staticmethod
    def _deserialize_analysis(snapshot_data: dict | None) -> AnalysisResponse | None:
        if not snapshot_data:
            return None
        return AnalysisResponse.model_validate(snapshot_data)

    @staticmethod
    def _classify_run_status(result: AnalysisResponse) -> str:
        if (
            result.checks.mx.lookup_error
            or result.checks.spf.lookup_error
            or result.checks.dmarc.lookup_error
            or result.checks.dkim.lookup_error
            or result.website_tls.error
            or result.domain_registration.error
        ):
            return "partial"
        return "success"

    @staticmethod
    def _due_domains_query(now: datetime) -> Select[tuple[MonitoredDomain]]:
        return (
            select(MonitoredDomain)
            .where(
                MonitoredDomain.is_active.is_(True),
                MonitoredDomain.monitoring_status == "active",
                or_(
                    MonitoredDomain.next_check_at <= now,
                    MonitoredDomain.next_run_at <= now,
                ),
            )
            .order_by(MonitoredDomain.next_check_at.asc(), MonitoredDomain.id.asc())
        )

    @staticmethod
    def _get_latest_completed_run(
        db: Session, monitored_domain_id: int
    ) -> MonitoringRun | None:
        stmt = (
            select(MonitoringRun)
            .where(
                MonitoringRun.monitored_domain_id == monitored_domain_id,
                MonitoringRun.completed_at.is_not(None),
            )
            .order_by(MonitoringRun.completed_at.desc(), MonitoringRun.id.desc())
            .limit(1)
        )
        return db.scalar(stmt)

    @staticmethod
    def _get_latest_scored_run(
        db: Session, monitored_domain_id: int
    ) -> MonitoringRun | None:
        stmt = (
            select(MonitoringRun)
            .where(
                MonitoringRun.monitored_domain_id == monitored_domain_id,
                MonitoringRun.completed_at.is_not(None),
                MonitoringRun.score.is_not(None),
            )
            .order_by(MonitoringRun.completed_at.desc(), MonitoringRun.id.desc())
            .limit(1)
        )
        return db.scalar(stmt)

    @staticmethod
    def _get_monitored_domain_by_domain(
        db: Session, user_id: int, normalized_domain: str
    ) -> MonitoredDomain | None:
        stmt = select(MonitoredDomain).where(
            MonitoredDomain.user_id == user_id,
            MonitoredDomain.normalized_domain == normalized_domain,
        )
        return db.scalar(stmt)

    def _get_monitored_domain_for_user(
        self,
        db: Session,
        user_id: int,
        monitored_domain_id: int,
        *,
        allow_deleted: bool,
    ) -> MonitoredDomain:
        monitored_domain = db.get(MonitoredDomain, monitored_domain_id)
        if monitored_domain is None or monitored_domain.user_id != user_id:
            raise AuthorizationError("Voce nao tem acesso a este dominio monitorado.")
        if not allow_deleted and monitored_domain.monitoring_status == "deleted":
            raise AuthorizationError("Este monitoramento nao esta mais disponivel.")
        return monitored_domain

    def _set_monitoring_status(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
        target_status: MonitoringStatus,
    ) -> MonitoredDomainSummary:
        with self.session_factory() as db:
            monitored_domain = self._get_monitored_domain_for_user(
                db,
                user_id,
                monitored_domain_id,
                allow_deleted=True,
            )
            current_time = self._utcnow()
            if target_status == "paused":
                if monitored_domain.monitoring_status == "deleted":
                    raise AuthorizationError(
                        "Monitoramentos excluidos nao podem ser pausados."
                    )
                monitored_domain.monitoring_status = "paused"
                monitored_domain.is_active = False
                monitored_domain.paused_at = current_time
                monitored_domain.updated_at = current_time
            elif target_status == "active":
                if monitored_domain.monitoring_status == "deleted":
                    raise AuthorizationError(
                        "Monitoramentos excluidos nao podem ser retomados."
                    )
                monitored_domain.monitoring_status = "active"
                monitored_domain.is_active = True
                monitored_domain.paused_at = None
                monitored_domain.deleted_at = None
                monitored_domain.next_check_at = current_time
                monitored_domain.next_run_at = current_time
                monitored_domain.updated_at = current_time
            else:
                monitored_domain.monitoring_status = "deleted"
                monitored_domain.is_active = False
                monitored_domain.deleted_at = current_time
                monitored_domain.updated_at = current_time

            db.commit()
            db.refresh(monitored_domain)
            return self._to_monitored_domain_summary(db, monitored_domain)

    @staticmethod
    def _require_user(db: Session, user_id: int) -> User:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            raise AuthorizationError("Usuario nao autenticado ou inativo.")
        return user

    def _to_monitored_domain_summary(
        self, db: Session, monitored_domain: MonitoredDomain
    ) -> MonitoredDomainSummary:
        latest_run = db.scalar(
            select(MonitoringRun)
            .where(MonitoringRun.monitored_domain_id == monitored_domain.id)
            .order_by(MonitoringRun.started_at.desc(), MonitoringRun.id.desc())
            .limit(1)
        )
        latest_scored_run = db.scalar(
            select(MonitoringRun)
            .where(
                MonitoringRun.monitored_domain_id == monitored_domain.id,
                MonitoringRun.score.is_not(None),
            )
            .order_by(MonitoringRun.started_at.desc(), MonitoringRun.id.desc())
            .limit(1)
        )
        open_alert_count = db.scalar(
            select(func.count(AlertEvent.id)).where(
                AlertEvent.monitored_domain_id == monitored_domain.id,
                AlertEvent.status == "open",
            )
        )
        latest_attempt_at = None
        latest_run_status = None
        if latest_run is not None:
            latest_attempt_at = latest_run.completed_at or latest_run.started_at
            latest_run_status = latest_run.run_status
        next_check_at = monitored_domain.next_check_at or monitored_domain.next_run_at
        return MonitoredDomainSummary(
            id=monitored_domain.id,
            normalized_domain=monitored_domain.normalized_domain,
            input_label=monitored_domain.input_label,
            monitoring_frequency=self.schedule_service.frequency_label_for_interval(
                monitored_domain.check_interval_minutes
            ),
            plan=monitored_domain.plan,
            check_interval_minutes=monitored_domain.check_interval_minutes,
            is_active=monitored_domain.is_active,
            monitoring_status=monitored_domain.monitoring_status,
            paused_at=monitored_domain.paused_at,
            deleted_at=monitored_domain.deleted_at,
            last_run_at=monitored_domain.last_run_at,
            last_attempt_at=latest_attempt_at,
            next_check_at=next_check_at,
            next_run_at=next_check_at,
            last_status=monitored_domain.last_status,
            latest_run_status=latest_run_status,
            latest_score=latest_scored_run.score
            if latest_scored_run is not None
            else None,
            latest_severity=latest_scored_run.severity
            if latest_scored_run is not None
            else None,
            open_alert_count=int(open_alert_count or 0),
            scheduler_warning=self._build_scheduler_warning(monitored_domain),
            last_alert_sent_at=monitored_domain.last_alert_sent_at,
            last_alert_reason=monitored_domain.last_alert_reason,
            alert_contacts=list(monitored_domain.alert_contacts or []),
        )

    @staticmethod
    def _to_alert_summary(alert: AlertEvent) -> AlertEventSummary:
        return AlertEventSummary(
            id=alert.id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            title=alert.title,
            description=alert.description,
            status=alert.status,
            created_at=alert.created_at,
            resolved_at=alert.resolved_at,
        )

    @staticmethod
    def _to_run_summary(run: MonitoringRun) -> MonitoringRunSummary:
        return MonitoringRunSummary(
            id=run.id,
            score=run.score,
            severity=run.severity,
            run_status=run.run_status,
            trigger_type=run.trigger_type,
            error_message=run.error_message,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )

    def _resolve_interval(
        self,
        plan: MonitoringPlan,
        monitoring_frequency: str | None,
        check_interval_minutes: int | None,
    ) -> int:
        try:
            interval_minutes = self.schedule_service.normalize_interval_minutes(
                monitoring_frequency=monitoring_frequency,
                check_interval_minutes=check_interval_minutes,
            )
            self.schedule_service.validate_interval_for_plan(
                plan=plan,
                check_interval_minutes=interval_minutes,
            )
        except ValueError as exc:
            raise InputValidationError(str(exc)) from exc
        return interval_minutes

    def _sanitize_contacts_for_plan(
        self, plan: MonitoringPlan, contacts: list[str]
    ) -> list[str]:
        if plan == "standard" and len(contacts) > 1:
            raise InputValidationError(
                "O plano standard aceita apenas um contato de alerta."
            )
        return contacts

    def _apply_domain_configuration(
        self,
        monitored_domain: MonitoredDomain,
        *,
        plan: MonitoringPlan,
        input_label: str | None | object,
        interval_minutes: int,
        alert_contacts: list[str],
        next_check_at: datetime,
    ) -> None:
        monitored_domain.plan = plan
        if input_label is not _UNSET:
            monitored_domain.input_label = input_label
        monitored_domain.monitoring_frequency = (
            self.schedule_service.frequency_label_for_interval(interval_minutes)
        )
        monitored_domain.check_interval_minutes = interval_minutes
        monitored_domain.alert_contacts = alert_contacts
        monitored_domain.next_check_at = next_check_at
        monitored_domain.next_run_at = next_check_at

    def _normalize_alert_contacts(
        self, raw_value: str | Iterable[str] | None | object
    ) -> list[str]:
        if raw_value is None or raw_value is _UNSET:
            return []
        if isinstance(raw_value, str):
            parts = [
                item.strip()
                for chunk in raw_value.replace(";", ",").split(",")
                for item in chunk.splitlines()
            ]
        else:
            parts = [str(item).strip() for item in raw_value]
        contacts: list[str] = []
        seen: set[str] = set()
        for item in parts:
            if not item:
                continue
            normalized = item.lower()
            if normalized in seen:
                continue
            self._validate_email_contact(normalized)
            seen.add(normalized)
            contacts.append(normalized)
        return contacts

    @staticmethod
    def _validate_email_contact(value: str) -> None:
        _, parsed = parseaddr(value)
        if (
            not parsed
            or "@" not in parsed
            or parsed.startswith("@")
            or parsed.endswith("@")
        ):
            raise InputValidationError(f"Contato de alerta invalido: {value}")

    def _build_scheduler_warning(self, monitored_domain: MonitoredDomain) -> str | None:
        if monitored_domain.monitoring_status != "active":
            return None
        reference = monitored_domain.next_check_at or monitored_domain.next_run_at
        if reference is None:
            return None
        overdue = self._utcnow() - self._ensure_aware(reference)
        if overdue <= timedelta(0):
            return None
        grace_minutes = max(30, monitored_domain.check_interval_minutes // 2)
        if overdue < timedelta(minutes=grace_minutes):
            return None
        overdue_minutes = int(overdue.total_seconds() // 60)
        return (
            f"Check atrasado ha {overdue_minutes} minutos. "
            "Se isso persistir, o scheduler externo provavelmente esta parado."
        )

    @staticmethod
    def _ensure_aware(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)


async def run_check_for_target(db: Session, target: MonitoredDomain) -> None:
    """Compatibility entrypoint used by the APScheduler cycle."""

    service = MonitoringService(session_factory=lambda: db)
    service._run_monitored_domain(
        db,
        target,
        now=service._utcnow(),
        trigger_type="scheduled",
    )
    db.commit()
