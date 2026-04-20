from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.exceptions import AuthorizationError, InputValidationError, ResourceConflictError
from app.db.models import AlertEvent, MonitoredDomain, MonitoringRun, User
from app.db.session import SessionLocal
from app.schemas.analysis import AnalysisResponse
from app.schemas.monitoring import (
    AlertEventSummary,
    MonitoredDomainSummary,
    MonitoringDashboardResponse,
    MonitoringDomainCreateInput,
    MonitoringDomainDetailResponse,
    MonitoringStatus,
    MonitoringRunSummary,
)
from app.services.analysis_history_service import AnalysisHistoryService
from app.services.analysis_service import DomainAnalysisService
from app.services.monitoring_alert_service import MonitoringAlertService
from app.services.monitoring_schedule_service import MonitoringScheduleService
from app.services.notification_email_service import NotificationEmailService
from app.utils.input_parser import normalize_target


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
        self.analysis_history_service = analysis_history_service or AnalysisHistoryService(
            session_factory=self.session_factory
        )
        self.schedule_service = schedule_service or MonitoringScheduleService()
        self.alert_service = alert_service or MonitoringAlertService()
        self.notification_service = notification_service or NotificationEmailService()

    def create_monitored_domain(
        self,
        *,
        user_id: int,
        domain: str,
        monitoring_frequency: str,
        input_label: str | None = None,
    ) -> MonitoredDomainSummary:
        try:
            payload = MonitoringDomainCreateInput(
                domain=domain,
                monitoring_frequency=monitoring_frequency,
                input_label=input_label,
            )
        except ValidationError as exc:
            raise InputValidationError(str(exc.errors()[0]["msg"])) from exc
        normalized_domain = normalize_target(payload.domain).analysis_domain
        current_time = self._utcnow()
        with self.session_factory() as db:
            user = self._require_user(db, user_id)
            existing = self._get_monitored_domain_by_domain(db, user.id, normalized_domain)
            if existing is not None:
                if existing.monitoring_status == "deleted":
                    current_time = self._utcnow()
                    existing.input_label = payload.input_label
                    existing.monitoring_frequency = payload.monitoring_frequency
                    existing.is_active = True
                    existing.monitoring_status = "active"
                    existing.paused_at = None
                    existing.deleted_at = None
                    existing.next_run_at = current_time
                    existing.last_status = "agendado"
                    existing.updated_at = current_time
                    db.commit()
                    db.refresh(existing)
                    return self._to_monitored_domain_summary(db, existing)
                raise ResourceConflictError("Este dominio ja esta cadastrado no monitoramento.")

            monitored_domain = MonitoredDomain(
                user_id=user.id,
                normalized_domain=normalized_domain,
                input_label=payload.input_label,
                monitoring_frequency=payload.monitoring_frequency,
                is_active=True,
                monitoring_status="active",
                paused_at=None,
                deleted_at=None,
                next_run_at=current_time,
                last_status="agendado",
                created_at=current_time,
                updated_at=current_time,
            )
            db.add(monitored_domain)
            db.commit()
            db.refresh(monitored_domain)
            return self._to_monitored_domain_summary(db, monitored_domain)

    def list_monitored_domains(self, *, user_id: int, include_deleted: bool = False) -> list[MonitoredDomainSummary]:
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

    def get_dashboard(self, *, user_id: int) -> MonitoringDashboardResponse:
        with self.session_factory() as db:
            user = self._require_user(db, user_id)
            domains = db.scalars(
                select(MonitoredDomain)
                .where(MonitoredDomain.user_id == user.id)
                .where(MonitoredDomain.monitoring_status != "deleted")
                .order_by(MonitoredDomain.created_at.desc(), MonitoredDomain.id.desc())
            ).all()
            open_alerts = db.scalars(
                select(AlertEvent)
                .join(MonitoredDomain, AlertEvent.monitored_domain_id == MonitoredDomain.id)
                .where(
                    MonitoredDomain.user_id == user.id,
                    MonitoredDomain.monitoring_status != "deleted",
                    AlertEvent.status == "open",
                )
                .order_by(AlertEvent.created_at.desc(), AlertEvent.id.desc())
            ).all()
            return MonitoringDashboardResponse(
                user_email=user.email,
                monitored_domains=[self._to_monitored_domain_summary(db, item) for item in domains],
                open_alerts=[self._to_alert_summary(item) for item in open_alerts],
            )

    def get_domain_detail(self, *, user_id: int, monitored_domain_id: int) -> MonitoringDomainDetailResponse:
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
            return MonitoringDomainDetailResponse(
                domain=self._to_monitored_domain_summary(db, monitored_domain),
                recent_runs=[self._to_run_summary(item) for item in recent_runs],
                open_alerts=[self._to_alert_summary(item) for item in open_alerts],
            )

    def pause_monitored_domain(self, *, user_id: int, monitored_domain_id: int) -> MonitoredDomainSummary:
        return self._set_monitoring_status(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
            target_status="paused",
        )

    def resume_monitored_domain(self, *, user_id: int, monitored_domain_id: int) -> MonitoredDomainSummary:
        return self._set_monitoring_status(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
            target_status="active",
        )

    def delete_monitored_domain(self, *, user_id: int, monitored_domain_id: int) -> MonitoredDomainSummary:
        return self._set_monitoring_status(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
            target_status="deleted",
        )

    def run_due_monitors(self, *, limit: int = 10) -> int:
        now = self._utcnow()
        processed = 0
        with self.session_factory() as db:
            due_domains = db.scalars(
                self._due_domains_query(now).limit(limit)
            ).all()
            for monitored_domain in due_domains:
                self._run_monitored_domain(db, monitored_domain, now=now)
                processed += 1
            db.commit()
        return processed

    def _run_monitored_domain(self, db: Session, monitored_domain: MonitoredDomain, *, now: datetime) -> None:
        previous_run = self._get_latest_completed_run(db, monitored_domain.id)
        previous_result = self._deserialize_analysis(previous_run.snapshot_data) if previous_run else None
        started_at = now
        run = MonitoringRun(
            monitored_domain_id=monitored_domain.id,
            snapshot_data={},
            diff_data={},
            run_status="error",
            started_at=started_at,
        )
        db.add(run)
        db.flush()

        try:
            result = self.analysis_service.analyze_target(monitored_domain.normalized_domain, force_refresh=True)
            latest_snapshot = self.analysis_history_service.get_latest_snapshot_for_domain(
                monitored_domain.normalized_domain
            )
            run.analysis_snapshot_id = latest_snapshot.id if latest_snapshot is not None else None
            run.snapshot_data = result.model_dump(mode="json")
            run.diff_data = result.changes.model_dump(mode="json")
            run.score = result.score
            run.severity = result.severity
            run.run_status = self._classify_run_status(result)
            run.error_message = None
            run.completed_at = self._utcnow()

            monitored_domain.last_run_at = run.completed_at
            monitored_domain.next_run_at = self.schedule_service.calculate_next_run_at(
                monitored_domain.monitoring_frequency,
                reference_time=run.completed_at,
            )
            monitored_domain.last_status = run.run_status
            monitored_domain.updated_at = run.completed_at

            candidates = self.alert_service.evaluate_alerts(result, previous_result=previous_result)
            synced_alerts = self.alert_service.synchronize_alerts(
                db,
                monitored_domain=monitored_domain,
                monitoring_run=run,
                candidates=candidates,
            )
            try:
                self.notification_service.deliver_pending_alerts(
                    db,
                    monitored_domain=monitored_domain,
                    monitoring_run=run,
                    analysis_result=result,
                    alert_events=synced_alerts,
                )
            except Exception:
                pass
        except Exception as exc:
            finished_at = self._utcnow()
            run.run_status = "error"
            run.error_message = str(exc)
            run.completed_at = finished_at
            monitored_domain.last_run_at = finished_at
            monitored_domain.next_run_at = self.schedule_service.calculate_next_run_at(
                monitored_domain.monitoring_frequency,
                reference_time=finished_at,
            )
            monitored_domain.last_status = "error"
            monitored_domain.updated_at = finished_at

        db.flush()

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
                MonitoredDomain.next_run_at <= now,
            )
            .order_by(MonitoredDomain.next_run_at.asc(), MonitoredDomain.id.asc())
        )

    @staticmethod
    def _get_latest_completed_run(db: Session, monitored_domain_id: int) -> MonitoringRun | None:
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
    def _get_monitored_domain_by_domain(db: Session, user_id: int, normalized_domain: str) -> MonitoredDomain | None:
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
                    raise AuthorizationError("Monitoramentos excluidos nao podem ser pausados.")
                monitored_domain.monitoring_status = "paused"
                monitored_domain.is_active = False
                monitored_domain.paused_at = current_time
                monitored_domain.updated_at = current_time
            elif target_status == "active":
                if monitored_domain.monitoring_status == "deleted":
                    raise AuthorizationError("Monitoramentos excluidos nao podem ser retomados.")
                monitored_domain.monitoring_status = "active"
                monitored_domain.is_active = True
                monitored_domain.paused_at = None
                monitored_domain.deleted_at = None
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

    def _to_monitored_domain_summary(self, db: Session, monitored_domain: MonitoredDomain) -> MonitoredDomainSummary:
        latest_run = db.scalar(
            select(MonitoringRun)
            .where(MonitoringRun.monitored_domain_id == monitored_domain.id)
            .order_by(MonitoringRun.started_at.desc(), MonitoringRun.id.desc())
            .limit(1)
        )
        open_alert_count = db.scalar(
            select(func.count(AlertEvent.id)).where(
                AlertEvent.monitored_domain_id == monitored_domain.id,
                AlertEvent.status == "open",
            )
        )
        return MonitoredDomainSummary(
            id=monitored_domain.id,
            normalized_domain=monitored_domain.normalized_domain,
            input_label=monitored_domain.input_label,
            monitoring_frequency=monitored_domain.monitoring_frequency,
            is_active=monitored_domain.is_active,
            monitoring_status=monitored_domain.monitoring_status,
            paused_at=monitored_domain.paused_at,
            deleted_at=monitored_domain.deleted_at,
            last_run_at=monitored_domain.last_run_at,
            next_run_at=monitored_domain.next_run_at,
            last_status=monitored_domain.last_status,
            latest_score=latest_run.score if latest_run is not None else None,
            latest_severity=latest_run.severity if latest_run is not None else None,
            open_alert_count=int(open_alert_count or 0),
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
            error_message=run.error_message,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
