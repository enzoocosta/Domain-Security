from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.db.models import AlertEvent, MonitoredDomain, MonitoringRun
from app.schemas.analysis import AnalysisResponse
from app.services.email_delivery_service import EmailDeliveryService, EmailMessagePayload


class NotificationEmailService:
    """Delivers monitoring alert e-mails without coupling alert generation to transport."""

    _ALERT_SEVERITY_ORDER = {
        "baixa": 0,
        "media": 1,
        "alta": 2,
    }

    def __init__(self, email_delivery_service: EmailDeliveryService | None = None) -> None:
        self.email_delivery_service = email_delivery_service or EmailDeliveryService()

    def deliver_pending_alerts(
        self,
        db: Session,
        *,
        monitored_domain: MonitoredDomain,
        monitoring_run: MonitoringRun,
        analysis_result: AnalysisResponse,
        alert_events: list[AlertEvent],
    ) -> None:
        pending_events = [
            item
            for item in alert_events
            if item.status == "open" and item.email_delivery_status == "pending"
        ]
        if not pending_events:
            return

        current_time = self._utcnow()
        user = monitored_domain.user
        preference = getattr(user, "notification_preference", None)
        if user is None or not user.email or preference is None or not preference.email_alerts_enabled:
            self._mark_events(pending_events, status="skipped", attempted_at=current_time)
            return

        payload = EmailMessagePayload(
            recipient=user.email,
            subject=self._build_subject(monitored_domain.normalized_domain, pending_events),
            text_body=self._build_body(
                monitored_domain=monitored_domain,
                monitoring_run=monitoring_run,
                analysis_result=analysis_result,
                alert_events=pending_events,
            ),
        )
        send_result = self.email_delivery_service.send(payload)
        if send_result.delivered:
            self._mark_events(
                pending_events,
                status="sent",
                attempted_at=current_time,
                sent_at=current_time,
            )
            return

        failure_status = "failed" if send_result.attempted else "skipped"
        self._mark_events(
            pending_events,
            status=failure_status,
            attempted_at=current_time,
            error=send_result.error,
        )
        db.flush()

    def _build_subject(self, domain: str, alert_events: list[AlertEvent]) -> str:
        highest = max(
            alert_events,
            key=lambda item: self._ALERT_SEVERITY_ORDER.get(item.severity, 0),
        )
        return f"[Domain Security Checker] {domain} - alerta {highest.severity}"

    def _build_body(
        self,
        *,
        monitored_domain: MonitoredDomain,
        monitoring_run: MonitoringRun,
        analysis_result: AnalysisResponse,
        alert_events: list[AlertEvent],
    ) -> str:
        changed_checks = [item.label for item in analysis_result.changes.changed_checks[:5]]
        main_recommendation = analysis_result.recommendations[0] if analysis_result.recommendations else None
        lines = [
            "Um alerta de monitoramento foi gerado.",
            "",
            f"Dominio monitorado: {monitored_domain.normalized_domain}",
            f"Data/hora: {self._format_datetime(monitoring_run.completed_at or monitoring_run.started_at)}",
            f"Severidade: {analysis_result.severity}",
            f"Resumo: {analysis_result.summary}",
            "",
            "Principais alertas:",
        ]
        lines.extend(f"- {item.title}: {item.description}" for item in alert_events)
        if changed_checks:
            lines.extend(["", "Principais mudancas detectadas:"])
            lines.extend(f"- {label}" for label in changed_checks)
        if main_recommendation is not None:
            lines.extend(
                [
                    "",
                    f"Recomendacao principal: {main_recommendation.title}",
                    main_recommendation.action,
                ]
            )
        return "\n".join(lines)

    @staticmethod
    def _mark_events(
        alert_events: list[AlertEvent],
        *,
        status: str,
        attempted_at: datetime,
        sent_at: datetime | None = None,
        error: str | None = None,
    ) -> None:
        for event in alert_events:
            event.email_delivery_status = status
            event.email_last_attempt_at = attempted_at
            event.email_sent_at = sent_at
            event.email_last_error = error

    @staticmethod
    def _format_datetime(value: datetime) -> str:
        normalized = value if value.tzinfo else value.replace(tzinfo=UTC)
        return normalized.strftime("%d/%m/%Y %H:%M %Z")

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
