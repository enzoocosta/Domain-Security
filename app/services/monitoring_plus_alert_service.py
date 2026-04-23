"""Sends e-mail notifications for Monitoring Plus traffic incidents.

Mirrors the pattern of ``NotificationEmailService`` but operates on
``TrafficIncident`` rows. Idempotent: only incidents with delivery status
``pending`` are dispatched, then marked as ``sent``/``failed``/``skipped``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import MonitoredDomain, TrafficIncident, User
from app.db.session import SessionLocal
from app.services.email_delivery_service import EmailDeliveryService, EmailMessagePayload


class MonitoringPlusAlertService:
    _SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session] | None = None,
        email_delivery_service: EmailDeliveryService | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal
        self.email_delivery_service = email_delivery_service or EmailDeliveryService()

    def dispatch_pending_incidents(self) -> int:
        """Dispatches all pending incidents and returns the count of attempts."""

        with self.session_factory() as db:
            incidents = db.scalars(
                select(TrafficIncident)
                .options(
                    selectinload(TrafficIncident.monitored_domain).selectinload(MonitoredDomain.user)
                )
                .where(
                    TrafficIncident.status == "open",
                    TrafficIncident.email_delivery_status == "pending",
                )
                .order_by(TrafficIncident.detected_at.asc())
            ).all()
            if not incidents:
                return 0

            grouped: dict[int, list[TrafficIncident]] = {}
            for incident in incidents:
                grouped.setdefault(incident.monitored_domain_id, []).append(incident)

            attempted = 0
            for monitored_domain_id, items in grouped.items():
                domain = items[0].monitored_domain
                if domain is None:
                    continue
                attempted += self._dispatch_for_domain(db, domain=domain, incidents=items)

            db.commit()
            return attempted

    def _dispatch_for_domain(
        self,
        db: Session,
        *,
        domain: MonitoredDomain,
        incidents: list[TrafficIncident],
    ) -> int:
        current_time = self._utcnow()
        user: User | None = domain.user
        preference = getattr(user, "notification_preference", None) if user else None

        if user is None or not user.email or preference is None or not preference.email_alerts_enabled:
            self._mark(incidents, status="skipped", attempted_at=current_time)
            return len(incidents)

        payload = EmailMessagePayload(
            recipient=user.email,
            subject=self._build_subject(domain.normalized_domain, incidents),
            text_body=self._build_body(domain=domain, incidents=incidents),
        )
        result = self.email_delivery_service.send(payload)
        if result.delivered:
            self._mark(
                incidents,
                status="sent",
                attempted_at=current_time,
                sent_at=current_time,
            )
            return len(incidents)

        failure_status = "failed" if result.attempted else "skipped"
        self._mark(
            incidents,
            status=failure_status,
            attempted_at=current_time,
            error=result.error,
        )
        return len(incidents)

    def _build_subject(self, domain: str, incidents: list[TrafficIncident]) -> str:
        highest = max(incidents, key=lambda item: self._SEVERITY_ORDER.get(item.severity, 0))
        return f"[Monitoring Plus] {domain} - {highest.severity.upper()}: {highest.title}"

    def _build_body(self, *, domain: MonitoredDomain, incidents: list[TrafficIncident]) -> str:
        lines = [
            "O Monitoring Plus detectou comportamento suspeito no seu dominio.",
            "",
            f"Dominio: {domain.normalized_domain}",
            f"Incidentes: {len(incidents)}",
            "",
            "Detalhes:",
        ]
        for incident in incidents:
            lines.append(
                f"- [{incident.severity.upper()}] {incident.title}\n  {incident.description}"
            )
        lines.extend(
            [
                "",
                "Acesse o painel Monitoring Plus para revisar os incidentes e tomar acoes.",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _mark(
        incidents: list[TrafficIncident],
        *,
        status: str,
        attempted_at: datetime,
        sent_at: datetime | None = None,
        error: str | None = None,
    ) -> None:
        for incident in incidents:
            incident.email_delivery_status = status
            incident.email_last_attempt_at = attempted_at
            incident.email_sent_at = sent_at
            incident.email_last_error = error

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
