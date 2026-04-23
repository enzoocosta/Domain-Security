"""Orchestrates Monitoring Plus reads and the post-analysis activation flow.

This service coordinates ``MonitoringService`` (for the underlying monitored
domain), ``BillingService`` (for entitlement) and ``PremiumIngestTokenService``
(for ingest credentials), exposing a clean facade for the web routes.

It deliberately does NOT call detection here: detection runs asynchronously in
the scheduler. Web routes only read the resulting state.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import AuthorizationError, InputValidationError, ResourceConflictError
from app.db.models import MonitoredDomain, PremiumSubscription, TrafficEvent, TrafficIncident, User
from app.db.session import SessionLocal
from app.schemas.monitoring_plus import (
    MonitoringPlusActivationInput,
    MonitoringPlusDashboard,
    MonitoringPlusDomainCard,
    MonitoringPlusDomainDetail,
    MonitoringPlusDomainStats,
    PremiumIngestTokenSummary,
    PremiumSubscriptionSummary,
    TrafficIncidentSummary,
)
from app.services.billing_service import BillingService
from app.services.monitoring_service import MonitoringService
from app.services.premium_ingest_token_service import PremiumIngestTokenService


class MonitoringPlusService:
    def __init__(
        self,
        *,
        session_factory: Callable[[], Session] | None = None,
        monitoring_service: MonitoringService | None = None,
        billing_service: BillingService | None = None,
        ingest_token_service: PremiumIngestTokenService | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal
        self.monitoring_service = monitoring_service or MonitoringService(
            session_factory=self.session_factory
        )
        self.billing_service = billing_service or BillingService(session_factory=self.session_factory)
        self.ingest_token_service = ingest_token_service or PremiumIngestTokenService(
            session_factory=self.session_factory
        )

    # -- post-analysis activation -------------------------------------

    def activate_from_offer(
        self,
        *,
        user_id: int,
        payload: MonitoringPlusActivationInput,
    ) -> MonitoringPlusDomainDetail:
        """Activates Monitoring Plus right after the user accepts the offer.

        Idempotent: if the domain is already monitored we just (re)start the
        trial. Never disturbs the underlying technical analysis.
        """

        existing = self._find_monitored_domain(user_id=user_id, domain=payload.domain)
        if existing is None:
            try:
                created = self.monitoring_service.create_monitored_domain(
                    user_id=user_id,
                    domain=payload.domain,
                    monitoring_frequency=payload.monitoring_frequency,
                    input_label=payload.input_label,
                )
            except ResourceConflictError:
                # Race condition: another request just created it.
                existing = self._find_monitored_domain(user_id=user_id, domain=payload.domain)
                if existing is None:
                    raise
                monitored_domain_id = existing
            else:
                monitored_domain_id = created.id
        else:
            monitored_domain_id = existing

        self.billing_service.start_trial(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
        )
        return self.get_domain_detail(
            user_id=user_id,
            monitored_domain_id=monitored_domain_id,
        )

    # -- dashboard reads ---------------------------------------------

    def get_dashboard(self, *, user_id: int) -> MonitoringPlusDashboard:
        with self.session_factory() as db:
            user = self._require_user(db, user_id)
            rows = db.scalars(
                select(MonitoredDomain)
                .where(
                    MonitoredDomain.user_id == user_id,
                    MonitoredDomain.deleted_at.is_(None),
                )
                .order_by(MonitoredDomain.created_at.desc())
            ).all()

            cards: list[MonitoringPlusDomainCard] = []
            total_open = 0
            for domain in rows:
                subscription = self.billing_service.get_subscription_in_session(
                    db, monitored_domain_id=domain.id
                )
                if subscription is None:
                    continue
                open_incidents = int(
                    db.scalar(
                        select(func.count(TrafficIncident.id)).where(
                            TrafficIncident.monitored_domain_id == domain.id,
                            TrafficIncident.status == "open",
                        )
                    )
                    or 0
                )
                last_incident_at = db.scalar(
                    select(func.max(TrafficIncident.detected_at)).where(
                        TrafficIncident.monitored_domain_id == domain.id
                    )
                )
                cards.append(
                    MonitoringPlusDomainCard(
                        monitored_domain_id=domain.id,
                        normalized_domain=domain.normalized_domain,
                        input_label=domain.input_label,
                        subscription_status=subscription.status,
                        is_entitled=self.billing_service.evaluate_entitlement(subscription),
                        days_left_in_trial=self.billing_service.days_left_in_trial(subscription),
                        open_incidents=open_incidents,
                        last_incident_at=last_incident_at,
                    )
                )
                total_open += open_incidents

            return MonitoringPlusDashboard(
                user_email=user.email,
                items=cards,
                total_open_incidents=total_open,
            )

    def get_domain_detail(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
    ) -> MonitoringPlusDomainDetail:
        with self.session_factory() as db:
            domain = self._require_owned_domain(
                db, user_id=user_id, monitored_domain_id=monitored_domain_id
            )
            subscription = self.billing_service.get_subscription_in_session(
                db, monitored_domain_id=domain.id
            )
            stats = self._build_stats(db, monitored_domain_id=domain.id)
            recent_incidents = db.scalars(
                select(TrafficIncident)
                .where(TrafficIncident.monitored_domain_id == domain.id)
                .order_by(TrafficIncident.detected_at.desc())
                .limit(50)
            ).all()
            tokens = self.ingest_token_service.list_tokens_in_session(
                db, monitored_domain_id=domain.id
            )

            return MonitoringPlusDomainDetail(
                monitored_domain_id=domain.id,
                normalized_domain=domain.normalized_domain,
                input_label=domain.input_label,
                subscription=self._to_subscription_summary(subscription),
                stats=stats,
                recent_incidents=[self._to_incident_summary(item) for item in recent_incidents],
                ingest_tokens=tokens,
            )

    # -- mutations ----------------------------------------------------

    def cancel_subscription(self, *, user_id: int, monitored_domain_id: int) -> None:
        self.billing_service.cancel(
            user_id=user_id, monitored_domain_id=monitored_domain_id
        )

    def restart_trial(self, *, user_id: int, monitored_domain_id: int) -> None:
        self.billing_service.start_trial(
            user_id=user_id, monitored_domain_id=monitored_domain_id
        )

    def resolve_incident(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
        incident_id: int,
    ) -> None:
        with self.session_factory() as db:
            self._require_owned_domain(
                db, user_id=user_id, monitored_domain_id=monitored_domain_id
            )
            incident = db.get(TrafficIncident, incident_id)
            if incident is None or incident.monitored_domain_id != monitored_domain_id:
                raise InputValidationError("Incidente nao encontrado.")
            if incident.status != "open":
                return
            incident.status = "resolved"
            incident.resolved_at = datetime.now(tz=UTC)
            db.commit()

    # -- helpers ------------------------------------------------------

    def _build_stats(
        self,
        db: Session,
        *,
        monitored_domain_id: int,
    ) -> MonitoringPlusDomainStats:
        now = datetime.now(tz=UTC)
        events_last_hour = int(
            db.scalar(
                select(func.count(TrafficEvent.id)).where(
                    TrafficEvent.monitored_domain_id == monitored_domain_id,
                    TrafficEvent.occurred_at >= now - timedelta(hours=1),
                )
            )
            or 0
        )
        events_last_24h = int(
            db.scalar(
                select(func.count(TrafficEvent.id)).where(
                    TrafficEvent.monitored_domain_id == monitored_domain_id,
                    TrafficEvent.occurred_at >= now - timedelta(hours=24),
                )
            )
            or 0
        )
        open_incidents = int(
            db.scalar(
                select(func.count(TrafficIncident.id)).where(
                    TrafficIncident.monitored_domain_id == monitored_domain_id,
                    TrafficIncident.status == "open",
                )
            )
            or 0
        )
        last_event_at = db.scalar(
            select(func.max(TrafficEvent.occurred_at)).where(
                TrafficEvent.monitored_domain_id == monitored_domain_id
            )
        )
        return MonitoringPlusDomainStats(
            events_last_hour=events_last_hour,
            events_last_24h=events_last_24h,
            open_incidents=open_incidents,
            last_event_at=last_event_at,
        )

    def _to_subscription_summary(
        self,
        subscription: PremiumSubscription | None,
    ) -> PremiumSubscriptionSummary | None:
        if subscription is None:
            return None
        return PremiumSubscriptionSummary(
            id=subscription.id,
            monitored_domain_id=subscription.monitored_domain_id,
            plan_code=subscription.plan_code,
            status=subscription.status,
            trial_started_at=subscription.trial_started_at,
            trial_ends_at=subscription.trial_ends_at,
            activated_at=subscription.activated_at,
            canceled_at=subscription.canceled_at,
            current_period_end=subscription.current_period_end,
            is_entitled=self.billing_service.evaluate_entitlement(subscription),
            days_left_in_trial=self.billing_service.days_left_in_trial(subscription),
        )

    @staticmethod
    def _to_incident_summary(incident: TrafficIncident) -> TrafficIncidentSummary:
        return TrafficIncidentSummary(
            id=incident.id,
            monitored_domain_id=incident.monitored_domain_id,
            incident_type=incident.incident_type,
            severity=incident.severity,
            title=incident.title,
            description=incident.description,
            evidence=incident.evidence or {},
            status=incident.status,
            detected_at=incident.detected_at,
            resolved_at=incident.resolved_at,
            email_delivery_status=incident.email_delivery_status,
            email_sent_at=incident.email_sent_at,
        )

    def _find_monitored_domain(self, *, user_id: int, domain: str) -> int | None:
        with self.session_factory() as db:
            row = db.scalar(
                select(MonitoredDomain.id).where(
                    MonitoredDomain.user_id == user_id,
                    MonitoredDomain.normalized_domain == domain,
                    MonitoredDomain.deleted_at.is_(None),
                )
            )
            return int(row) if row is not None else None

    @staticmethod
    def _require_user(db: Session, user_id: int) -> User:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            raise AuthorizationError("Usuario nao autenticado ou inativo.")
        return user

    @staticmethod
    def _require_owned_domain(
        db: Session,
        *,
        user_id: int,
        monitored_domain_id: int,
    ) -> MonitoredDomain:
        domain = db.get(MonitoredDomain, monitored_domain_id)
        if domain is None or domain.user_id != user_id or domain.deleted_at is not None:
            raise AuthorizationError("Dominio monitorado nao encontrado para este usuario.")
        return domain
