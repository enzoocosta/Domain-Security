"""Pure commercial-state service for the Monitoring Plus add-on.

This service intentionally does NOT touch payment gateways or technical
analysis. It only owns the lifecycle of the local ``PremiumSubscription``
record so the rest of the application can ask:

    "Is this monitored domain entitled to Monitoring Plus right now?"

Future Stripe/Paddle integrations should call ``activate``/``cancel`` from
their webhooks instead of replacing this module.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthorizationError,
    InputValidationError,
    SubscriptionRequiredError,
)
from app.db.models import MonitoredDomain, PremiumSubscription
from app.db.session import SessionLocal


_VALID_STATUSES = {"trial", "active", "past_due", "canceled"}


class BillingService:
    """Owns Monitoring Plus subscription state for monitored domains."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session] | None = None,
        trial_days: int | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal
        self.trial_days = trial_days if trial_days is not None else settings.monitoring_plus_trial_days

    # -- public API ---------------------------------------------------

    def start_trial(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
    ) -> PremiumSubscription:
        with self.session_factory() as db:
            domain = self._require_owned_domain(db, user_id=user_id, monitored_domain_id=monitored_domain_id)
            subscription = self._get_subscription(db, monitored_domain_id=domain.id)
            current_time = self._utcnow()
            trial_end = current_time + timedelta(days=self.trial_days)

            if subscription is None:
                subscription = PremiumSubscription(
                    monitored_domain_id=domain.id,
                    plan_code="monitoring_plus",
                    status="trial",
                    trial_started_at=current_time,
                    trial_ends_at=trial_end,
                    created_at=current_time,
                    updated_at=current_time,
                )
                db.add(subscription)
            else:
                if subscription.status == "active":
                    db.commit()
                    db.refresh(subscription)
                    return subscription
                subscription.status = "trial"
                subscription.trial_started_at = current_time
                subscription.trial_ends_at = trial_end
                subscription.canceled_at = None
                subscription.updated_at = current_time

            db.commit()
            db.refresh(subscription)
            return subscription

    def activate(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
        plan_code: str = "monitoring_plus",
        current_period_end: datetime | None = None,
    ) -> PremiumSubscription:
        with self.session_factory() as db:
            domain = self._require_owned_domain(db, user_id=user_id, monitored_domain_id=monitored_domain_id)
            subscription = self._get_subscription(db, monitored_domain_id=domain.id)
            current_time = self._utcnow()

            if subscription is None:
                subscription = PremiumSubscription(
                    monitored_domain_id=domain.id,
                    plan_code=plan_code,
                    status="active",
                    activated_at=current_time,
                    current_period_end=current_period_end,
                    created_at=current_time,
                    updated_at=current_time,
                )
                db.add(subscription)
            else:
                subscription.plan_code = plan_code
                subscription.status = "active"
                subscription.activated_at = current_time
                subscription.canceled_at = None
                subscription.current_period_end = current_period_end
                subscription.updated_at = current_time

            db.commit()
            db.refresh(subscription)
            return subscription

    def cancel(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
    ) -> PremiumSubscription:
        with self.session_factory() as db:
            domain = self._require_owned_domain(db, user_id=user_id, monitored_domain_id=monitored_domain_id)
            subscription = self._get_subscription(db, monitored_domain_id=domain.id)
            if subscription is None:
                raise InputValidationError("Nao existe assinatura para este dominio.")

            current_time = self._utcnow()
            subscription.status = "canceled"
            subscription.canceled_at = current_time
            subscription.updated_at = current_time
            db.commit()
            db.refresh(subscription)
            return subscription

    def get_subscription(
        self,
        *,
        monitored_domain_id: int,
    ) -> PremiumSubscription | None:
        with self.session_factory() as db:
            return self._get_subscription(db, monitored_domain_id=monitored_domain_id)

    def get_subscription_in_session(
        self,
        db: Session,
        *,
        monitored_domain_id: int,
    ) -> PremiumSubscription | None:
        return self._get_subscription(db, monitored_domain_id=monitored_domain_id)

    def is_entitled(self, *, monitored_domain_id: int) -> bool:
        with self.session_factory() as db:
            subscription = self._get_subscription(db, monitored_domain_id=monitored_domain_id)
            return self.evaluate_entitlement(subscription)

    def is_entitled_in_session(self, db: Session, *, monitored_domain_id: int) -> bool:
        subscription = self._get_subscription(db, monitored_domain_id=monitored_domain_id)
        return self.evaluate_entitlement(subscription)

    def require_entitlement(self, *, monitored_domain_id: int) -> None:
        if not self.is_entitled(monitored_domain_id=monitored_domain_id):
            raise SubscriptionRequiredError(
                "Monitoring Plus inativo ou expirado para este dominio."
            )

    def evaluate_entitlement(self, subscription: PremiumSubscription | None) -> bool:
        if subscription is None:
            return False
        if subscription.status == "active":
            if subscription.current_period_end is None:
                return True
            return self._utcnow() <= self._ensure_aware(subscription.current_period_end)
        if subscription.status == "trial":
            if subscription.trial_ends_at is None:
                return False
            return self._utcnow() <= self._ensure_aware(subscription.trial_ends_at)
        return False

    def days_left_in_trial(self, subscription: PremiumSubscription | None) -> int | None:
        if subscription is None or subscription.status != "trial" or subscription.trial_ends_at is None:
            return None
        delta = self._ensure_aware(subscription.trial_ends_at) - self._utcnow()
        days_left = delta.total_seconds() / 86400
        if days_left <= 0:
            return 0
        return max(1, int(days_left + 0.5))

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _get_subscription(db: Session, *, monitored_domain_id: int) -> PremiumSubscription | None:
        return db.scalar(
            select(PremiumSubscription).where(
                PremiumSubscription.monitored_domain_id == monitored_domain_id
            )
        )

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

    @staticmethod
    def _ensure_aware(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)


def validate_status(status: str) -> str:
    cleaned = status.strip().lower()
    if cleaned not in _VALID_STATUSES:
        raise InputValidationError(f"Status de assinatura invalido: {status}")
    return cleaned
