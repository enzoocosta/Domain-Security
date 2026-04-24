from datetime import UTC, datetime, timedelta

import pytest

from app.core.exceptions import SubscriptionRequiredError
from app.db.models import PremiumSubscription
from app.services.billing_service import BillingService
from tests.premium_test_utils import (
    build_test_session_factory,
    create_monitored_domain,
    create_test_user,
)


def test_start_trial_creates_entitled_subscription():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = BillingService(session_factory=session_factory, trial_days=14)

    subscription = service.start_trial(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )

    assert subscription.status == "trial"
    assert subscription.plan_code == "monitoring_plus"
    assert service.is_entitled(monitored_domain_id=domain.id) is True
    assert service.days_left_in_trial(subscription) >= 13


def test_start_trial_does_not_downgrade_active_subscription():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = BillingService(session_factory=session_factory)

    active = service.activate(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )
    restarted = service.start_trial(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )

    assert active.status == "active"
    assert restarted.status == "active"
    assert restarted.id == active.id


def test_cancel_revokes_entitlement():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = BillingService(session_factory=session_factory)
    service.start_trial(user_id=user.id, monitored_domain_id=domain.id)

    canceled = service.cancel(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )

    assert canceled.status == "canceled"
    assert service.is_entitled(monitored_domain_id=domain.id) is False


def test_require_entitlement_rejects_expired_trial():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = BillingService(session_factory=session_factory)
    subscription = service.start_trial(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )

    with session_factory() as db:
        stored = db.get(PremiumSubscription, subscription.id)
        stored.trial_ends_at = datetime.now(tz=UTC) - timedelta(minutes=5)
        db.commit()

    assert service.is_entitled(monitored_domain_id=domain.id) is False
    with pytest.raises(SubscriptionRequiredError):
        service.require_entitlement(monitored_domain_id=domain.id)
