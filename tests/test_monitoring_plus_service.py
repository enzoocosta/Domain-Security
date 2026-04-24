from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.db.models import MonitoredDomain, TrafficEvent, TrafficIncident
from app.schemas.monitoring_plus import MonitoringPlusActivationInput
from app.services.billing_service import BillingService
from app.services.monitoring_plus_service import MonitoringPlusService
from app.services.premium_ingest_token_service import PremiumIngestTokenService
from tests.premium_test_utils import (
    build_test_session_factory,
    create_monitored_domain,
    create_test_user,
)


def test_activate_from_offer_reuses_existing_monitored_domain():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    existing = create_monitored_domain(session_factory, user_id=user.id)
    service = MonitoringPlusService(session_factory=session_factory)

    detail = service.activate_from_offer(
        user_id=user.id,
        payload=MonitoringPlusActivationInput(
            domain="example.com",
            monitoring_frequency="weekly",
            input_label="Dominio principal",
        ),
    )

    with session_factory() as db:
        domain_count = db.scalar(select(func.count(MonitoredDomain.id)))

    assert detail.monitored_domain_id == existing.id
    assert detail.subscription is not None
    assert detail.subscription.status == "trial"
    assert domain_count == 1


def test_get_offer_state_distinguishes_plain_monitoring_from_entitled_plus():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = MonitoringPlusService(session_factory=session_factory)

    state_before = service.get_offer_state(user_id=user.id, domain="example.com")
    BillingService(session_factory=session_factory).start_trial(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )
    state_after = service.get_offer_state(user_id=user.id, domain="example.com")

    assert state_before.monitored_domain_id == domain.id
    assert state_before.subscription_status is None
    assert state_before.is_entitled is False
    assert state_after.subscription_status == "trial"
    assert state_after.is_entitled is True


def test_get_dashboard_aggregates_open_incidents():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    BillingService(session_factory=session_factory).start_trial(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )
    now = datetime.now(tz=UTC)

    with session_factory() as db:
        db.add_all(
            [
                TrafficIncident(
                    monitored_domain_id=domain.id,
                    incident_type="scan_pattern",
                    severity="high",
                    title="Scan detectado",
                    description="Descricao",
                    evidence={},
                    status="open",
                    email_delivery_status="pending",
                    detected_at=now - timedelta(minutes=5),
                ),
                TrafficIncident(
                    monitored_domain_id=domain.id,
                    incident_type="error_spike",
                    severity="high",
                    title="Erro 5xx",
                    description="Descricao",
                    evidence={},
                    status="open",
                    email_delivery_status="pending",
                    detected_at=now - timedelta(minutes=1),
                ),
                TrafficIncident(
                    monitored_domain_id=domain.id,
                    incident_type="traffic_spike",
                    severity="high",
                    title="Resolvido",
                    description="Descricao",
                    evidence={},
                    status="resolved",
                    email_delivery_status="pending",
                    detected_at=now - timedelta(minutes=20),
                    resolved_at=now - timedelta(minutes=10),
                ),
            ]
        )
        db.commit()

    dashboard = MonitoringPlusService(session_factory=session_factory).get_dashboard(
        user_id=user.id
    )

    assert dashboard.total_open_incidents == 2
    assert len(dashboard.items) == 1
    assert dashboard.items[0].open_incidents == 2
    assert dashboard.items[0].subscription_status == "trial"


def test_domain_detail_includes_tokens_events_and_resolve_flow():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    BillingService(session_factory=session_factory).start_trial(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )
    token_service = PremiumIngestTokenService(session_factory=session_factory)
    created = token_service.create_token(
        user_id=user.id,
        monitored_domain_id=domain.id,
        name="edge-prod",
    )
    now = datetime.now(tz=UTC)

    with session_factory() as db:
        db.add(
            TrafficEvent(
                monitored_domain_id=domain.id,
                occurred_at=now - timedelta(minutes=2),
                received_at=now - timedelta(minutes=2),
                path="/api",
                status_code=200,
                meta={},
            )
        )
        db.add(
            TrafficIncident(
                monitored_domain_id=domain.id,
                incident_type="suspicious_user_agent",
                severity="medium",
                title="UA suspeito",
                description="Descricao",
                evidence={"matched_user_agent_substring": "sqlmap"},
                status="open",
                email_delivery_status="pending",
                detected_at=now - timedelta(minutes=1),
            )
        )
        db.commit()
        incident = db.scalar(select(TrafficIncident))

    service = MonitoringPlusService(session_factory=session_factory)
    detail = service.get_domain_detail(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )
    service.resolve_incident(
        user_id=user.id,
        monitored_domain_id=domain.id,
        incident_id=incident.id,
    )

    with session_factory() as db:
        resolved = db.get(TrafficIncident, incident.id)

    assert created.token.startswith("mp_")
    assert detail.stats.events_last_24h == 1
    assert len(detail.ingest_tokens) == 1
    assert detail.recent_incidents[0].status == "open"
    assert resolved is not None
    assert resolved.status == "resolved"
    assert resolved.resolved_at is not None
