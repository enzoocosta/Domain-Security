from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.db.models import TrafficEvent, TrafficIncident
from app.services.billing_service import BillingService
from app.services.traffic_detection_service import DetectionConfig, TrafficDetectionService
from tests.premium_test_utils import (
    build_test_session_factory,
    create_monitored_domain,
    create_test_user,
)


def _config() -> DetectionConfig:
    return DetectionConfig(
        spike_window_seconds=60,
        spike_baseline_window_seconds=300,
        spike_multiplier=100.0,
        spike_min_requests=100,
        scan_window_seconds=300,
        scan_unique_paths_threshold=3,
        scan_404_ratio_threshold=0.5,
        error_window_seconds=300,
        error_rate_threshold=0.8,
        error_min_requests=10,
        suspicious_user_agents=("sqlmap",),
        dedupe_window_seconds=1800,
    )


def test_detection_creates_scan_and_user_agent_incidents():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    BillingService(session_factory=session_factory).activate(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )
    now = datetime.now(tz=UTC)

    with session_factory() as db:
        for path in ("/admin", "/.env", "/backup", "/phpmyadmin"):
            db.add(
                TrafficEvent(
                    monitored_domain_id=domain.id,
                    occurred_at=now - timedelta(seconds=30),
                    received_at=now - timedelta(seconds=30),
                    client_ip="198.51.100.10",
                    path=path,
                    status_code=404,
                    user_agent="sqlmap/1.7",
                    meta={},
                )
            )
        db.commit()

    service = TrafficDetectionService(
        session_factory=session_factory,
        config=_config(),
    )
    incidents = service.detect_for_domain(monitored_domain_id=domain.id)

    incident_types = {item.incident_type for item in incidents}
    assert incident_types == {"scan_pattern", "suspicious_user_agent"}


def test_detection_skips_domain_without_entitlement():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    now = datetime.now(tz=UTC)

    with session_factory() as db:
        db.add(
            TrafficEvent(
                monitored_domain_id=domain.id,
                occurred_at=now - timedelta(seconds=20),
                received_at=now - timedelta(seconds=20),
                client_ip="198.51.100.20",
                path="/scan",
                status_code=404,
                user_agent="sqlmap/1.7",
                meta={},
            )
        )
        db.commit()

    service = TrafficDetectionService(
        session_factory=session_factory,
        config=_config(),
    )

    assert service.detect_for_domain(monitored_domain_id=domain.id) == []


def test_detection_deduplicates_incidents_within_same_window(monkeypatch):
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    BillingService(session_factory=session_factory).activate(
        user_id=user.id,
        monitored_domain_id=domain.id,
    )
    fixed_now = datetime(2026, 4, 24, 12, 0, tzinfo=UTC)

    with session_factory() as db:
        db.add(
            TrafficEvent(
                monitored_domain_id=domain.id,
                occurred_at=fixed_now - timedelta(seconds=10),
                received_at=fixed_now - timedelta(seconds=10),
                client_ip="198.51.100.30",
                path="/scanner",
                status_code=200,
                user_agent="sqlmap/1.7",
                meta={},
            )
        )
        db.commit()

    service = TrafficDetectionService(
        session_factory=session_factory,
        config=_config(),
    )
    monkeypatch.setattr(service, "_utcnow", lambda: fixed_now)

    first_run = service.detect_for_domain(monitored_domain_id=domain.id)
    second_run = service.detect_for_domain(monitored_domain_id=domain.id)

    with session_factory() as db:
        stored = db.scalars(select(TrafficIncident)).all()

    assert len(first_run) == 1
    assert second_run == []
    assert len(stored) == 1
