from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.exceptions import InputValidationError
from app.db.models import TrafficEvent
from app.schemas.monitoring_plus import TrafficEventIngestBatch, TrafficEventIngestItem
from app.services.traffic_ingest_service import TrafficIngestService
from tests.premium_test_utils import (
    build_test_session_factory,
    create_monitored_domain,
    create_test_user,
)


def test_ingest_batch_persists_valid_events_and_rejects_future_rows():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = TrafficIngestService(session_factory=session_factory, max_batch_size=10)

    response = service.ingest_batch(
        monitored_domain_id=domain.id,
        batch=TrafficEventIngestBatch(
            events=[
                TrafficEventIngestItem(
                    client_ip=" 203.0.113.9 ",
                    method=" get ",
                    path=" /health ",
                    status_code=200,
                    user_agent=" curl/8.0 ",
                ),
                TrafficEventIngestItem(
                    occurred_at=datetime.now(tz=UTC) + timedelta(minutes=10),
                    path="/future",
                    status_code=200,
                ),
            ]
        ),
    )

    assert response.accepted == 1
    assert response.rejected == 1
    assert response.monitored_domain_id == domain.id

    with session_factory() as db:
        stored = db.scalar(select(TrafficEvent))

    assert stored is not None
    assert stored.client_ip == "203.0.113.9"
    assert stored.method == "GET"
    assert stored.path == "/health"
    assert stored.user_agent == "curl/8.0"


def test_ingest_batch_rejects_oversized_payload():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = TrafficIngestService(session_factory=session_factory, max_batch_size=1)

    with pytest.raises(InputValidationError):
        service.ingest_batch(
            monitored_domain_id=domain.id,
            batch=TrafficEventIngestBatch(
                events=[
                    TrafficEventIngestItem(path="/one"),
                    TrafficEventIngestItem(path="/two"),
                ]
            ),
        )


def test_purge_expired_events_deletes_only_old_rows():
    session_factory = build_test_session_factory()
    user = create_test_user(session_factory)
    domain = create_monitored_domain(session_factory, user_id=user.id)
    service = TrafficIngestService(session_factory=session_factory, retention_hours=24)
    now = datetime.now(tz=UTC)

    with session_factory() as db:
        db.add_all(
            [
                TrafficEvent(
                    monitored_domain_id=domain.id,
                    occurred_at=now - timedelta(hours=30),
                    received_at=now - timedelta(hours=30),
                    path="/old",
                    meta={},
                ),
                TrafficEvent(
                    monitored_domain_id=domain.id,
                    occurred_at=now - timedelta(hours=2),
                    received_at=now - timedelta(hours=2),
                    path="/recent",
                    meta={},
                ),
            ]
        )
        db.commit()

    deleted = service.purge_expired_events()

    with session_factory() as db:
        paths = [item.path for item in db.scalars(select(TrafficEvent)).all()]

    assert deleted == 1
    assert paths == ["/recent"]
