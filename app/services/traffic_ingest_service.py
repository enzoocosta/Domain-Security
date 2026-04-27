"""Persists traffic events ingested for a Monitoring Plus monitored domain.

This service is intentionally minimal:
- it validates the batch limits;
- it stores normalized rows in ``premium_traffic_events``;
- it never performs detection itself (that is the job of
  ``TrafficDetectionService``);
- it never deals with billing (the route is responsible for invoking
  ``BillingService.require_entitlement`` upfront).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import InputValidationError
from app.db.models import TrafficEvent
from app.db.session import SessionLocal
from app.schemas.monitoring_plus import (
    TrafficEventIngestBatch,
    TrafficEventIngestItem,
    TrafficEventIngestResponse,
)


class TrafficIngestService:
    def __init__(
        self,
        *,
        session_factory: Callable[[], Session] | None = None,
        max_batch_size: int | None = None,
        retention_hours: int | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal
        self.max_batch_size = (
            max_batch_size
            if max_batch_size is not None
            else settings.monitoring_plus_ingest_max_batch
        )
        self.retention_hours = (
            retention_hours
            if retention_hours is not None
            else settings.monitoring_plus_event_retention_hours
        )

    def ingest_batch(
        self,
        *,
        monitored_domain_id: int,
        batch: TrafficEventIngestBatch,
    ) -> TrafficEventIngestResponse:
        if not batch.events:
            return TrafficEventIngestResponse(
                accepted=0, rejected=0, monitored_domain_id=monitored_domain_id
            )
        if len(batch.events) > self.max_batch_size:
            raise InputValidationError(
                f"Lote excede o limite de {self.max_batch_size} eventos."
            )

        accepted = 0
        rejected = 0
        rows: list[TrafficEvent] = []
        received_at = self._utcnow()
        for event in batch.events:
            try:
                rows.append(
                    self._build_row(
                        event,
                        monitored_domain_id=monitored_domain_id,
                        received_at=received_at,
                    )
                )
                accepted += 1
            except InputValidationError:
                rejected += 1

        if rows:
            with self.session_factory() as db:
                db.bulk_save_objects(rows)
                db.commit()

        return TrafficEventIngestResponse(
            accepted=accepted,
            rejected=rejected,
            monitored_domain_id=monitored_domain_id,
        )

    def purge_expired_events(self) -> int:
        """Removes events older than the configured retention window.

        Returns the number of deleted rows. Safe to call from a scheduler;
        idempotent and bounded by retention configuration.
        """

        if self.retention_hours <= 0:
            return 0
        threshold = self._utcnow() - timedelta(hours=self.retention_hours)
        with self.session_factory() as db:
            result = db.execute(
                delete(TrafficEvent).where(TrafficEvent.occurred_at < threshold)
            )
            db.commit()
            return int(result.rowcount or 0)

    # -- helpers ------------------------------------------------------

    def _build_row(
        self,
        event: TrafficEventIngestItem,
        *,
        monitored_domain_id: int,
        received_at: datetime,
    ) -> TrafficEvent:
        occurred_at = event.occurred_at or received_at
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=UTC)
        # Discard absurd future timestamps (more than 5 minutes ahead)
        if occurred_at > received_at + timedelta(minutes=5):
            raise InputValidationError("occurred_at no futuro distante.")

        method = (event.method or "").strip().upper() or None
        path = (event.path or "").strip() or None
        client_ip = (event.client_ip or "").strip() or None
        user_agent = (event.user_agent or "").strip() or None
        referer = (event.referer or "").strip() or None
        request_id = (event.request_id or "").strip() or None
        meta = event.meta if isinstance(event.meta, dict) else {}

        return TrafficEvent(
            monitored_domain_id=monitored_domain_id,
            occurred_at=occurred_at,
            received_at=received_at,
            client_ip=client_ip,
            method=method,
            path=path,
            status_code=event.status_code,
            user_agent=user_agent,
            referer=referer,
            request_id=request_id,
            meta=meta,
        )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
