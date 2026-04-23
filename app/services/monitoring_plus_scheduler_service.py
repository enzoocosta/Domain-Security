"""Background scheduler for the Monitoring Plus pipeline.

Runs three independent loops sharing the same lifecycle:

- detection cycle (TrafficDetectionService)
- alert dispatch (MonitoringPlusAlertService)
- traffic event purge (TrafficIngestService)

Mirrors the ``MonitoringSchedulerService`` pattern: lightweight daemon thread,
swallowing exceptions to keep the loop alive, started/stopped from the FastAPI
lifespan.
"""

from __future__ import annotations

from threading import Event, Lock, Thread
from time import monotonic

from app.core.config import settings
from app.services.monitoring_plus_alert_service import MonitoringPlusAlertService
from app.services.traffic_detection_service import TrafficDetectionService
from app.services.traffic_ingest_service import TrafficIngestService


class MonitoringPlusSchedulerService:
    PURGE_INTERVAL_SECONDS = 3600

    def __init__(
        self,
        *,
        detection_service: TrafficDetectionService | None = None,
        alert_service: MonitoringPlusAlertService | None = None,
        ingest_service: TrafficIngestService | None = None,
        detection_interval_seconds: int | None = None,
        alert_dispatch_interval_seconds: int | None = None,
    ) -> None:
        self.detection_service = detection_service or TrafficDetectionService()
        self.alert_service = alert_service or MonitoringPlusAlertService()
        self.ingest_service = ingest_service or TrafficIngestService()
        self.detection_interval_seconds = (
            detection_interval_seconds
            if detection_interval_seconds is not None
            else settings.monitoring_plus_detection_interval_seconds
        )
        self.alert_dispatch_interval_seconds = (
            alert_dispatch_interval_seconds
            if alert_dispatch_interval_seconds is not None
            else settings.monitoring_plus_alert_dispatch_interval_seconds
        )
        self._poll_seconds = max(
            5,
            min(
                self.detection_interval_seconds,
                self.alert_dispatch_interval_seconds,
            ),
        )
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._lock = Lock()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = Thread(
                target=self._run_loop,
                name="dsc-monitoring-plus-scheduler",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            if self._thread is not None:
                self._thread.join(timeout=max(1, self._poll_seconds))
            self._thread = None

    def _run_loop(self) -> None:
        last_detection_at = 0.0
        last_dispatch_at = 0.0
        last_purge_at = 0.0
        while not self._stop_event.is_set():
            now = monotonic()
            if now - last_detection_at >= self.detection_interval_seconds:
                try:
                    self.detection_service.run_detection_cycle()
                except Exception:
                    pass
                last_detection_at = now
            if now - last_dispatch_at >= self.alert_dispatch_interval_seconds:
                try:
                    self.alert_service.dispatch_pending_incidents()
                except Exception:
                    pass
                last_dispatch_at = now
            if now - last_purge_at >= self.PURGE_INTERVAL_SECONDS:
                try:
                    self.ingest_service.purge_expired_events()
                except Exception:
                    pass
                last_purge_at = now
            self._stop_event.wait(self._poll_seconds)
