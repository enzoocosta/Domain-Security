from threading import Event, Lock, Thread
from app.core.config import settings
from app.services.monitoring_service import MonitoringService


class MonitoringSchedulerService:
    """Runs due monitoring jobs in a lightweight background loop."""

    def __init__(
        self,
        monitoring_service: MonitoringService | None = None,
        *,
        poll_seconds: int | None = None,
    ) -> None:
        self.monitoring_service = monitoring_service or MonitoringService()
        self.poll_seconds = poll_seconds or settings.monitoring_poll_seconds
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._lock = Lock()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = Thread(
                target=self._run_loop, name="dsc-monitoring-scheduler", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            if self._thread is not None:
                self._thread.join(timeout=max(1, self.poll_seconds))
            self._thread = None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.monitoring_service.run_pending_checks()
            except Exception:
                pass
            self._stop_event.wait(self.poll_seconds)
