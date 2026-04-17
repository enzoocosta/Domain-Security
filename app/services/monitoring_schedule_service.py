from calendar import monthrange
from datetime import UTC, datetime, timedelta

from app.schemas.monitoring import MonitoringFrequency


class MonitoringScheduleService:
    """Calculates the next execution time for monitored domains."""

    def calculate_next_run_at(
        self,
        frequency: MonitoringFrequency,
        *,
        reference_time: datetime | None = None,
    ) -> datetime:
        current = reference_time or datetime.now(tz=UTC)
        current = current if current.tzinfo else current.replace(tzinfo=UTC)
        if frequency == "daily":
            return current + timedelta(days=1)
        if frequency == "weekly":
            return current + timedelta(days=7)
        return self._add_one_month(current)

    @staticmethod
    def _add_one_month(reference_time: datetime) -> datetime:
        year = reference_time.year
        month = reference_time.month + 1
        if month > 12:
            month = 1
            year += 1
        day = min(reference_time.day, monthrange(year, month)[1])
        return reference_time.replace(year=year, month=month, day=day)
