from calendar import monthrange
from datetime import UTC, datetime, timedelta

from app.schemas.monitoring import MonitoringFrequency, MonitoringPlan


class MonitoringScheduleService:
    """Owns interval normalization and next-check calculations."""

    FREQUENCY_TO_MINUTES: dict[str, int] = {
        "1h": 60,
        "6h": 360,
        "12h": 720,
        "daily": 1440,
        "weekly": 10080,
        "monthly": 43200,
    }
    MIN_INTERVAL_BY_PLAN: dict[str, int] = {
        "standard": 360,
        "plus": 60,
    }

    def calculate_next_check_at(
        self,
        check_interval_minutes: int,
        *,
        reference_time: datetime | None = None,
    ) -> datetime:
        current = reference_time or datetime.now(tz=UTC)
        current = current if current.tzinfo else current.replace(tzinfo=UTC)
        return current + timedelta(minutes=check_interval_minutes)

    def calculate_retry_at(
        self,
        *,
        reference_time: datetime | None = None,
        retry_minutes: int = 15,
    ) -> datetime:
        current = reference_time or datetime.now(tz=UTC)
        current = current if current.tzinfo else current.replace(tzinfo=UTC)
        return current + timedelta(minutes=retry_minutes)

    def normalize_interval_minutes(
        self,
        *,
        monitoring_frequency: str | None = None,
        check_interval_minutes: int | None = None,
    ) -> int:
        if check_interval_minutes is not None:
            return int(check_interval_minutes)
        if monitoring_frequency is None:
            raise ValueError("Informe a frequencia ou o intervalo do monitoramento.")
        return self.frequency_to_minutes(monitoring_frequency)

    def validate_interval_for_plan(
        self, *, plan: MonitoringPlan, check_interval_minutes: int
    ) -> None:
        minimum = self.minimum_interval_for_plan(plan)
        if check_interval_minutes < minimum:
            if plan == "plus":
                raise ValueError("Monitoring Plus exige intervalo minimo de 1 hora.")
            raise ValueError("O plano standard exige intervalo minimo de 6 horas.")

    def frequency_to_minutes(self, frequency: str) -> int:
        normalized = str(frequency).strip().lower()
        if normalized not in self.FREQUENCY_TO_MINUTES:
            raise ValueError(
                "Frequencia invalida. Use 1h, 6h, 12h, daily, weekly ou monthly."
            )
        return self.FREQUENCY_TO_MINUTES[normalized]

    def frequency_label_for_interval(self, check_interval_minutes: int) -> str:
        for label, minutes in self.FREQUENCY_TO_MINUTES.items():
            if minutes == check_interval_minutes:
                return label
        if check_interval_minutes % 1440 == 0:
            return f"{check_interval_minutes // 1440}d"
        if check_interval_minutes % 60 == 0:
            return f"{check_interval_minutes // 60}h"
        return f"{check_interval_minutes}m"

    def minimum_interval_for_plan(self, plan: MonitoringPlan | str) -> int:
        return self.MIN_INTERVAL_BY_PLAN.get(str(plan).strip().lower(), 360)

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
        if frequency == "monthly":
            return self._add_one_month(current)
        return self.calculate_next_check_at(
            self.frequency_to_minutes(frequency), reference_time=current
        )

    @staticmethod
    def _add_one_month(reference_time: datetime) -> datetime:
        year = reference_time.year
        month = reference_time.month + 1
        if month > 12:
            month = 1
            year += 1
        day = min(reference_time.day, monthrange(year, month)[1])
        return reference_time.replace(year=year, month=month, day=day)
