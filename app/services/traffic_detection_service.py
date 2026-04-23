"""Detects suspicious traffic patterns and persists them as ``TrafficIncident``.

Detection rules (objective and configurable via ``Settings``):

1. Traffic spike   - requests in the recent window exceed a multiple of the
                     baseline rate observed over a longer window.
2. Scan pattern    - a single client IP touches many distinct paths and/or has
                     a high 4xx ratio in a short window.
3. 5xx error spike - 5xx ratio in the recent window crosses a threshold with
                     enough requests to be statistically meaningful.
4. Suspicious UA   - any ingested event matches a known scanner User-Agent
                     substring.

The service is invoked by the Monitoring Plus scheduler. It is deliberately
side-effect free besides writing ``TrafficIncident`` rows, and it deduplicates
recent incidents using a ``dedupe_key`` to avoid alert storms.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import (
    MonitoredDomain,
    PremiumSubscription,
    TrafficEvent,
    TrafficIncident,
)
from app.db.session import SessionLocal
from app.services.billing_service import BillingService


@dataclass(frozen=True)
class DetectionConfig:
    spike_window_seconds: int
    spike_baseline_window_seconds: int
    spike_multiplier: float
    spike_min_requests: int
    scan_window_seconds: int
    scan_unique_paths_threshold: int
    scan_404_ratio_threshold: float
    error_window_seconds: int
    error_rate_threshold: float
    error_min_requests: int
    suspicious_user_agents: tuple[str, ...]
    dedupe_window_seconds: int = 30 * 60

    @classmethod
    def from_settings(cls) -> "DetectionConfig":
        return cls(
            spike_window_seconds=settings.monitoring_plus_spike_window_seconds,
            spike_baseline_window_seconds=settings.monitoring_plus_spike_baseline_window_seconds,
            spike_multiplier=settings.monitoring_plus_spike_multiplier,
            spike_min_requests=settings.monitoring_plus_spike_min_requests,
            scan_window_seconds=settings.monitoring_plus_scan_window_seconds,
            scan_unique_paths_threshold=settings.monitoring_plus_scan_unique_paths_threshold,
            scan_404_ratio_threshold=settings.monitoring_plus_scan_404_ratio_threshold,
            error_window_seconds=settings.monitoring_plus_error_window_seconds,
            error_rate_threshold=settings.monitoring_plus_error_rate_threshold,
            error_min_requests=settings.monitoring_plus_error_min_requests,
            suspicious_user_agents=settings.monitoring_plus_suspicious_user_agents,
        )


@dataclass
class _IncidentCandidate:
    incident_type: str
    severity: str
    title: str
    description: str
    evidence: dict
    dedupe_key: str


class TrafficDetectionService:
    def __init__(
        self,
        *,
        session_factory: Callable[[], Session] | None = None,
        billing_service: BillingService | None = None,
        config: DetectionConfig | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal
        self.billing_service = billing_service or BillingService(session_factory=self.session_factory)
        self.config = config or DetectionConfig.from_settings()

    def run_detection_cycle(self) -> list[TrafficIncident]:
        """Runs detection for every domain that has an entitled subscription.

        Returns the list of newly persisted incidents (already detached from
        the original session). Safe to call from a background scheduler.
        """

        created: list[TrafficIncident] = []
        with self.session_factory() as db:
            entitled_ids = self._select_entitled_domain_ids(db)
            for monitored_domain_id in entitled_ids:
                created.extend(self._detect_for_domain(db, monitored_domain_id=monitored_domain_id))
            db.commit()
        return created

    def detect_for_domain(self, *, monitored_domain_id: int) -> list[TrafficIncident]:
        with self.session_factory() as db:
            if not self.billing_service.is_entitled_in_session(
                db, monitored_domain_id=monitored_domain_id
            ):
                return []
            created = self._detect_for_domain(db, monitored_domain_id=monitored_domain_id)
            db.commit()
            return created

    # -- internals ----------------------------------------------------

    def _select_entitled_domain_ids(self, db: Session) -> list[int]:
        rows = db.execute(
            select(MonitoredDomain.id, PremiumSubscription)
            .join(PremiumSubscription, PremiumSubscription.monitored_domain_id == MonitoredDomain.id)
            .where(MonitoredDomain.deleted_at.is_(None))
        ).all()
        entitled: list[int] = []
        for monitored_id, subscription in rows:
            if self.billing_service.evaluate_entitlement(subscription):
                entitled.append(int(monitored_id))
        return entitled

    def _detect_for_domain(
        self,
        db: Session,
        *,
        monitored_domain_id: int,
    ) -> list[TrafficIncident]:
        now = self._utcnow()
        max_window = max(
            self.config.spike_window_seconds,
            self.config.spike_baseline_window_seconds,
            self.config.scan_window_seconds,
            self.config.error_window_seconds,
        )
        events = self._load_events(
            db,
            monitored_domain_id=monitored_domain_id,
            since=now - timedelta(seconds=max_window),
        )
        if not events:
            return []

        candidates: list[_IncidentCandidate] = []
        candidates.extend(self._detect_traffic_spike(events, now=now))
        candidates.extend(self._detect_scan_pattern(events, now=now))
        candidates.extend(self._detect_error_spike(events, now=now))
        candidates.extend(self._detect_suspicious_user_agents(events, now=now))

        if not candidates:
            return []

        return self._persist_incidents(
            db,
            monitored_domain_id=monitored_domain_id,
            candidates=candidates,
            now=now,
        )

    def _load_events(
        self,
        db: Session,
        *,
        monitored_domain_id: int,
        since: datetime,
    ) -> list[TrafficEvent]:
        rows = db.scalars(
            select(TrafficEvent)
            .where(
                TrafficEvent.monitored_domain_id == monitored_domain_id,
                TrafficEvent.occurred_at >= since,
            )
            .order_by(TrafficEvent.occurred_at.asc())
        ).all()
        return list(rows)

    # -- detection rules ---------------------------------------------

    def _detect_traffic_spike(
        self,
        events: Sequence[TrafficEvent],
        *,
        now: datetime,
    ) -> list[_IncidentCandidate]:
        recent_window_start = now - timedelta(seconds=self.config.spike_window_seconds)
        baseline_start = now - timedelta(seconds=self.config.spike_baseline_window_seconds)

        recent_count = sum(
            1 for event in events if self._aware(event.occurred_at) >= recent_window_start
        )
        if recent_count < self.config.spike_min_requests:
            return []

        baseline_events = [
            event
            for event in events
            if baseline_start <= self._aware(event.occurred_at) < recent_window_start
        ]
        if not baseline_events:
            return []

        baseline_seconds = max(
            1,
            self.config.spike_baseline_window_seconds - self.config.spike_window_seconds,
        )
        baseline_rate_per_second = len(baseline_events) / baseline_seconds
        recent_rate_per_second = recent_count / max(1, self.config.spike_window_seconds)

        if baseline_rate_per_second <= 0:
            return []
        if recent_rate_per_second < baseline_rate_per_second * self.config.spike_multiplier:
            return []

        return [
            _IncidentCandidate(
                incident_type="traffic_spike",
                severity="high",
                title="Pico anomalo de requisicoes detectado",
                description=(
                    f"Foram observadas {recent_count} requisicoes nos ultimos "
                    f"{self.config.spike_window_seconds}s, contra uma media de "
                    f"{baseline_rate_per_second * self.config.spike_window_seconds:.1f} "
                    f"requisicoes por janela equivalente no periodo de referencia."
                ),
                evidence={
                    "recent_requests": recent_count,
                    "recent_window_seconds": self.config.spike_window_seconds,
                    "baseline_window_seconds": self.config.spike_baseline_window_seconds,
                    "baseline_rate_per_second": round(baseline_rate_per_second, 4),
                    "recent_rate_per_second": round(recent_rate_per_second, 4),
                    "multiplier_threshold": self.config.spike_multiplier,
                },
                dedupe_key=self._dedupe_key("traffic_spike", now, self.config.spike_window_seconds),
            )
        ]

    def _detect_scan_pattern(
        self,
        events: Sequence[TrafficEvent],
        *,
        now: datetime,
    ) -> list[_IncidentCandidate]:
        window_start = now - timedelta(seconds=self.config.scan_window_seconds)
        windowed = [event for event in events if self._aware(event.occurred_at) >= window_start]
        if not windowed:
            return []

        per_ip_paths: dict[str, set[str]] = defaultdict(set)
        per_ip_404: dict[str, int] = defaultdict(int)
        per_ip_total: dict[str, int] = defaultdict(int)
        for event in windowed:
            ip = event.client_ip or "unknown"
            per_ip_total[ip] += 1
            if event.path:
                per_ip_paths[ip].add(event.path)
            if event.status_code == 404:
                per_ip_404[ip] += 1

        candidates: list[_IncidentCandidate] = []
        for ip, total in per_ip_total.items():
            if total < self.config.scan_unique_paths_threshold:
                continue
            unique_paths = len(per_ip_paths.get(ip, set()))
            ratio_404 = per_ip_404.get(ip, 0) / total if total else 0
            triggers_paths = unique_paths >= self.config.scan_unique_paths_threshold
            triggers_404 = ratio_404 >= self.config.scan_404_ratio_threshold
            if not (triggers_paths and triggers_404):
                continue
            candidates.append(
                _IncidentCandidate(
                    incident_type="scan_pattern",
                    severity="high",
                    title=f"Padrao de varredura detectado vindo de {ip}",
                    description=(
                        f"O IP {ip} acessou {unique_paths} caminhos distintos com "
                        f"{ratio_404 * 100:.0f}% de respostas 404 nos ultimos "
                        f"{self.config.scan_window_seconds}s."
                    ),
                    evidence={
                        "client_ip": ip,
                        "unique_paths": unique_paths,
                        "requests": total,
                        "ratio_404": round(ratio_404, 4),
                        "window_seconds": self.config.scan_window_seconds,
                    },
                    dedupe_key=self._dedupe_key(
                        f"scan_pattern:{ip}", now, self.config.scan_window_seconds
                    ),
                )
            )
        return candidates

    def _detect_error_spike(
        self,
        events: Sequence[TrafficEvent],
        *,
        now: datetime,
    ) -> list[_IncidentCandidate]:
        window_start = now - timedelta(seconds=self.config.error_window_seconds)
        windowed = [event for event in events if self._aware(event.occurred_at) >= window_start]
        if len(windowed) < self.config.error_min_requests:
            return []

        error_count = sum(1 for event in windowed if event.status_code and event.status_code >= 500)
        rate = error_count / len(windowed)
        if rate < self.config.error_rate_threshold:
            return []

        return [
            _IncidentCandidate(
                incident_type="error_spike",
                severity="high",
                title="Aumento anomalo de erros 5xx",
                description=(
                    f"{error_count} de {len(windowed)} requisicoes "
                    f"({rate * 100:.0f}%) retornaram erro 5xx nos ultimos "
                    f"{self.config.error_window_seconds}s."
                ),
                evidence={
                    "errors_5xx": error_count,
                    "total_requests": len(windowed),
                    "error_rate": round(rate, 4),
                    "window_seconds": self.config.error_window_seconds,
                },
                dedupe_key=self._dedupe_key("error_spike", now, self.config.error_window_seconds),
            )
        ]

    def _detect_suspicious_user_agents(
        self,
        events: Sequence[TrafficEvent],
        *,
        now: datetime,
    ) -> list[_IncidentCandidate]:
        if not self.config.suspicious_user_agents:
            return []
        window_seconds = self.config.scan_window_seconds
        window_start = now - timedelta(seconds=window_seconds)
        matches: Counter[tuple[str, str]] = Counter()
        for event in events:
            if self._aware(event.occurred_at) < window_start:
                continue
            user_agent = (event.user_agent or "").lower()
            if not user_agent:
                continue
            for needle in self.config.suspicious_user_agents:
                if needle and needle in user_agent:
                    matches[(needle, event.client_ip or "unknown")] += 1
                    break

        candidates: list[_IncidentCandidate] = []
        for (needle, ip), count in matches.items():
            candidates.append(
                _IncidentCandidate(
                    incident_type="suspicious_user_agent",
                    severity="medium",
                    title=f"User-Agent suspeito detectado: {needle}",
                    description=(
                        f"O IP {ip} apresentou {count} requisicoes com User-Agent "
                        f"associado a ferramenta de varredura ('{needle}')."
                    ),
                    evidence={
                        "client_ip": ip,
                        "matched_user_agent_substring": needle,
                        "occurrences": count,
                        "window_seconds": window_seconds,
                    },
                    dedupe_key=self._dedupe_key(
                        f"suspicious_user_agent:{needle}:{ip}", now, window_seconds
                    ),
                )
            )
        return candidates

    # -- persistence -------------------------------------------------

    def _persist_incidents(
        self,
        db: Session,
        *,
        monitored_domain_id: int,
        candidates: Iterable[_IncidentCandidate],
        now: datetime,
    ) -> list[TrafficIncident]:
        dedupe_window_start = now - timedelta(seconds=self.config.dedupe_window_seconds)
        existing_keys = set(
            db.scalars(
                select(TrafficIncident.dedupe_key)
                .where(
                    TrafficIncident.monitored_domain_id == monitored_domain_id,
                    TrafficIncident.detected_at >= dedupe_window_start,
                    TrafficIncident.dedupe_key.is_not(None),
                )
            ).all()
        )

        created: list[TrafficIncident] = []
        for candidate in candidates:
            if candidate.dedupe_key in existing_keys:
                continue
            incident = TrafficIncident(
                monitored_domain_id=monitored_domain_id,
                incident_type=candidate.incident_type,
                severity=candidate.severity,
                title=candidate.title,
                description=candidate.description,
                evidence=candidate.evidence,
                status="open",
                dedupe_key=candidate.dedupe_key,
                email_delivery_status="pending",
                detected_at=now,
            )
            db.add(incident)
            created.append(incident)
            existing_keys.add(candidate.dedupe_key)
        if created:
            db.flush()
        return created

    @staticmethod
    def _dedupe_key(prefix: str, now: datetime, window_seconds: int) -> str:
        bucket = int(now.timestamp() // max(60, window_seconds))
        return f"{prefix}:{bucket}"

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)


def _domain_count_per_period(
    db: Session, *, monitored_domain_id: int, since: datetime
) -> int:
    """Convenience helper for tests; counts events in a given window."""

    return int(
        db.scalar(
            select(func.count(TrafficEvent.id)).where(
                TrafficEvent.monitored_domain_id == monitored_domain_id,
                TrafficEvent.occurred_at >= since,
            )
        )
        or 0
    )
