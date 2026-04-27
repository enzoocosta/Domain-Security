from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


MonitoringFrequency = Literal["1h", "6h", "12h", "daily", "weekly", "monthly"]
MonitoringRunStatus = Literal["success", "partial", "error"]
MonitoringStatus = Literal["active", "paused", "deleted"]
AlertSeverity = Literal["alta", "media", "baixa"]
AlertStatus = Literal["open", "acknowledged", "resolved"]
MonitoringPlan = Literal["standard", "plus"]


class MonitoringDomainCreateInput(BaseModel):
    domain: str = Field(..., min_length=1, max_length=320)
    monitoring_frequency: MonitoringFrequency | None = None
    check_interval_minutes: int | None = Field(default=None, ge=60, le=43200)
    input_label: str | None = Field(default=None, max_length=255)
    plan: MonitoringPlan = "standard"
    alert_contacts: list[str] = Field(default_factory=list)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Informe um dominio valido.")
        return cleaned

    @field_validator("monitoring_frequency")
    @classmethod
    def validate_frequency(
        cls, value: MonitoringFrequency | None
    ) -> MonitoringFrequency | None:
        if value is None:
            return None
        return value

    @field_validator("input_label")
    @classmethod
    def validate_label(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("alert_contacts")
    @classmethod
    def validate_contacts(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for item in value:
            cleaned = item.strip().lower()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            normalized.append(cleaned)
        return normalized


class AlertEventSummary(BaseModel):
    id: int
    alert_type: str
    severity: AlertSeverity
    title: str
    description: str
    status: AlertStatus
    created_at: datetime
    resolved_at: datetime | None = None


class MonitoringRunSummary(BaseModel):
    id: int
    score: int | None = Field(default=None, ge=0, le=100)
    severity: str | None = None
    run_status: MonitoringRunStatus
    trigger_type: str = "scheduled"
    error_message: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class MonitoredDomainSummary(BaseModel):
    id: int
    normalized_domain: str
    input_label: str | None = None
    monitoring_frequency: str
    plan: MonitoringPlan
    check_interval_minutes: int = Field(ge=60, le=43200)
    is_active: bool
    monitoring_status: MonitoringStatus
    paused_at: datetime | None = None
    deleted_at: datetime | None = None
    last_run_at: datetime | None = None
    last_attempt_at: datetime | None = None
    next_check_at: datetime
    next_run_at: datetime
    last_status: str | None = None
    latest_run_status: str | None = None
    latest_score: int | None = Field(default=None, ge=0, le=100)
    latest_severity: str | None = None
    open_alert_count: int = Field(default=0, ge=0)
    scheduler_warning: str | None = None
    last_alert_sent_at: datetime | None = None
    last_alert_reason: str | None = None
    alert_contacts: list[str] = Field(default_factory=list)


class MonitoringScorePoint(BaseModel):
    run_id: int
    score: int = Field(ge=0, le=100)
    run_status: MonitoringRunStatus
    recorded_at: datetime


class MonitoringDashboardResponse(BaseModel):
    user_email: str
    monitored_domains: list[MonitoredDomainSummary] = Field(default_factory=list)
    open_alerts: list[AlertEventSummary] = Field(default_factory=list)
    scheduler_warning: str | None = None


class MonitoringDomainDetailResponse(BaseModel):
    domain: MonitoredDomainSummary
    recent_runs: list[MonitoringRunSummary] = Field(default_factory=list)
    open_alerts: list[AlertEventSummary] = Field(default_factory=list)
    score_history: list[MonitoringScorePoint] = Field(default_factory=list)
    scheduler_warning: str | None = None
