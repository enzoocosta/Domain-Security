from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


MonitoringFrequency = Literal["daily", "weekly", "monthly"]
MonitoringRunStatus = Literal["success", "partial", "error"]
AlertSeverity = Literal["alta", "media", "baixa"]
AlertStatus = Literal["open", "acknowledged", "resolved"]


class MonitoringDomainCreateInput(BaseModel):
    domain: str = Field(..., min_length=1, max_length=320)
    monitoring_frequency: MonitoringFrequency
    input_label: str | None = Field(default=None, max_length=255)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Informe um dominio valido.")
        return cleaned

    @field_validator("input_label")
    @classmethod
    def validate_label(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


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
    error_message: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class MonitoredDomainSummary(BaseModel):
    id: int
    normalized_domain: str
    input_label: str | None = None
    monitoring_frequency: MonitoringFrequency
    is_active: bool
    last_run_at: datetime | None = None
    next_run_at: datetime
    last_status: str | None = None
    latest_score: int | None = Field(default=None, ge=0, le=100)
    latest_severity: str | None = None
    open_alert_count: int = Field(default=0, ge=0)


class MonitoringDashboardResponse(BaseModel):
    user_email: str
    monitored_domains: list[MonitoredDomainSummary] = Field(default_factory=list)
    open_alerts: list[AlertEventSummary] = Field(default_factory=list)


class MonitoringDomainDetailResponse(BaseModel):
    domain: MonitoredDomainSummary
    recent_runs: list[MonitoringRunSummary] = Field(default_factory=list)
    open_alerts: list[AlertEventSummary] = Field(default_factory=list)
