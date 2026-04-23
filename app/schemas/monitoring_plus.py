from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.utils.input_parser import normalize_target


class MonitoringPlusActivationInput(BaseModel):
    """Payload received from the post-analysis premium offer."""

    domain: str = Field(min_length=3, max_length=320)
    input_label: str | None = Field(default=None, max_length=255)
    monitoring_frequency: str = Field(default="daily", max_length=16)

    @field_validator("domain")
    @classmethod
    def _normalize_domain(cls, value: str) -> str:
        return normalize_target(value).analysis_domain

    @field_validator("monitoring_frequency")
    @classmethod
    def _validate_frequency(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in {"daily", "weekly", "monthly"}:
            raise ValueError("Frequencia invalida. Use daily, weekly ou monthly.")
        return cleaned


class PremiumSubscriptionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    monitored_domain_id: int
    plan_code: str
    status: str
    trial_started_at: datetime | None
    trial_ends_at: datetime | None
    activated_at: datetime | None
    canceled_at: datetime | None
    current_period_end: datetime | None
    is_entitled: bool
    days_left_in_trial: int | None


class PremiumIngestTokenSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    monitored_domain_id: int
    name: str
    token_prefix: str
    is_active: bool
    last_used_at: datetime | None
    created_at: datetime


class PremiumIngestTokenCreateInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class PremiumIngestTokenCreateResult(BaseModel):
    token: str
    token_item: PremiumIngestTokenSummary


class TrafficEventIngestItem(BaseModel):
    occurred_at: datetime | None = None
    client_ip: str | None = Field(default=None, max_length=64)
    method: str | None = Field(default=None, max_length=16)
    path: str | None = Field(default=None, max_length=1024)
    status_code: int | None = Field(default=None, ge=100, le=599)
    user_agent: str | None = Field(default=None, max_length=512)
    referer: str | None = Field(default=None, max_length=1024)
    request_id: str | None = Field(default=None, max_length=128)
    meta: dict[str, Any] = Field(default_factory=dict)


class TrafficEventIngestBatch(BaseModel):
    events: list[TrafficEventIngestItem] = Field(default_factory=list)


class TrafficEventIngestResponse(BaseModel):
    accepted: int
    rejected: int
    monitored_domain_id: int


class TrafficIncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    monitored_domain_id: int
    incident_type: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any]
    status: str
    detected_at: datetime
    resolved_at: datetime | None
    email_delivery_status: str
    email_sent_at: datetime | None


class MonitoringPlusDomainStats(BaseModel):
    events_last_hour: int
    events_last_24h: int
    open_incidents: int
    last_event_at: datetime | None


class MonitoringPlusDomainDetail(BaseModel):
    monitored_domain_id: int
    normalized_domain: str
    input_label: str | None
    subscription: PremiumSubscriptionSummary | None
    stats: MonitoringPlusDomainStats
    recent_incidents: list[TrafficIncidentSummary]
    ingest_tokens: list[PremiumIngestTokenSummary]


class MonitoringPlusDomainCard(BaseModel):
    monitored_domain_id: int
    normalized_domain: str
    input_label: str | None
    subscription_status: str | None
    is_entitled: bool
    days_left_in_trial: int | None
    open_incidents: int
    last_incident_at: datetime | None


class MonitoringPlusDashboard(BaseModel):
    user_email: str
    items: list[MonitoringPlusDomainCard]
    total_open_incidents: int
