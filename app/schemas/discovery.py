from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


DiscoveryRunStatus = Literal[
    "queued", "running", "completed", "partial", "failed", "unavailable"
]


class DiscoveryRunCreateInput(BaseModel):
    domain: str = Field(..., min_length=1, max_length=320)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Informe um dominio valido.")
        return cleaned


class DiscoveredSubdomainItem(BaseModel):
    id: int
    fqdn: str
    source: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    is_new: bool
    created_at: datetime


class DiscoveryRunSummary(BaseModel):
    id: int
    normalized_domain: str
    provider: str
    status: DiscoveryRunStatus
    asset_count: int = Field(default=0, ge=0)
    new_asset_count: int = Field(default=0, ge=0)
    error_message: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class DiscoveryRunDetail(BaseModel):
    run: DiscoveryRunSummary
    subdomains: list[DiscoveredSubdomainItem] = Field(default_factory=list)
