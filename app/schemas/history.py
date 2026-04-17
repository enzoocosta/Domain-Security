from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

OverallSeverity = Literal["excelente", "bom", "atencao", "alto", "critico"]


class HistoryItem(BaseModel):
    id: int
    created_at: datetime
    input_target: str
    analysis_domain: str
    score: int = Field(..., ge=0, le=100)
    severity: OverallSeverity
    summary: str


class SnapshotChangeItem(BaseModel):
    field: str
    label: str
    previous: str | int | bool | None = None
    current: str | int | bool | None = None


class AnalysisDiffSummary(BaseModel):
    has_previous_snapshot: bool
    message: str
    previous_snapshot_created_at: datetime | None = None
    previous_score: int | None = Field(default=None, ge=0, le=100)
    current_score: int = Field(..., ge=0, le=100)
    score_delta: int | None = None
    previous_severity: OverallSeverity | None = None
    current_severity: OverallSeverity
    severity_changed: bool = False
    changed_checks: list[SnapshotChangeItem] = Field(default_factory=list)
    added_findings: list[str] = Field(default_factory=list)
    removed_findings: list[str] = Field(default_factory=list)


class DomainHistoryResponse(BaseModel):
    domain: str
    items: list[HistoryItem] = Field(default_factory=list)
