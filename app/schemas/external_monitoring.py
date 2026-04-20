from pydantic import BaseModel, Field

from app.schemas.monitoring import MonitoredDomainSummary, MonitoringDomainDetailResponse


class ExternalMonitoringListResponse(BaseModel):
    items: list[MonitoredDomainSummary] = Field(default_factory=list)


class ExternalMonitoringDetailResponse(BaseModel):
    item: MonitoringDomainDetailResponse


class ExternalMonitoringMutationResponse(BaseModel):
    message: str
    item: MonitoredDomainSummary
