from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from app.api.routes.error_utils import get_http_status_code
from app.core.exceptions import AuthenticationError, DomainSecurityError
from app.core.limiter import limiter
from app.schemas.external_monitoring import (
    ExternalMonitoringDetailResponse,
    ExternalMonitoringListResponse,
    ExternalMonitoringMutationResponse,
)
from app.schemas.monitoring import MonitoringDomainCreateInput
from app.services.api_token_service import ApiTokenPrincipal, ApiTokenService
from app.services.monitoring_service import MonitoringService

router = APIRouter(prefix="/api/external/v1", tags=["external-monitoring"])
monitoring_service = MonitoringService()
api_token_service = ApiTokenService()


def _authenticate_request(
    authorization: Annotated[str | None, Header()] = None,
    x_api_token: Annotated[str | None, Header(alias="X-API-Token")] = None,
) -> ApiTokenPrincipal:
    raw_token = _extract_token(authorization, x_api_token)
    try:
        return api_token_service.authenticate_token(raw_token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc


@router.post(
    "/monitoring",
    response_model=ExternalMonitoringMutationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("30/minute")
def create_monitoring(
    request: Request,
    payload: MonitoringDomainCreateInput,
    principal: Annotated[ApiTokenPrincipal, Depends(_authenticate_request)],
) -> ExternalMonitoringMutationResponse:
    try:
        item = monitoring_service.create_monitored_domain(
            user_id=principal.user_id,
            domain=payload.domain,
            monitoring_frequency=payload.monitoring_frequency,
            check_interval_minutes=payload.check_interval_minutes,
            input_label=payload.input_label,
            plan=payload.plan,
            alert_contacts=payload.alert_contacts,
        )
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc
    return ExternalMonitoringMutationResponse(
        message="Monitoramento criado.", item=item
    )


@router.get("/monitoring", response_model=ExternalMonitoringListResponse)
def list_monitoring(
    principal: Annotated[ApiTokenPrincipal, Depends(_authenticate_request)],
) -> ExternalMonitoringListResponse:
    items = monitoring_service.list_monitored_domains(user_id=principal.user_id)
    return ExternalMonitoringListResponse(items=items)


@router.get(
    "/monitoring/{monitored_domain_id}", response_model=ExternalMonitoringDetailResponse
)
def detail_monitoring(
    monitored_domain_id: int,
    principal: Annotated[ApiTokenPrincipal, Depends(_authenticate_request)],
) -> ExternalMonitoringDetailResponse:
    try:
        item = monitoring_service.get_domain_detail(
            user_id=principal.user_id,
            monitored_domain_id=monitored_domain_id,
        )
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc
    return ExternalMonitoringDetailResponse(item=item)


@router.post(
    "/monitoring/{monitored_domain_id}/pause",
    response_model=ExternalMonitoringMutationResponse,
)
def pause_monitoring(
    monitored_domain_id: int,
    principal: Annotated[ApiTokenPrincipal, Depends(_authenticate_request)],
) -> ExternalMonitoringMutationResponse:
    try:
        item = monitoring_service.pause_monitored_domain(
            user_id=principal.user_id,
            monitored_domain_id=monitored_domain_id,
        )
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc
    return ExternalMonitoringMutationResponse(
        message="Monitoramento pausado.", item=item
    )


@router.post(
    "/monitoring/{monitored_domain_id}/resume",
    response_model=ExternalMonitoringMutationResponse,
)
def resume_monitoring(
    monitored_domain_id: int,
    principal: Annotated[ApiTokenPrincipal, Depends(_authenticate_request)],
) -> ExternalMonitoringMutationResponse:
    try:
        item = monitoring_service.resume_monitored_domain(
            user_id=principal.user_id,
            monitored_domain_id=monitored_domain_id,
        )
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc
    return ExternalMonitoringMutationResponse(
        message="Monitoramento retomado.", item=item
    )


@router.delete(
    "/monitoring/{monitored_domain_id}",
    response_model=ExternalMonitoringMutationResponse,
)
def delete_monitoring(
    monitored_domain_id: int,
    principal: Annotated[ApiTokenPrincipal, Depends(_authenticate_request)],
) -> ExternalMonitoringMutationResponse:
    try:
        item = monitoring_service.delete_monitored_domain(
            user_id=principal.user_id,
            monitored_domain_id=monitored_domain_id,
        )
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc
    return ExternalMonitoringMutationResponse(
        message="Monitoramento excluido.", item=item
    )


def _extract_token(authorization: str | None, x_api_token: str | None) -> str:
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            return token.strip()
    if x_api_token and x_api_token.strip():
        return x_api_token.strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Token ausente."
    )
