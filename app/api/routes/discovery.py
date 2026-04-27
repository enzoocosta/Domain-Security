from fastapi import APIRouter, HTTPException, Request, status

from app.api.routes.error_utils import get_http_status_code
from app.core.exceptions import AuthorizationError, DomainSecurityError
from app.core.limiter import limiter
from app.schemas.discovery import (
    DiscoveryRunCreateInput,
    DiscoveryRunDetail,
    DiscoveryRunSummary,
)
from app.services.asset_discovery_service import AssetDiscoveryService
from app.services.auth_service import AuthenticationService

router = APIRouter(tags=["asset-discovery"])
auth_service = AuthenticationService()
service = AssetDiscoveryService()


@router.get(
    "/discovery",
    response_model=list[DiscoveryRunSummary],
    summary="Listar execucoes de asset discovery",
)
def list_discovery_runs(request: Request) -> list[DiscoveryRunSummary]:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticacao requerida."
        )
    return service.list_runs(user_id=current_user.id)


@router.post(
    "/discovery",
    response_model=DiscoveryRunDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Executar asset discovery",
)
@limiter.limit("3/minute")
def create_discovery_run(
    payload: DiscoveryRunCreateInput, request: Request
) -> DiscoveryRunDetail:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticacao requerida."
        )
    try:
        return service.create_run(user_id=current_user.id, domain=payload.domain)
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc


@router.get(
    "/discovery/{run_id}",
    response_model=DiscoveryRunDetail,
    summary="Detalhar execucao de asset discovery",
)
def get_discovery_run(run_id: int, request: Request) -> DiscoveryRunDetail:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticacao requerida."
        )
    try:
        return service.get_run_detail(user_id=current_user.id, run_id=run_id)
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc
