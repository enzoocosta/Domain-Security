from fastapi import APIRouter, HTTPException

from app.api.routes.error_utils import get_http_status_code
from app.core.exceptions import DomainSecurityError
from app.schemas.history import DomainHistoryResponse
from app.services.analysis_history_service import AnalysisHistoryService

router = APIRouter(tags=["history"])
service = AnalysisHistoryService()


@router.get(
    "/history/{domain}",
    response_model=DomainHistoryResponse,
    summary="Listar historico por dominio",
)
def get_history(domain: str) -> DomainHistoryResponse:
    try:
        return service.list_history(domain)
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc),
            detail=str(exc),
        ) from exc
