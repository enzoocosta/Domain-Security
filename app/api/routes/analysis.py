from fastapi import APIRouter, HTTPException

from app.api.routes.error_utils import get_http_status_code
from app.core.exceptions import DomainSecurityError
from app.schemas.analysis import AnalysisRequest, AnalysisResponse
from app.services.analysis_service import DomainAnalysisService

router = APIRouter(tags=["analysis"])
service = DomainAnalysisService()


@router.post(
    "/analyze", response_model=AnalysisResponse, summary="Analisar um dominio ou e-mail"
)
def analyze(payload: AnalysisRequest) -> AnalysisResponse:
    try:
        return service.analyze_target(payload.target)
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc),
            detail=str(exc),
        ) from exc
