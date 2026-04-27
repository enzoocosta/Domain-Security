from fastapi import APIRouter, HTTPException

from app.api.routes.error_utils import get_http_status_code
from app.core.exceptions import DomainSecurityError
from app.schemas.wordpress import WordPressAnalysisRequest, WordPressAnalysisResponse
from app.services.wordpress_security_service import WordPressSecurityService

router = APIRouter(tags=["wordpress"])
service = WordPressSecurityService()


@router.post(
    "/wordpress/analyze",
    response_model=WordPressAnalysisResponse,
    summary="Analisar seguranca publica de um site WordPress",
)
def analyze_wordpress(payload: WordPressAnalysisRequest) -> WordPressAnalysisResponse:
    try:
        return service.analyze_site(payload.url, options=payload.options)
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc),
            detail=str(exc),
        ) from exc
