from fastapi import APIRouter

from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Application health check")
async def healthcheck() -> HealthResponse:
    return HealthResponse(status="ok", service="domain-security-checker")

