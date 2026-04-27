from datetime import UTC, datetime
import hmac

from fastapi import APIRouter, Header, HTTPException, status

from app.core.config import settings
from app.services.monitoring_service import MonitoringService

router = APIRouter(include_in_schema=False)
monitoring_service = MonitoringService()


@router.post("/internal/run-checks")
def run_checks(
    x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
):
    expected = settings.internal_run_checks_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token interno nao configurado.",
        )
    provided = (x_internal_token or "").strip()
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token interno invalido.",
        )
    result = monitoring_service.run_pending_checks()
    return {
        "processed": result.processed,
        "succeeded": result.succeeded,
        "failed": result.failed,
        "checked_at": datetime.now(tz=UTC),
    }
