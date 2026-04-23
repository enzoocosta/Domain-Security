"""Public endpoint that receives traffic events from the customer's edge.

Authentication uses a per-domain ``PremiumIngestToken``. The route is the only
place that translates a token into a ``monitored_domain_id`` and enforces the
billing entitlement check before forwarding the batch to the service layer.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from app.api.routes.error_utils import get_http_status_code
from app.core.exceptions import AuthenticationError, DomainSecurityError
from app.schemas.monitoring_plus import (
    TrafficEventIngestBatch,
    TrafficEventIngestResponse,
)
from app.services.billing_service import BillingService
from app.services.premium_ingest_token_service import (
    PremiumIngestPrincipal,
    PremiumIngestTokenService,
)
from app.services.traffic_ingest_service import TrafficIngestService

router = APIRouter(prefix="/api/ingest/v1", tags=["monitoring-plus-ingest"])

ingest_token_service = PremiumIngestTokenService()
billing_service = BillingService()
traffic_ingest_service = TrafficIngestService()


def _authenticate_ingest(
    authorization: Annotated[str | None, Header()] = None,
    x_ingest_token: Annotated[str | None, Header(alias="X-Ingest-Token")] = None,
) -> PremiumIngestPrincipal:
    raw_token = _extract_token(authorization, x_ingest_token)
    try:
        return ingest_token_service.authenticate_token(raw_token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc


@router.post(
    "/traffic",
    response_model=TrafficEventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_traffic(
    payload: TrafficEventIngestBatch,
    principal: Annotated[PremiumIngestPrincipal, Depends(_authenticate_ingest)],
) -> TrafficEventIngestResponse:
    try:
        billing_service.require_entitlement(
            monitored_domain_id=principal.monitored_domain_id
        )
        return traffic_ingest_service.ingest_batch(
            monitored_domain_id=principal.monitored_domain_id,
            batch=payload,
        )
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc), detail=str(exc)
        ) from exc


def _extract_token(authorization: str | None, x_ingest_token: str | None) -> str:
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            return token.strip()
    if x_ingest_token and x_ingest_token.strip():
        return x_ingest_token.strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Token de ingestao ausente."
    )
