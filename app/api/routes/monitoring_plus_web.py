"""Web routes for the Monitoring Plus premium dashboard.

These routes are intentionally thin: they only handle authentication via the
session cookie, parse form inputs and delegate to ``MonitoringPlusService``,
``BillingService`` and ``PremiumIngestTokenService``. No business rules live
here.
"""

from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.exceptions import DomainSecurityError
from app.presenters import configure_template_filters
from app.schemas.monitoring_plus import MonitoringPlusActivationInput
from app.services.auth_service import AuthenticationService
from app.services.monitoring_plus_service import MonitoringPlusService
from app.services.premium_ingest_token_service import PremiumIngestTokenService

router = APIRouter(include_in_schema=False)
templates = configure_template_filters(
    Jinja2Templates(directory=str(settings.templates_dir))
)
auth_service = AuthenticationService()
monitoring_plus_service = MonitoringPlusService()
ingest_token_service = PremiumIngestTokenService()


@router.get("/monitoring-plus", response_class=HTMLResponse)
def monitoring_plus_dashboard(request: Request) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login("/monitoring-plus")
    return _render_dashboard(request, user_id=current_user.id)


@router.post("/monitoring-plus/activate", response_class=HTMLResponse)
def activate_monitoring_plus(
    request: Request,
    domain: Annotated[str, Form(max_length=320)],
    monitoring_frequency: Annotated[str, Form(max_length=16)] = "daily",
    input_label: Annotated[str | None, Form(max_length=255)] = None,
) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login("/monitoring-plus")

    try:
        payload = MonitoringPlusActivationInput(
            domain=domain,
            monitoring_frequency=monitoring_frequency,
            input_label=input_label,
        )
        detail = monitoring_plus_service.activate_from_offer(
            user_id=current_user.id, payload=payload
        )
    except DomainSecurityError as exc:
        return _render_dashboard(
            request,
            user_id=current_user.id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        return _render_dashboard(
            request,
            user_id=current_user.id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return RedirectResponse(
        url=f"/monitoring-plus/domains/{detail.monitored_domain_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/monitoring-plus/domains/{monitored_domain_id}",
    response_class=HTMLResponse,
)
def monitoring_plus_domain_detail(
    request: Request,
    monitored_domain_id: int,
    new_token: str | None = None,
) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(
            f"/monitoring-plus/domains/{monitored_domain_id}"
        )
    return _render_domain_detail(
        request,
        user_id=current_user.id,
        monitored_domain_id=monitored_domain_id,
        new_token=new_token,
    )


@router.post(
    "/monitoring-plus/domains/{monitored_domain_id}/cancel",
    response_class=HTMLResponse,
)
def cancel_subscription(request: Request, monitored_domain_id: int) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(
            f"/monitoring-plus/domains/{monitored_domain_id}"
        )
    try:
        monitoring_plus_service.cancel_subscription(
            user_id=current_user.id, monitored_domain_id=monitored_domain_id
        )
    except DomainSecurityError as exc:
        return _render_domain_detail(
            request,
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=f"/monitoring-plus/domains/{monitored_domain_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/monitoring-plus/domains/{monitored_domain_id}/restart-trial",
    response_class=HTMLResponse,
)
def restart_trial(request: Request, monitored_domain_id: int) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(
            f"/monitoring-plus/domains/{monitored_domain_id}"
        )
    try:
        monitoring_plus_service.restart_trial(
            user_id=current_user.id, monitored_domain_id=monitored_domain_id
        )
    except DomainSecurityError as exc:
        return _render_domain_detail(
            request,
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=f"/monitoring-plus/domains/{monitored_domain_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/monitoring-plus/domains/{monitored_domain_id}/incidents/{incident_id}/resolve",
    response_class=HTMLResponse,
)
def resolve_incident(
    request: Request,
    monitored_domain_id: int,
    incident_id: int,
) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(
            f"/monitoring-plus/domains/{monitored_domain_id}"
        )
    try:
        monitoring_plus_service.resolve_incident(
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            incident_id=incident_id,
        )
    except DomainSecurityError as exc:
        return _render_domain_detail(
            request,
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=f"/monitoring-plus/domains/{monitored_domain_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/monitoring-plus/domains/{monitored_domain_id}/ingest-tokens",
    response_class=HTMLResponse,
)
def create_ingest_token(
    request: Request,
    monitored_domain_id: int,
    name: Annotated[str, Form(max_length=100)],
) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(
            f"/monitoring-plus/domains/{monitored_domain_id}"
        )
    try:
        result = ingest_token_service.create_token(
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            name=name,
        )
    except DomainSecurityError as exc:
        return _render_domain_detail(
            request,
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=(
            f"/monitoring-plus/domains/{monitored_domain_id}"
            f"?new_token={result.token}"
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/monitoring-plus/domains/{monitored_domain_id}/ingest-tokens/{token_id}/revoke",
    response_class=HTMLResponse,
)
def revoke_ingest_token(
    request: Request,
    monitored_domain_id: int,
    token_id: int,
) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(
            f"/monitoring-plus/domains/{monitored_domain_id}"
        )
    try:
        ingest_token_service.revoke_token(
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            token_id=token_id,
        )
    except DomainSecurityError as exc:
        return _render_domain_detail(
            request,
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=f"/monitoring-plus/domains/{monitored_domain_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# -- helpers ---------------------------------------------------------


def _render_dashboard(
    request: Request,
    *,
    user_id: int,
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    dashboard = monitoring_plus_service.get_dashboard(user_id=user_id)
    return templates.TemplateResponse(
        request=request,
        name="pages/monitoring_plus_dashboard.html",
        context={
            "request": request,
            "page_title": "Monitoring Plus",
            "page_name": "monitoring_plus",
            "dashboard": dashboard,
            "error": error,
        },
        status_code=status_code,
    )


def _render_domain_detail(
    request: Request,
    *,
    user_id: int,
    monitored_domain_id: int,
    error: str | None = None,
    new_token: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    try:
        detail = monitoring_plus_service.get_domain_detail(
            user_id=user_id, monitored_domain_id=monitored_domain_id
        )
    except DomainSecurityError as exc:
        return _render_dashboard(
            request,
            user_id=user_id,
            error=str(exc),
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return templates.TemplateResponse(
        request=request,
        name="pages/monitoring_plus_domain.html",
        context={
            "request": request,
            "page_title": f"Monitoring Plus - {detail.normalized_domain}",
            "page_name": "monitoring_plus",
            "detail": detail,
            "new_token": new_token,
            "error": error,
        },
        status_code=status_code,
    )


def _redirect_to_login(next_path: str) -> RedirectResponse:
    target = f"/auth/login?next={next_path}"
    return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
