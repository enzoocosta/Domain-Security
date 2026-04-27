from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.exceptions import AuthorizationError, DomainSecurityError
from app.presenters import configure_template_filters
from app.services.api_token_service import ApiTokenService
from app.services.auth_service import AuthenticationService
from app.services.monitoring_service import MonitoringService

router = APIRouter(include_in_schema=False)
templates = configure_template_filters(
    Jinja2Templates(directory=str(settings.templates_dir))
)
auth_service = AuthenticationService()
monitoring_service = MonitoringService()
api_token_service = ApiTokenService()


@router.get("/monitoring", response_class=HTMLResponse)
def monitoring_dashboard(request: Request) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login("/monitoring")

    return _render_dashboard(request, user_id=current_user.id)


@router.post("/monitoring/domains", response_class=HTMLResponse)
def create_monitored_domain(
    request: Request,
    domain: Annotated[str, Form(max_length=320)],
    check_interval_minutes: Annotated[int | None, Form()] = None,
    monitoring_frequency: Annotated[str | None, Form(max_length=16)] = None,
    input_label: Annotated[str | None, Form(max_length=255)] = None,
) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login("/monitoring")

    try:
        monitoring_service.create_monitored_domain(
            user_id=current_user.id,
            domain=domain,
            monitoring_frequency=monitoring_frequency,
            check_interval_minutes=check_interval_minutes,
            input_label=input_label,
        )
        return RedirectResponse(
            url="/monitoring", status_code=status.HTTP_303_SEE_OTHER
        )
    except DomainSecurityError as exc:
        return _render_dashboard(
            request,
            user_id=current_user.id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@router.get("/monitoring/domains/{monitored_domain_id}", response_class=HTMLResponse)
def monitored_domain_detail(request: Request, monitored_domain_id: int) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(f"/monitoring/domains/{monitored_domain_id}")

    try:
        detail = monitoring_service.get_domain_detail(
            user_id=current_user.id,
            monitored_domain_id=monitored_domain_id,
        )
    except AuthorizationError:
        return RedirectResponse(
            url="/monitoring", status_code=status.HTTP_303_SEE_OTHER
        )
    except DomainSecurityError as exc:
        return _render_dashboard(
            request,
            user_id=current_user.id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return templates.TemplateResponse(
        request=request,
        name="pages/monitoring_domain.html",
        context={
            "request": request,
            "page_title": f"Monitoramento de {detail.domain.normalized_domain}",
            "page_name": "monitoring",
            "detail": detail,
            "error": None,
        },
    )


@router.post("/monitoring/domains/{monitored_domain_id}/pause")
def pause_monitored_domain(
    request: Request,
    monitored_domain_id: int,
    next_path: Annotated[str, Form(max_length=512)] = "/monitoring",
):
    return _handle_status_change(
        request,
        monitored_domain_id=monitored_domain_id,
        next_path=next_path,
        action="pause",
    )


@router.post("/monitoring/domains/{monitored_domain_id}/resume")
def resume_monitored_domain(
    request: Request,
    monitored_domain_id: int,
    next_path: Annotated[str, Form(max_length=512)] = "/monitoring",
):
    return _handle_status_change(
        request,
        monitored_domain_id=monitored_domain_id,
        next_path=next_path,
        action="resume",
    )


@router.post("/monitoring/domains/{monitored_domain_id}/delete")
def delete_monitored_domain(
    request: Request,
    monitored_domain_id: int,
    next_path: Annotated[str, Form(max_length=512)] = "/monitoring",
):
    return _handle_status_change(
        request,
        monitored_domain_id=monitored_domain_id,
        next_path=next_path,
        action="delete",
    )


@router.post("/monitoring/api-tokens", response_class=HTMLResponse)
def create_api_token(
    request: Request,
    token_name: Annotated[str, Form(max_length=100)],
):
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login("/monitoring")

    try:
        created = api_token_service.create_token(
            user_id=current_user.id, name=token_name
        )
    except DomainSecurityError as exc:
        return _render_dashboard(
            request,
            user_id=current_user.id,
            api_token_error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return _render_dashboard(
        request,
        user_id=current_user.id,
        new_api_token=created.token,
    )


@router.post("/monitoring/api-tokens/{token_id}/activate")
def activate_api_token(request: Request, token_id: int):
    return _toggle_api_token(request, token_id=token_id, is_active=True)


@router.post("/monitoring/api-tokens/{token_id}/deactivate")
def deactivate_api_token(request: Request, token_id: int):
    return _toggle_api_token(request, token_id=token_id, is_active=False)


def _redirect_to_login(path: str) -> RedirectResponse:
    return RedirectResponse(
        url=f"/auth/login?next={quote(path)}", status_code=status.HTTP_303_SEE_OTHER
    )


def _render_dashboard(
    request: Request,
    *,
    user_id: int,
    error: str | None = None,
    api_token_error: str | None = None,
    new_api_token: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    dashboard = monitoring_service.get_dashboard(user_id=user_id)
    api_tokens = api_token_service.list_tokens(user_id=user_id)
    return templates.TemplateResponse(
        request=request,
        name="pages/monitoring_dashboard.html",
        context={
            "request": request,
            "page_title": "Monitoramento autenticado",
            "page_name": "monitoring",
            "dashboard": dashboard,
            "api_tokens": api_tokens,
            "new_api_token": new_api_token,
            "error": error,
            "api_token_error": api_token_error,
        },
        status_code=status_code,
    )


def _handle_status_change(
    request: Request,
    *,
    monitored_domain_id: int,
    next_path: str,
    action: str,
):
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login(next_path or "/monitoring")

    try:
        if action == "pause":
            monitoring_service.pause_monitored_domain(
                user_id=current_user.id,
                monitored_domain_id=monitored_domain_id,
            )
        elif action == "resume":
            monitoring_service.resume_monitored_domain(
                user_id=current_user.id,
                monitored_domain_id=monitored_domain_id,
            )
        else:
            monitoring_service.delete_monitored_domain(
                user_id=current_user.id,
                monitored_domain_id=monitored_domain_id,
            )
    except DomainSecurityError as exc:
        return _render_dashboard(
            request,
            user_id=current_user.id,
            error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    redirect_target = (
        "/monitoring" if action == "delete" else (next_path or "/monitoring")
    )
    return RedirectResponse(url=redirect_target, status_code=status.HTTP_303_SEE_OTHER)


def _toggle_api_token(
    request: Request,
    *,
    token_id: int,
    is_active: bool,
):
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login("/monitoring")

    try:
        api_token_service.set_token_active_state(
            user_id=current_user.id,
            token_id=token_id,
            is_active=is_active,
        )
    except DomainSecurityError as exc:
        return _render_dashboard(
            request,
            user_id=current_user.id,
            api_token_error=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(url="/monitoring", status_code=status.HTTP_303_SEE_OTHER)
