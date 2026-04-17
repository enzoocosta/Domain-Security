from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.exceptions import AuthorizationError, DomainSecurityError
from app.presenters import configure_template_filters
from app.services.auth_service import AuthenticationService
from app.services.monitoring_service import MonitoringService

router = APIRouter(include_in_schema=False)
templates = configure_template_filters(Jinja2Templates(directory=str(settings.templates_dir)))
auth_service = AuthenticationService()
monitoring_service = MonitoringService()


@router.get("/monitoring", response_class=HTMLResponse)
def monitoring_dashboard(request: Request) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return _redirect_to_login("/monitoring")

    dashboard = monitoring_service.get_dashboard(user_id=current_user.id)
    return templates.TemplateResponse(
        request=request,
        name="pages/monitoring_dashboard.html",
        context={
            "request": request,
            "page_title": "Monitoramento autenticado",
            "page_name": "monitoring",
            "dashboard": dashboard,
            "error": None,
        },
    )


@router.post("/monitoring/domains", response_class=HTMLResponse)
def create_monitored_domain(
    request: Request,
    domain: Annotated[str, Form(max_length=320)],
    monitoring_frequency: Annotated[str, Form(max_length=16)],
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
            input_label=input_label,
        )
        return RedirectResponse(url="/monitoring", status_code=status.HTTP_303_SEE_OTHER)
    except DomainSecurityError as exc:
        dashboard = monitoring_service.get_dashboard(user_id=current_user.id)
        return templates.TemplateResponse(
            request=request,
            name="pages/monitoring_dashboard.html",
            context={
                "request": request,
                "page_title": "Monitoramento autenticado",
                "page_name": "monitoring",
                "dashboard": dashboard,
                "error": str(exc),
            },
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
        return RedirectResponse(url="/monitoring", status_code=status.HTTP_303_SEE_OTHER)
    except DomainSecurityError as exc:
        dashboard = monitoring_service.get_dashboard(user_id=current_user.id)
        return templates.TemplateResponse(
            request=request,
            name="pages/monitoring_dashboard.html",
            context={
                "request": request,
                "page_title": "Monitoramento autenticado",
                "page_name": "monitoring",
                "dashboard": dashboard,
                "error": str(exc),
            },
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


def _redirect_to_login(path: str) -> RedirectResponse:
    return RedirectResponse(url=f"/auth/login?next={quote(path)}", status_code=status.HTTP_303_SEE_OTHER)
