from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.exceptions import AuthorizationError, DomainSecurityError
from app.presenters import configure_template_filters
from app.services.asset_discovery_service import AssetDiscoveryService
from app.services.auth_service import AuthenticationService

router = APIRouter(include_in_schema=False)
templates = configure_template_filters(
    Jinja2Templates(directory=str(settings.templates_dir))
)
auth_service = AuthenticationService()
discovery_service = AssetDiscoveryService()


@router.get("/discovery", response_class=HTMLResponse)
def discovery_dashboard(request: Request) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return RedirectResponse(
            url="/auth/login?next=/discovery", status_code=status.HTTP_303_SEE_OTHER
        )

    runs = discovery_service.list_runs(user_id=current_user.id)
    return templates.TemplateResponse(
        request=request,
        name="pages/discovery_dashboard.html",
        context={
            "request": request,
            "page_title": "Asset Discovery",
            "page_name": "discovery",
            "runs": runs,
            "error": None,
        },
    )


@router.post("/discovery/runs", response_class=HTMLResponse)
def create_discovery_run(
    request: Request,
    domain: Annotated[str, Form(max_length=320)],
) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return RedirectResponse(
            url="/auth/login?next=/discovery", status_code=status.HTTP_303_SEE_OTHER
        )

    try:
        detail = discovery_service.create_run(user_id=current_user.id, domain=domain)
    except DomainSecurityError as exc:
        runs = discovery_service.list_runs(user_id=current_user.id)
        return templates.TemplateResponse(
            request=request,
            name="pages/discovery_dashboard.html",
            context={
                "request": request,
                "page_title": "Asset Discovery",
                "page_name": "discovery",
                "runs": runs,
                "error": str(exc),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return RedirectResponse(
        url=f"/discovery/runs/{detail.run.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/discovery/runs/{run_id}", response_class=HTMLResponse)
def discovery_run_detail(request: Request, run_id: int) -> HTMLResponse:
    current_user = auth_service.get_user_session(request)
    if current_user is None:
        return RedirectResponse(
            url=f"/auth/login?next=/discovery/runs/{run_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        detail = discovery_service.get_run_detail(
            user_id=current_user.id, run_id=run_id
        )
    except AuthorizationError:
        return RedirectResponse(url="/discovery", status_code=status.HTTP_303_SEE_OTHER)
    except DomainSecurityError as exc:
        runs = discovery_service.list_runs(user_id=current_user.id)
        return templates.TemplateResponse(
            request=request,
            name="pages/discovery_dashboard.html",
            context={
                "request": request,
                "page_title": "Asset Discovery",
                "page_name": "discovery",
                "runs": runs,
                "error": str(exc),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return templates.TemplateResponse(
        request=request,
        name="pages/discovery_run.html",
        context={
            "request": request,
            "page_title": f"Discovery de {detail.run.normalized_domain}",
            "page_name": "discovery",
            "detail": detail,
            "error": None,
        },
    )
