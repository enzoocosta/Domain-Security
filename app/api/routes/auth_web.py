from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.exceptions import DomainSecurityError
from app.presenters import configure_template_filters
from app.services.auth_service import AuthenticationService

router = APIRouter(include_in_schema=False)
templates = configure_template_filters(Jinja2Templates(directory=str(settings.templates_dir)))
auth_service = AuthenticationService()


@router.get("/auth/register", response_class=HTMLResponse)
def register_page(request: Request) -> HTMLResponse:
    if auth_service.get_user_session(request) is not None:
        return RedirectResponse(url="/monitoring", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request,
        name="pages/auth_register.html",
        context={
            "request": request,
            "page_title": "Criar conta",
            "page_name": "auth",
            "error": None,
            "next_path": request.query_params.get("next", "/monitoring"),
        },
    )


@router.post("/auth/register", response_class=HTMLResponse)
def register_user(
    request: Request,
    email: Annotated[str, Form(max_length=320)],
    password: Annotated[str, Form(max_length=128)],
    next_path: Annotated[str, Form(max_length=512)] = "/monitoring",
) -> HTMLResponse:
    try:
        user = auth_service.register_user(email, password)
        response = RedirectResponse(url=next_path or "/monitoring", status_code=status.HTTP_303_SEE_OTHER)
        auth_service.apply_login(response, user)
        return response
    except DomainSecurityError as exc:
        return templates.TemplateResponse(
            request=request,
            name="pages/auth_register.html",
            context={
                "request": request,
                "page_title": "Criar conta",
                "page_name": "auth",
                "error": str(exc),
                "next_path": next_path or "/monitoring",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@router.get("/auth/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    if auth_service.get_user_session(request) is not None:
        return RedirectResponse(url="/monitoring", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request,
        name="pages/auth_login.html",
        context={
            "request": request,
            "page_title": "Entrar",
            "page_name": "auth",
            "error": None,
            "next_path": request.query_params.get("next", "/monitoring"),
        },
    )


@router.post("/auth/login", response_class=HTMLResponse)
def login_user(
    request: Request,
    email: Annotated[str, Form(max_length=320)],
    password: Annotated[str, Form(max_length=128)],
    next_path: Annotated[str, Form(max_length=512)] = "/monitoring",
) -> HTMLResponse:
    try:
        user = auth_service.authenticate(email, password)
        response = RedirectResponse(url=next_path or "/monitoring", status_code=status.HTTP_303_SEE_OTHER)
        auth_service.apply_login(response, user)
        return response
    except DomainSecurityError as exc:
        return templates.TemplateResponse(
            request=request,
            name="pages/auth_login.html",
            context={
                "request": request,
                "page_title": "Entrar",
                "page_name": "auth",
                "error": str(exc),
                "next_path": next_path or "/monitoring",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


@router.post("/auth/logout")
def logout_user(request: Request) -> RedirectResponse:
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    auth_service.clear_login(response)
    return response
