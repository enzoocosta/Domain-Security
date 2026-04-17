from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.api.routes.error_utils import get_http_status_code
from app.core.config import settings
from app.core.exceptions import DomainSecurityError
from app.services.analysis_history_service import AnalysisHistoryService
from app.services.analysis_service import DomainAnalysisService

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(settings.templates_dir))
service = DomainAnalysisService()
history_service = AnalysisHistoryService()


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    context = {
        "request": request,
        "page_title": settings.app_name,
        "error": None,
        "result": None,
        "submitted_target": "",
    }
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=context,
    )


@router.post("/analyze", response_class=HTMLResponse)
def analyze_from_form(
    request: Request,
    target: Annotated[str, Form(max_length=320)],
) -> HTMLResponse:
    try:
        result = service.analyze_target(target)
    except DomainSecurityError as exc:
        context = {
            "request": request,
            "page_title": settings.app_name,
            "error": str(exc),
            "result": None,
            "submitted_target": target,
        }
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context=context,
            status_code=get_http_status_code(exc),
        )

    context = {
        "request": request,
        "page_title": "Resultado da Analise",
        "error": None,
        "result": result,
        "submitted_target": target,
    }
    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context=context,
        status_code=status.HTTP_200_OK,
    )


@router.get("/history/{domain}", response_class=HTMLResponse)
def history_page(request: Request, domain: str) -> HTMLResponse:
    try:
        history = history_service.list_history(domain)
    except DomainSecurityError as exc:
        context = {
            "request": request,
            "page_title": settings.app_name,
            "error": str(exc),
            "result": None,
            "submitted_target": domain,
        }
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context=context,
            status_code=get_http_status_code(exc),
        )
    context = {
        "request": request,
        "page_title": f"Historico de {history.domain}",
        "history": history,
    }
    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context=context,
        status_code=status.HTTP_200_OK,
    )
