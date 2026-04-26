from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.api.routes.error_utils import get_http_status_code
from app.core.config import settings
from app.core.exceptions import DomainSecurityError
from app.presenters import ReportPresenter, configure_template_filters
from app.presenters.monitoring_plus_offer_presenter import MonitoringPlusOfferPresenter
from app.services.analysis_history_service import AnalysisHistoryService
from app.services.analysis_service import DomainAnalysisService
from app.services.auth_service import AuthenticationService

router = APIRouter(include_in_schema=False)
templates = configure_template_filters(Jinja2Templates(directory=str(settings.templates_dir)))
service = DomainAnalysisService()
history_service = AnalysisHistoryService()
report_presenter = ReportPresenter()
auth_service = AuthenticationService()
offer_presenter = MonitoringPlusOfferPresenter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    context = {
        "request": request,
        "page_title": settings.app_name,
        "page_name": "home",
        "error": None,
        "submitted_target": "",
    }
    return templates.TemplateResponse(
        request=request,
        name="pages/home.html",
        context=context,
    )


@router.get("/wordpress", response_class=HTMLResponse)
def wordpress_page(request: Request) -> HTMLResponse:
    context = {
        "request": request,
        "page_title": "WordPress Security",
        "page_name": "wordpress",
    }
    return templates.TemplateResponse(
        request=request,
        name="pages/wordpress.html",
        context=context,
    )


@router.get("/wordpress/relatorio-tecnico", response_class=HTMLResponse)
def wordpress_technical_report_page(request: Request) -> HTMLResponse:
    context = {
        "request": request,
        "page_title": "Relatorio Tecnico WordPress",
        "page_name": "wordpress-technical-report",
    }
    return templates.TemplateResponse(
        request=request,
        name="pages/wordpress_technical_report.html",
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
            "page_name": "home",
            "error": str(exc),
            "submitted_target": target,
        }
        return templates.TemplateResponse(
            request=request,
            name="pages/home.html",
            context=context,
            status_code=get_http_status_code(exc),
        )

    report = report_presenter.present(
        result,
        submitted_target=target,
        analyzed_at=datetime.now(tz=UTC),
    )
    current_user = auth_service.get_user_session(request)
    monitoring_plus_offer = offer_presenter.prepare_offer_data(
        analysis_result=result,
        user_id=current_user.id if current_user else None,
    )

    context = {
        "request": request,
        "page_title": "Resultado da Analise",
        "page_name": "result",
        "error": None,
        "report": report,
        "submitted_target": target,
        "monitoring_plus_offer": monitoring_plus_offer,
    }
    return templates.TemplateResponse(
        request=request,
        name="pages/result.html",
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
            "page_name": "home",
            "error": str(exc),
            "submitted_target": domain,
        }
        return templates.TemplateResponse(
            request=request,
            name="pages/home.html",
            context=context,
            status_code=get_http_status_code(exc),
        )
    context = {
        "request": request,
        "page_title": f"Historico de {history.domain}",
        "page_name": "history",
        "history": history,
    }
    return templates.TemplateResponse(
        request=request,
        name="pages/history.html",
        context=context,
        status_code=status.HTTP_200_OK,
    )
