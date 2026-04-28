from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import api_router, external_api_router, web_router
from app.api.routes.health import router as health_router
from app.core.auth_session import AuthSessionMiddleware
from app.core.config import settings
from app.core.limiter import limiter
from app.core.scheduler import scheduler as app_scheduler
from app.core.scheduler import start_scheduler, stop_scheduler
from app.db import init_db
from app.presenters import configure_template_filters
from app.services.monitoring_plus_scheduler_service import (
    MonitoringPlusSchedulerService,
)

templates = configure_template_filters(
    Jinja2Templates(directory=str(settings.templates_dir))
)


def create_app() -> FastAPI:
    init_db()
    monitoring_plus_scheduler = MonitoringPlusSchedulerService()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        start_scheduler()
        if settings.monitoring_plus_scheduler_enabled:
            monitoring_plus_scheduler.start()
        try:
            yield
        finally:
            monitoring_plus_scheduler.stop()
            stop_scheduler()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.state.monitoring_scheduler = app_scheduler
    app.state.monitoring_plus_scheduler = monitoring_plus_scheduler
    app.add_middleware(
        AuthSessionMiddleware,
        secret=settings.session_secret,
    )
    app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")
    app.include_router(health_router)
    app.include_router(web_router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)
    app.include_router(external_api_router)

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Exception) -> HTMLResponse:
        if request.url.path.startswith("/api/") or request.url.path.startswith(
            "/internal/"
        ):
            return JSONResponse(
                content={"detail": getattr(exc, "detail", "Not Found")},
                status_code=404,
            )

        return templates.TemplateResponse(
            request=request,
            name="404.html",
            context={
                "request": request,
                "page_title": "Página não encontrada — Domain Security Checker",
                "title": "Página não encontrada — Domain Security Checker",
                "page_name": "not-found",
            },
            status_code=404,
        )

    return app


app = create_app()
