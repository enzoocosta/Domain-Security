from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
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
from app.services.monitoring_plus_scheduler_service import (
    MonitoringPlusSchedulerService,
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
        docs_url="/docs",
        redoc_url="/redoc",
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
    return app


app = create_app()
