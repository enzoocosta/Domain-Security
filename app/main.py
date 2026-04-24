from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import api_router, external_api_router, web_router
from app.core.auth_session import AuthSessionMiddleware
from app.core.config import settings
from app.db import init_db
from app.services.monitoring_plus_scheduler_service import (
    MonitoringPlusSchedulerService,
)
from app.services.monitoring_scheduler_service import MonitoringSchedulerService


def create_app() -> FastAPI:
    init_db()
    scheduler = MonitoringSchedulerService()
    monitoring_plus_scheduler = MonitoringPlusSchedulerService()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.monitoring_scheduler_enabled:
            scheduler.start()
        if settings.monitoring_plus_scheduler_enabled:
            monitoring_plus_scheduler.start()
        try:
            yield
        finally:
            monitoring_plus_scheduler.stop()
            scheduler.stop()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    app.state.monitoring_scheduler = scheduler
    app.state.monitoring_plus_scheduler = monitoring_plus_scheduler
    app.add_middleware(
        AuthSessionMiddleware,
        secret=settings.session_secret,
    )
    app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")
    app.include_router(web_router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)
    app.include_router(external_api_router)
    return app


app = create_app()
