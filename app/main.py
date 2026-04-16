from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import api_router, web_router
from app.core.config import settings


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")
    app.include_router(web_router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()

