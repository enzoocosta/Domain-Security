from fastapi import APIRouter

from app.api.routes.analysis import router as analysis_router
from app.api.routes.health import router as health_router
from app.api.routes.web import router as web_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(analysis_router)

__all__ = ["api_router", "web_router"]

