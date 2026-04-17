from fastapi import APIRouter

from app.api.routes.analysis import router as analysis_router
from app.api.routes.auth_web import router as auth_web_router
from app.api.routes.health import router as health_router
from app.api.routes.history import router as history_router
from app.api.routes.monitoring_web import router as monitoring_web_router
from app.api.routes.web import router as public_web_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(history_router)
api_router.include_router(analysis_router)

web_router = APIRouter()
web_router.include_router(public_web_router)
web_router.include_router(auth_web_router)
web_router.include_router(monitoring_web_router)

__all__ = ["api_router", "web_router"]
