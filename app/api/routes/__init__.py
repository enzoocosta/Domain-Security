from fastapi import APIRouter

from app.api.routes.analysis import router as analysis_router
from app.api.routes.asset_discovery_web import router as asset_discovery_web_router
from app.api.routes.auth_web import router as auth_web_router
from app.api.routes.discovery import router as discovery_router
from app.api.routes.external_monitoring import router as external_monitoring_router
from app.api.routes.health import router as health_router
from app.api.routes.history import router as history_router
from app.api.routes.internal_monitoring import router as internal_monitoring_router
from app.api.routes.monitoring_plus_web import router as monitoring_plus_web_router
from app.api.routes.monitoring_web import router as monitoring_web_router
from app.api.routes.report_web import router as report_web_router
from app.api.routes.traffic_ingest import router as traffic_ingest_router
from app.api.routes.wordpress_analysis import router as wordpress_analysis_router
from app.api.routes.web import router as public_web_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(history_router)
api_router.include_router(analysis_router)
api_router.include_router(discovery_router)
api_router.include_router(wordpress_analysis_router)

external_api_router = APIRouter()
external_api_router.include_router(external_monitoring_router)
external_api_router.include_router(traffic_ingest_router)
external_api_router.include_router(internal_monitoring_router)

web_router = APIRouter()
web_router.include_router(public_web_router)
web_router.include_router(auth_web_router)
web_router.include_router(monitoring_web_router)
web_router.include_router(monitoring_plus_web_router)
web_router.include_router(asset_discovery_web_router)
web_router.include_router(report_web_router)

__all__ = ["api_router", "external_api_router", "web_router"]
