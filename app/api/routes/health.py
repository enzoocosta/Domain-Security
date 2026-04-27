import importlib.metadata

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health", summary="Application health check")
def health_check(db: Session = Depends(get_db)):
    db_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    try:
        version = importlib.metadata.version("domain-security-checker")
    except importlib.metadata.PackageNotFoundError:
        version = settings.app_version

    if db_status == "error":
        return JSONResponse(
            content={"status": "degraded", "db": "error", "version": version},
            status_code=503,
        )

    return {"status": "ok", "version": version, "db": db_status}
