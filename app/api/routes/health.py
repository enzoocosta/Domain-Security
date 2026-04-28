from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health", include_in_schema=False)
def health_check(db: Session = Depends(get_db)):
    db_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    if db_status == "error":
        import json

        return Response(
            content=json.dumps({"status": "degraded", "db": "error"}),
            status_code=503,
            media_type="application/json",
        )

    return {"status": "ok", "db": "ok"}
