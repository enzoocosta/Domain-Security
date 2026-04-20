from fastapi import APIRouter, HTTPException, Response

from app.api.routes.error_utils import get_http_status_code
from app.core.exceptions import DomainSecurityError
from app.services.report_export_service import ReportExportService

router = APIRouter(include_in_schema=False)
service = ReportExportService()


@router.get("/reports/{domain}.pdf")
def export_report_pdf(domain: str) -> Response:
    try:
        filename, content = service.export_latest_pdf(domain)
    except DomainSecurityError as exc:
        raise HTTPException(
            status_code=get_http_status_code(exc),
            detail=str(exc),
        ) from exc

    headers = {"Content-Disposition": f'inline; filename="{filename}"'}
    return Response(content=content, media_type="application/pdf", headers=headers)
