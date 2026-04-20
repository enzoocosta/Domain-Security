from __future__ import annotations

from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Protocol

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings
from app.core.exceptions import FeatureUnavailableError
from app.presenters.pdf_report_presenter import PDFReportPresenter
from app.schemas.analysis import AnalysisResponse
from app.services.analysis_history_service import AnalysisHistoryService
from app.services.analysis_service import DomainAnalysisService


class PDFRenderer(Protocol):
    def render(self, *, html: str, base_url: str, css_paths: list[Path]) -> bytes: ...


class WeasyPrintRenderer:
    """Lazily imports WeasyPrint so the app can boot without the optional dependency."""

    def render(self, *, html: str, base_url: str, css_paths: list[Path]) -> bytes:
        try:
            weasyprint = import_module("weasyprint")
        except Exception as exc:  # pragma: no cover - depends on runtime environment
            raise FeatureUnavailableError(
                "A exportacao PDF requer WeasyPrint e suas dependencias nativas no ambiente atual."
            ) from exc

        try:
            html_document = weasyprint.HTML(string=html, base_url=base_url)
            stylesheets = [weasyprint.CSS(filename=str(path)) for path in css_paths]
            return html_document.write_pdf(stylesheets=stylesheets)
        except Exception as exc:  # pragma: no cover - runtime/native dependency path
            raise FeatureUnavailableError(
                "O mecanismo PDF nao conseguiu renderizar o relatorio com WeasyPrint neste ambiente."
            ) from exc


class ReportExportService:
    """Builds a PDF report from the latest saved analysis snapshot or a fresh analysis."""

    def __init__(
        self,
        *,
        history_service: AnalysisHistoryService | None = None,
        analysis_service: DomainAnalysisService | None = None,
        presenter: PDFReportPresenter | None = None,
        renderer: PDFRenderer | None = None,
        template_environment: Environment | None = None,
    ) -> None:
        self.history_service = history_service or AnalysisHistoryService()
        self.analysis_service = analysis_service or DomainAnalysisService()
        self.presenter = presenter or PDFReportPresenter()
        self.renderer = renderer or WeasyPrintRenderer()
        self.template_environment = template_environment or self._build_template_environment()

    def export_latest_pdf(self, domain: str) -> tuple[str, bytes]:
        result = self.history_service.get_latest_result_for_domain(domain)
        if result is None:
            result = self.analysis_service.analyze_target(domain)

        exported_at = datetime.now(tz=UTC)
        report_payload = self.presenter.present(result, exported_at=exported_at)
        html = self._render_html(report_payload)
        pdf_bytes = self.renderer.render(
            html=html,
            base_url=settings.base_dir.as_uri(),
            css_paths=[settings.static_dir / "css" / "pdf.css"],
        )
        filename = f"{result.normalized.analysis_domain.replace('.', '_')}_report.pdf"
        return filename, pdf_bytes

    def _render_html(self, report_payload: dict) -> str:
        template = self.template_environment.get_template("pdf/report.html")
        return template.render(report=report_payload)

    @staticmethod
    def _build_template_environment() -> Environment:
        return Environment(
            loader=FileSystemLoader(str(settings.templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
