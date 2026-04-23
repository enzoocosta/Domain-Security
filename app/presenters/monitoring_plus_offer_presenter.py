"""Prepara dados da oferta do Monitoring Plus para a pagina de resultado.

A oferta aparece apenas para dominios elegiveis (nao email), com uma chamada
legivel e honesta, sem hype. Baseada em estado local sem dependencias externas.
"""

from __future__ import annotations

from app.schemas.analysis import AnalysisResponse
from app.services.monitoring_plus_service import MonitoringPlusService
from app.utils.input_parser import normalize_target


class MonitoringPlusOfferPresenter:
    def __init__(self, monitoring_plus_service: MonitoringPlusService | None = None):
        self.monitoring_plus_service = (
            monitoring_plus_service or MonitoringPlusService()
        )

    def prepare_offer_data(
        self,
        *,
        analysis_result: AnalysisResponse,
        user_id: int | None = None,
    ) -> dict | None:
        """Retorna os dados da oferta ou None se nao aplicavel."""
        normalized = analysis_result.normalized
        if normalized.target_type != "domain":
            return None
        if user_id is None:
            return None

        try:
            existing = self.monitoring_plus_service._find_monitored_domain(
                user_id=user_id,
                domain=normalized.analysis_domain,
            )
            if existing is not None:
                return None  # Ja tem Monitoring Plus ativo
        except Exception:
            pass

        return {
            "analysis_domain": normalized.analysis_domain,
            "input_label": normalized.original,
            "score": analysis_result.score,
            "severity": analysis_result.severity,
            "monitoring_frequency": "daily",  # padrao
            "show_offer": True,
        }

    @staticmethod
    def monitoring_frequency_options() -> list[dict]:
        return [
            {"value": "daily", "label": "Diario"},
            {"value": "weekly", "label": "Semanal"},
            {"value": "monthly", "label": "Mensal"},
        ]
