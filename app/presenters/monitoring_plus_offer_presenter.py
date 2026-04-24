"""Prepara dados da oferta do Monitoring Plus para a pagina de resultado.

A oferta aparece apenas para dominios elegiveis (nao email), com uma chamada
legivel e honesta, sem hype. Baseada em estado local sem dependencias externas.
"""

from __future__ import annotations

from urllib.parse import quote

from app.core.config import settings
from app.schemas.analysis import AnalysisResponse
from app.services.monitoring_plus_service import MonitoringPlusService


class MonitoringPlusOfferPresenter:
    _FREQUENCY_OPTIONS = (
        {"value": "daily", "label": "Diario"},
        {"value": "weekly", "label": "Semanal"},
        {"value": "monthly", "label": "Mensal"},
    )

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
        offer_state = None
        if user_id is not None:
            offer_state = self.monitoring_plus_service.get_offer_state(
                user_id=user_id,
                domain=normalized.analysis_domain,
            )
            if offer_state.is_entitled:
                return None

        default_label = normalized.original
        if default_label == normalized.analysis_domain:
            default_label = ""

        requires_auth = user_id is None
        is_reactivation = (
            offer_state is not None
            and offer_state.monitored_domain_id is not None
        )
        login_next = quote("/monitoring-plus", safe="/")

        return {
            "analysis_domain": normalized.analysis_domain,
            "input_label": default_label,
            "score_label": f"Score atual: {analysis_result.score}",
            "severity_label": f"Severidade atual: {analysis_result.severity}",
            "monitoring_frequency": "daily",
            "frequency_options": self.monitoring_frequency_options(),
            "show_offer": True,
            "requires_auth": requires_auth,
            "title": (
                f"{'Reative' if is_reactivation else 'Ative'} o Monitoring Plus para {normalized.analysis_domain}"
            ),
            "summary": (
                "O diagnostico acima continua separado. O Monitoring Plus usa "
                "telemetria enviada pelo seu edge ou aplicacao para sinalizar "
                "picos, varredura, erros 5xx e User-Agents suspeitos."
            ),
            "highlights": [
                "Cria um painel tecnico por dominio com incidentes e estado da assinatura.",
                "A deteccao depende da telemetria recebida. Sem ingestao, nao ha incidentes para analisar.",
                f"Teste previsto: {settings.monitoring_plus_trial_days} dias.",
            ],
            "submit_label": (
                "Reativar teste tecnico"
                if is_reactivation
                else "Ativar teste tecnico"
            ),
            "auth_login_href": f"/auth/login?next={login_next}",
            "auth_register_href": f"/auth/register?next={login_next}",
            "auth_cta_label": "Entrar para ativar",
            "trial_note": (
                "Sem regra de deteccao no navegador: a analise continua publica e "
                "o monitoramento premium so ganha dados apos a ingestao."
            ),
        }

    @staticmethod
    def monitoring_frequency_options() -> list[dict]:
        return list(MonitoringPlusOfferPresenter._FREQUENCY_OPTIONS)
