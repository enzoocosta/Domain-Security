from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AlertEvent, MonitoredDomain, MonitoringRun
from app.schemas.analysis import AnalysisResponse, Finding
from app.core.config import settings


@dataclass(frozen=True)
class AlertCandidate:
    alert_type: str
    severity: str
    title: str
    description: str


@dataclass(frozen=True)
class AlertEvaluation:
    candidates: list[AlertCandidate]
    primary_reason: str | None
    should_notify: bool


class MonitoringAlertService:
    """Evaluates monitoring results and synchronizes alert state."""

    SEVERITY_ORDER = {
        "excelente": 0,
        "bom": 1,
        "atencao": 2,
        "alto": 3,
        "critico": 4,
    }

    EMAIL_AUTH_CRITICAL_CATEGORIES = {"spf", "dkim", "dmarc", "mx", "tls_email"}

    def evaluate_alerts(
        self,
        current_result: AnalysisResponse,
        *,
        previous_result: AnalysisResponse | None = None,
        last_alert_reason: str | None = None,
    ) -> AlertEvaluation:
        candidates: list[AlertCandidate] = []

        dmarc = current_result.checks.dmarc
        spf = current_result.checks.spf
        dkim = current_result.checks.dkim
        registration = current_result.domain_registration
        website_tls = current_result.website_tls

        if dmarc.status == "ausente":
            candidates.append(
                AlertCandidate(
                    alert_type="dmarc_missing",
                    severity="alta",
                    title="DMARC ausente",
                    description="A postura atual indica risco aumentado de spoofing porque o dominio nao publica DMARC.",
                )
            )
        if spf.status == "ausente":
            candidates.append(
                AlertCandidate(
                    alert_type="spf_missing",
                    severity="alta",
                    title="SPF ausente",
                    description="A postura atual aumentou a exposicao a spoofing porque nao ha SPF publicado.",
                )
            )
        if spf.status == "invalido":
            candidates.append(
                AlertCandidate(
                    alert_type="spf_invalid",
                    severity="alta",
                    title="SPF invalido",
                    description="O SPF atual esta invalido, o que reduz a capacidade de limitar remetentes autorizados.",
                )
            )
        if registration.expiry_status in {"proximo_expiracao", "expirado"}:
            candidates.append(
                AlertCandidate(
                    alert_type="domain_expiry_risk",
                    severity="alta",
                    title="Dominio perto da expiracao",
                    description="O ciclo de vida do dominio exige atencao imediata para evitar indisponibilidade e perda de controle.",
                )
            )
        if dkim.status in {"provavelmente_ausente", "invalido"}:
            candidates.append(
                AlertCandidate(
                    alert_type="dkim_weakened",
                    severity="media",
                    title="DKIM enfraquecido",
                    description="A postura de DKIM sugere risco aumentado de spoofing ou configuracao inconsistente.",
                )
            )
        if website_tls.days_to_expire is not None and website_tls.days_to_expire < 7:
            candidates.append(
                AlertCandidate(
                    alert_type="cert_expiring_critical",
                    severity="alta",
                    title="Certificado TLS expirando em menos de 7 dias",
                    description="O certificado do website esta muito perto de expirar e exige renovacao imediata.",
                )
            )
        elif website_tls.days_to_expire is not None and website_tls.days_to_expire < 30:
            candidates.append(
                AlertCandidate(
                    alert_type="cert_expiring_warning",
                    severity="media",
                    title="Certificado TLS expirando em menos de 30 dias",
                    description="O certificado do website esta proximo da expiracao e deve entrar na fila de renovacao.",
                )
            )

        if previous_result is not None:
            if self._dmarc_regressed(previous_result, current_result):
                candidates.append(
                    AlertCandidate(
                        alert_type="dmarc_regressed",
                        severity="alta",
                        title="DMARC regrediu",
                        description="A politica DMARC atual esta menos restritiva do que a execucao anterior, elevando o risco de spoofing.",
                    )
                )
            if (
                previous_result.score - current_result.score
                >= settings.monitoring_score_drop_threshold
            ):
                candidates.append(
                    AlertCandidate(
                        alert_type="score_drop",
                        severity="alta",
                        title="Queda relevante de score",
                        description=(
                            f"O score caiu de {previous_result.score} para {current_result.score}, indicando mudanca critica de postura."
                        ),
                    )
                )
            if self._severity_worsened(
                previous_result.severity, current_result.severity
            ):
                candidates.append(
                    AlertCandidate(
                        alert_type="severity_worsened",
                        severity="alta",
                        title="Severidade piorou",
                        description=(
                            f"A severidade mudou de {previous_result.severity} para {current_result.severity}, sugerindo postura mais fraca."
                        ),
                    )
                )
            if self._has_new_critical_email_auth_finding(
                previous_result.findings, current_result.findings
            ):
                candidates.append(
                    AlertCandidate(
                        alert_type="critical_email_auth_finding",
                        severity="alta",
                        title="Novo finding critico de autenticacao",
                        description="Foi detectado um novo achado critico ligado a autenticacao de e-mail ou transporte do e-mail.",
                    )
                )
            if self._is_recurrent_dkim_unknown(previous_result, current_result):
                candidates.append(
                    AlertCandidate(
                        alert_type="dkim_unknown_recurrent",
                        severity="media",
                        title="DKIM permanece inconclusivo",
                        description="O DKIM continua unknown em execucoes consecutivas, o que mantem a incerteza sobre o risco de spoofing.",
                    )
                )
            if self._ip_changed(previous_result, current_result):
                candidates.append(
                    AlertCandidate(
                        alert_type="ip_changed",
                        severity="alta",
                        title="IP principal do dominio mudou",
                        description="O IP principal observado para o website mudou desde a ultima execucao e merece revisao operacional.",
                    )
                )
            if self._mx_changed(previous_result, current_result):
                candidates.append(
                    AlertCandidate(
                        alert_type="mx_changed",
                        severity="media",
                        title="MX mudou de forma relevante",
                        description="Os registros MX mudaram desde a ultima execucao, o que merece revisao operacional.",
                    )
                )
            if self._website_tls_regressed(previous_result, current_result):
                candidates.append(
                    AlertCandidate(
                        alert_type="website_tls_regression",
                        severity="media",
                        title="TLS do website piorou",
                        description="O website apresentou regressao relevante de HTTPS ou certificado desde a ultima execucao.",
                    )
                )

        deduped = self._dedupe_candidates(candidates)
        primary_reason = self._build_primary_reason(deduped)
        should_notify = (
            bool(primary_reason) and primary_reason != (last_alert_reason or "").strip()
        )
        return AlertEvaluation(
            candidates=deduped,
            primary_reason=primary_reason,
            should_notify=should_notify,
        )

    def synchronize_alerts(
        self,
        db: Session,
        *,
        monitored_domain: MonitoredDomain,
        monitoring_run: MonitoringRun,
        candidates: Iterable[AlertCandidate],
    ) -> list[AlertEvent]:
        active_candidates = {
            candidate.alert_type: candidate for candidate in candidates
        }
        stmt = select(AlertEvent).where(
            AlertEvent.monitored_domain_id == monitored_domain.id
        )
        existing_events = db.scalars(stmt).all()
        current_time = self._utcnow()
        synced_events: list[AlertEvent] = []

        for event in existing_events:
            candidate = active_candidates.get(event.alert_type)
            if candidate is None:
                if event.status != "resolved":
                    event.status = "resolved"
                    event.resolved_at = current_time
                continue

            event.severity = candidate.severity
            event.title = candidate.title
            event.description = candidate.description
            was_resolved = event.status == "resolved"
            event.status = "open"
            event.monitoring_run_id = monitoring_run.id
            event.resolved_at = None
            if was_resolved:
                event.email_delivery_status = "pending"
                event.email_last_attempt_at = None
                event.email_sent_at = None
                event.email_last_error = None
            synced_events.append(event)
            active_candidates.pop(event.alert_type, None)

        for candidate in active_candidates.values():
            event = AlertEvent(
                monitored_domain_id=monitored_domain.id,
                monitoring_run_id=monitoring_run.id,
                alert_type=candidate.alert_type,
                severity=candidate.severity,
                title=candidate.title,
                description=candidate.description,
                status="open",
                email_delivery_status="pending",
                created_at=current_time,
            )
            db.add(event)
            synced_events.append(event)

        db.flush()
        return synced_events

    @staticmethod
    def _dmarc_regressed(
        previous_result: AnalysisResponse, current_result: AnalysisResponse
    ) -> bool:
        previous_policy = previous_result.checks.dmarc.policy or "none"
        current_policy = current_result.checks.dmarc.policy or "none"
        return MonitoringAlertService._dmarc_order(
            current_policy
        ) < MonitoringAlertService._dmarc_order(previous_policy)

    @staticmethod
    def _dmarc_order(policy: str) -> int:
        return {"none": 0, "quarantine": 1, "reject": 2}.get(policy, 0)

    def _severity_worsened(self, previous: str, current: str) -> bool:
        return self.SEVERITY_ORDER.get(current, 0) > self.SEVERITY_ORDER.get(
            previous, 0
        )

    def _has_new_critical_email_auth_finding(
        self,
        previous_findings: list[Finding],
        current_findings: list[Finding],
    ) -> bool:
        previous_signatures = {
            self._finding_signature(item) for item in previous_findings
        }
        for finding in current_findings:
            if finding.severity != "critico":
                continue
            if finding.category not in self.EMAIL_AUTH_CRITICAL_CATEGORIES:
                continue
            if self._finding_signature(finding) not in previous_signatures:
                return True
        return False

    @staticmethod
    def _is_recurrent_dkim_unknown(
        previous_result: AnalysisResponse, current_result: AnalysisResponse
    ) -> bool:
        return (
            previous_result.checks.dkim.status == "desconhecido"
            and current_result.checks.dkim.status == "desconhecido"
        )

    @staticmethod
    def _ip_changed(
        previous_result: AnalysisResponse, current_result: AnalysisResponse
    ) -> bool:
        previous_ip = previous_result.ip_intelligence.primary_ip
        current_ip = current_result.ip_intelligence.primary_ip
        return bool(previous_ip and current_ip and previous_ip != current_ip)

    @staticmethod
    def _mx_changed(
        previous_result: AnalysisResponse, current_result: AnalysisResponse
    ) -> bool:
        previous_records = {
            (record.preference, record.exchange)
            for record in previous_result.checks.mx.records
        }
        current_records = {
            (record.preference, record.exchange)
            for record in current_result.checks.mx.records
        }
        return previous_records != current_records

    @staticmethod
    def _website_tls_regressed(
        previous_result: AnalysisResponse, current_result: AnalysisResponse
    ) -> bool:
        previous_tls = previous_result.website_tls
        current_tls = current_result.website_tls
        if previous_tls.ssl_active and not current_tls.ssl_active:
            return True
        if (
            previous_tls.certificate_valid is True
            and current_tls.certificate_valid is False
        ):
            return True
        if previous_tls.expiry_status == "ok" and current_tls.expiry_status in {
            "proximo_expiracao",
            "expirado",
        }:
            return True
        return False

    @staticmethod
    def _finding_signature(finding: Finding) -> str:
        return f"{finding.category}|{finding.severity}|{finding.title}|{finding.detail}"

    @staticmethod
    def _dedupe_candidates(candidates: list[AlertCandidate]) -> list[AlertCandidate]:
        deduped: dict[str, AlertCandidate] = {}
        for candidate in candidates:
            deduped[candidate.alert_type] = candidate
        return list(deduped.values())

    @staticmethod
    def _build_primary_reason(candidates: list[AlertCandidate]) -> str | None:
        if not candidates:
            return None
        signatures = sorted(candidate.alert_type for candidate in candidates)
        return "|".join(signatures)

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
