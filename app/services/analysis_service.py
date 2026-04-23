from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from app.core.analysis_cache import AnalysisCache
from app.core.exceptions import DNSDomainNotFoundError, DNSLookupError, DNSNoResponseError, DNSTimeoutError
from app.schemas.analysis import (
    AnalysisChecks,
    AnalysisPerformance,
    EmailPolicyResult,
    AnalysisResponse,
    DKIMCheckResult,
    DMARCCheckResult,
    DomainRegistrationResult,
    EmailTLSResult,
    IPIntelligenceResult,
    MXCheckResult,
    MXRecord,
    SPFCheckResult,
    WebsiteTLSResult,
)
from app.schemas.history import AnalysisDiffSummary
from app.services.analysis_history_service import AnalysisHistoryService
from app.services.dns_service import DNSLookupService, MXRecordValue
from app.services.domain_registration_service import DomainRegistrationService
from app.services.email_auth_service import EmailAuthenticationService
from app.services.email_policy_service import EmailPolicyService
from app.services.email_tls_service import EmailTLSService
from app.services.ip_intelligence_service import IPIntelligenceService
from app.services.recommendation_service import RecommendationService
from app.services.scoring_service import ScoringService
from app.services.website_tls_service import WebsiteTLSService
from app.utils.input_parser import normalize_target


@dataclass(frozen=True)
class TimedStageResult:
    value: Any
    duration_ms: int


@dataclass(frozen=True)
class MXStagePayload:
    check: MXCheckResult
    records: list[MXRecordValue]


class DomainAnalysisService:
    """Coordinates the full domain analysis with short-lived caching."""

    MAX_PARALLEL_WORKERS = 4

    def __init__(
        self,
        *,
        dns_service: DNSLookupService | None = None,
        email_auth_service: EmailAuthenticationService | None = None,
        website_tls_service: WebsiteTLSService | None = None,
        email_tls_service: EmailTLSService | None = None,
        email_policy_service: EmailPolicyService | None = None,
        domain_registration_service: DomainRegistrationService | None = None,
        ip_intelligence_service: IPIntelligenceService | None = None,
        scoring_service: ScoringService | None = None,
        recommendation_service: RecommendationService | None = None,
        history_service: AnalysisHistoryService | None = None,
        analysis_cache: AnalysisCache | None = None,
    ) -> None:
        self.dns_service = dns_service or DNSLookupService()
        self.email_auth_service = email_auth_service or EmailAuthenticationService()
        self.website_tls_service = website_tls_service or WebsiteTLSService()
        self.email_tls_service = email_tls_service or EmailTLSService()
        self.email_policy_service = email_policy_service or EmailPolicyService(dns_service=self.dns_service)
        self.domain_registration_service = domain_registration_service or DomainRegistrationService()
        self.ip_intelligence_service = ip_intelligence_service or IPIntelligenceService(
            dns_service=self.dns_service
        )
        self.scoring_service = scoring_service or ScoringService()
        self.recommendation_service = recommendation_service or RecommendationService()
        self.history_service = history_service or AnalysisHistoryService()
        self.analysis_cache = analysis_cache or AnalysisCache()

    def analyze_target(self, target: str, *, force_refresh: bool = False) -> AnalysisResponse:
        total_started_at = perf_counter()

        normalized_started_at = perf_counter()
        normalized = normalize_target(target)
        normalize_ms = self._elapsed_ms(normalized_started_at)

        cached_payload = None if force_refresh else self.analysis_cache.get(normalized.analysis_domain)
        if cached_payload is not None:
            return self._build_cached_response(
                cached_payload,
                normalize_ms=normalize_ms,
                normalized=normalized,
                total_started_at=total_started_at,
            )

        with ThreadPoolExecutor(max_workers=self.MAX_PARALLEL_WORKERS, thread_name_prefix="dsc-analysis") as executor:
            mx_future = executor.submit(self._run_timed_stage, self._load_mx_stage, normalized.analysis_domain)
            spf_future = executor.submit(self._run_timed_stage, self._load_spf_stage, normalized.analysis_domain)
            dmarc_future = executor.submit(self._run_timed_stage, self._load_dmarc_stage, normalized.analysis_domain)

            mx_stage = mx_future.result()
            spf_stage = spf_future.result()
            dmarc_stage = dmarc_future.result()

            dkim_future = executor.submit(self._run_timed_stage, self._load_dkim_stage, normalized.analysis_domain)
            email_policy_future = executor.submit(
                self._run_timed_stage,
                self._load_email_policies_stage,
                normalized.analysis_domain,
                dmarc_stage.value,
            )
            website_tls_future = executor.submit(
                self._run_timed_stage,
                self._load_website_tls_stage,
                normalized.analysis_domain,
            )
            rdap_future = executor.submit(
                self._run_timed_stage,
                self._load_domain_registration_stage,
                normalized.analysis_domain,
            )
            ip_intelligence_future = executor.submit(
                self._run_timed_stage,
                self._load_ip_intelligence_stage,
                normalized.analysis_domain,
            )

            dkim_stage = dkim_future.result()
            email_policy_stage = email_policy_future.result()
            website_tls_stage = website_tls_future.result()
            rdap_stage = rdap_future.result()
            ip_intelligence_stage = ip_intelligence_future.result()

        email_tls_stage = self._run_timed_stage(
            self._load_email_tls_stage,
            normalized.analysis_domain,
            mx_stage.value.records,
            mx_stage.value.check.lookup_error,
        )

        checks = AnalysisChecks(
            mx=mx_stage.value.check,
            spf=spf_stage.value,
            dkim=dkim_stage.value,
            dmarc=dmarc_stage.value,
        )
        email_policies = email_policy_stage.value
        score_outcome = self.scoring_service.calculate(checks)
        website_tls = website_tls_stage.value
        email_tls = email_tls_stage.value
        domain_registration = rdap_stage.value
        ip_intelligence = ip_intelligence_stage.value

        findings = self.recommendation_service.build_findings(checks)
        recommendations = self.recommendation_service.build_recommendations(
            checks,
            website_tls=website_tls,
            domain_registration=domain_registration,
        )
        notes = self._build_notes(checks, website_tls, email_tls, domain_registration, email_policies)
        notes.extend(ip_intelligence.notes)
        notes = self._dedupe_notes(notes)
        summary = self._build_summary(
            score=score_outcome.score,
            severity=score_outcome.severity,
            website_tls=website_tls,
            email_tls=email_tls,
        )

        performance = AnalysisPerformance(
            total_ms=self._elapsed_ms(total_started_at),
            normalize_ms=normalize_ms,
            mx_ms=mx_stage.duration_ms,
            spf_ms=spf_stage.duration_ms,
            dmarc_ms=dmarc_stage.duration_ms,
            dkim_ms=dkim_stage.duration_ms,
            website_tls_ms=website_tls_stage.duration_ms,
            email_tls_ms=email_tls_stage.duration_ms,
            domain_registration_ms=rdap_stage.duration_ms,
            rdap_ms=rdap_stage.duration_ms,
            ip_intelligence_ms=ip_intelligence_stage.duration_ms,
            cache_hit=False,
        )

        response = AnalysisResponse(
            normalized=normalized,
            score=score_outcome.score,
            severity=score_outcome.severity,
            summary=summary,
            checks=checks,
            website_tls=website_tls,
            email_tls=email_tls,
            domain_registration=domain_registration,
            email_policies=email_policies,
            ip_intelligence=ip_intelligence,
            score_breakdown=score_outcome.breakdown,
            performance=performance,
            changes=self._initial_changes(score_outcome.score, score_outcome.severity),
            findings=findings,
            recommendations=recommendations,
            notes=notes,
        )

        final_result = self.history_service.record_analysis(response, input_target=target)
        if not force_refresh:
            self.analysis_cache.set(normalized.analysis_domain, final_result.model_dump(mode="json"))
        return final_result

    def _run_timed_stage(self, func, *args) -> TimedStageResult:
        started_at = perf_counter()
        value = func(*args)
        return TimedStageResult(value=value, duration_ms=self._elapsed_ms(started_at))

    def _build_cached_response(
        self,
        cached_payload: dict,
        *,
        normalize_ms: int,
        normalized,
        total_started_at: float,
    ) -> AnalysisResponse:
        cached_result = AnalysisResponse.model_validate(cached_payload)
        performance = AnalysisPerformance(
            total_ms=self._elapsed_ms(total_started_at),
            normalize_ms=normalize_ms,
            mx_ms=0,
            spf_ms=0,
            dmarc_ms=0,
            dkim_ms=0,
            website_tls_ms=0,
            email_tls_ms=0,
            domain_registration_ms=0,
            rdap_ms=0,
            ip_intelligence_ms=0,
            cache_hit=True,
        )
        return cached_result.model_copy(
            update={
                "normalized": normalized,
                "performance": performance,
            }
        )

    def _load_mx_stage(self, domain: str) -> MXStagePayload:
        try:
            records = self.dns_service.get_mx_records(domain)
        except DNSDomainNotFoundError:
            raise
        except (DNSTimeoutError, DNSNoResponseError) as exc:
            return MXStagePayload(
                check=self._build_mx_lookup_error_result(domain, exc),
                records=[],
            )
        return MXStagePayload(
            check=self._build_mx_result(domain, records),
            records=records,
        )

    def _load_spf_stage(self, domain: str) -> SPFCheckResult:
        try:
            txt_records = self.dns_service.get_txt_records(domain)
        except DNSDomainNotFoundError:
            raise
        except (DNSTimeoutError, DNSNoResponseError) as exc:
            return self._build_spf_lookup_error_result(domain, exc)
        return self.email_auth_service.analyze_spf(domain, txt_records, dns_service=self.dns_service)

    def _load_dmarc_stage(self, domain: str) -> DMARCCheckResult:
        checked_name = f"_dmarc.{domain}"
        try:
            txt_records = self.dns_service.get_txt_records(checked_name, missing_on_nxdomain=True)
        except (DNSTimeoutError, DNSNoResponseError) as exc:
            return self._build_dmarc_lookup_error_result(checked_name, exc)
        return self.email_auth_service.analyze_dmarc(checked_name, txt_records)

    def _load_dkim_stage(self, domain: str) -> DKIMCheckResult:
        try:
            return self.email_auth_service.analyze_dkim(domain, self.dns_service)
        except DNSLookupError as exc:
            return DKIMCheckResult(
                checked_name=domain,
                status="desconhecido",
                message="A heuristica de DKIM nao foi concluida por indisponibilidade temporaria de DNS.",
                lookup_error=str(exc),
                confidence_note=(
                    "Sem headers reais, o diagnostico de DKIM ja e heuristico; "
                    "neste caso, a consulta DNS tambem ficou inconclusiva."
                ),
            )

    def _load_website_tls_stage(self, domain: str) -> WebsiteTLSResult:
        try:
            return self.website_tls_service.analyze(domain)
        except Exception as exc:
            return WebsiteTLSResult(
                ssl_active=False,
                message="Nao foi possivel concluir a verificacao de HTTPS do website.",
                error=str(exc),
            )

    def _load_domain_registration_stage(self, domain: str) -> DomainRegistrationResult:
        try:
            return self.domain_registration_service.analyze(domain)
        except Exception as exc:
            return DomainRegistrationResult(
                available=False,
                whois_available=False,
                rdap_available=False,
                message="Nao foi possivel concluir a consulta WHOIS para o dominio.",
                error=str(exc),
                source="WHOIS",
            )

    def _load_ip_intelligence_stage(self, domain: str) -> IPIntelligenceResult:
        try:
            return self.ip_intelligence_service.analyze(domain)
        except Exception as exc:
            return IPIntelligenceResult(
                message="Nao foi possivel concluir a inteligencia de IP para o website.",
                notes=[str(exc), "A analise principal seguiu sem o enriquecimento adicional de IP."],
                source="DNS",
            )

    def _load_email_tls_stage(
        self,
        domain: str,
        mx_records: list[MXRecordValue],
        mx_lookup_error: str | None,
    ) -> EmailTLSResult:
        if mx_lookup_error:
            return EmailTLSResult(
                mx_results=[],
                has_email_tls_data=False,
                total_mx_count=0,
                tested_mx_count=0,
                probe_limited=False,
                message=f"Nao foi possivel obter informacoes de TLS/SSL dos registros MX do dominio {domain}.",
                note=self.email_tls_service.CERTIFICATE_NOTE,
            )
        try:
            return self.email_tls_service.analyze(mx_records)
        except Exception:
            return EmailTLSResult(
                mx_results=[],
                has_email_tls_data=False,
                total_mx_count=len(mx_records),
                tested_mx_count=0,
                probe_limited=False,
                message=f"Nao foi possivel obter informacoes de TLS/SSL dos registros MX do dominio {domain}.",
                note=self.email_tls_service.CERTIFICATE_NOTE,
                probe_note=None,
            )

    def _load_email_policies_stage(self, domain: str, dmarc_result: DMARCCheckResult) -> EmailPolicyResult:
        try:
            return self.email_policy_service.analyze(domain, dmarc_result=dmarc_result)
        except Exception as exc:
            return EmailPolicyResult()

    @staticmethod
    def _build_mx_result(domain: str, records: list[MXRecordValue]) -> MXCheckResult:
        serialized_records = [
            MXRecord(preference=record.preference, exchange=record.exchange)
            for record in records
        ]
        if len(records) == 1 and records[0].exchange == "." and records[0].preference == 0:
            return MXCheckResult(
                checked_name=domain,
                status="presente",
                message="O dominio publica Null MX e declara que nao recebe e-mails.",
                records=serialized_records,
                accepts_mail=False,
                is_null_mx=True,
            )
        if not records:
            return MXCheckResult(
                checked_name=domain,
                status="ausente",
                message="Nenhum registro MX foi encontrado no dominio.",
                records=[],
                accepts_mail=False,
                is_null_mx=False,
            )
        return MXCheckResult(
            checked_name=domain,
            status="presente",
            message=f"O dominio publica {len(records)} registro(s) MX.",
            records=serialized_records,
            accepts_mail=True,
            is_null_mx=False,
        )

    @staticmethod
    def _build_mx_lookup_error_result(domain: str, exc: Exception) -> MXCheckResult:
        return MXCheckResult(
            checked_name=domain,
            status="ausente",
            message="Nao foi possivel confirmar os registros MX por indisponibilidade temporaria do DNS.",
            lookup_error=str(exc),
            accepts_mail=None,
            is_null_mx=False,
        )

    @staticmethod
    def _build_spf_lookup_error_result(domain: str, exc: Exception) -> SPFCheckResult:
        return SPFCheckResult(
            checked_name=domain,
            status="ausente",
            message="Nao foi possivel concluir a consulta SPF por indisponibilidade temporaria do DNS.",
            lookup_error=str(exc),
            posture="desconhecido",
        )

    @staticmethod
    def _build_dmarc_lookup_error_result(checked_name: str, exc: Exception) -> DMARCCheckResult:
        return DMARCCheckResult(
            checked_name=checked_name,
            status="ausente",
            message="Nao foi possivel concluir a consulta DMARC por indisponibilidade temporaria do DNS.",
            lookup_error=str(exc),
            policy_strength="desconhecido",
        )

    @staticmethod
    def _build_summary(
        *,
        score: int,
        severity: str,
        website_tls: WebsiteTLSResult,
        email_tls: EmailTLSResult,
    ) -> str:
        website_label = "HTTPS ativo" if website_tls.ssl_active else "HTTPS nao confirmado"
        email_label = "STARTTLS observado" if email_tls.has_email_tls_data else "STARTTLS inconclusivo"
        return (
            f"Postura geral {severity} ({score}/100). "
            f"{website_label}; {email_label} na camada de e-mail."
        )

    def _build_notes(
        self,
        checks: AnalysisChecks,
        website_tls: WebsiteTLSResult,
        email_tls: EmailTLSResult,
        domain_registration: DomainRegistrationResult,
        email_policies: EmailPolicyResult,
    ) -> list[str]:
        notes = [
            "A avaliacao de DKIM continua heuristica sem headers reais de e-mail.",
            "Os dados de registro do dominio podem ser parciais, conforme o TLD, o registrador e a origem disponivel.",
        ]

        if website_tls.provider_guess:
            notes.append(
                "provider_guess no TLS do website e apenas uma inferencia baseada no certificado apresentado."
            )
        if email_tls.has_email_tls_data:
            notes.append(email_tls.note)
        if email_tls.probe_note:
            notes.append(email_tls.probe_note)
        if checks.mx.lookup_error:
            notes.append("A consulta de MX falhou temporariamente e a analise seguiu com resultado parcial.")
        if checks.spf.lookup_error:
            notes.append("A consulta SPF falhou temporariamente e a analise seguiu com resultado parcial.")
        if checks.dmarc.lookup_error:
            notes.append("A consulta DMARC falhou temporariamente e a analise seguiu com resultado parcial.")
        if checks.dkim.lookup_error:
            notes.append("A heuristica DKIM ficou inconclusiva por indisponibilidade temporaria de DNS.")
        if website_tls.error and not website_tls.ssl_active:
            notes.append("A verificacao de HTTPS do website retornou resultado parcial ou inconclusivo.")
        if domain_registration.error:
            notes.append("A consulta de registro do dominio pode estar parcial por indisponibilidade de WHOIS ou fallback secundario.")
        if email_policies.mta_sts.warnings:
            notes.append("MTA-STS foi localizado com inconsistencias ou cobertura parcial.")
        if email_policies.tls_rpt.warnings:
            notes.append("TLS-RPT foi localizado, mas requer revisao dos destinos ou do formato.")
        if email_policies.bimi.dmarc_dependency:
            notes.append(email_policies.bimi.dmarc_dependency)
        notes.extend(email_policies.dnssec.notes)

        return self._dedupe_notes(notes)

    @staticmethod
    def _initial_changes(score: int, severity: str) -> AnalysisDiffSummary:
        return AnalysisDiffSummary(
            has_previous_snapshot=False,
            message="Esta e a primeira analise salva para este dominio.",
            current_score=score,
            current_severity=severity,
        )

    @staticmethod
    def _dedupe_notes(notes: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in notes:
            if not item or item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    @staticmethod
    def _elapsed_ms(started_at: float) -> int:
        return max(0, round((perf_counter() - started_at) * 1000))
