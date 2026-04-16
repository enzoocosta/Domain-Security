from app.schemas.analysis import AnalysisChecks, AnalysisResponse, MXCheckResult, MXRecord
from app.services.domain_registration_service import DomainRegistrationService
from app.services.dns_service import DNSLookupService, MXRecordValue
from app.services.email_tls_service import EmailTLSService
from app.services.email_auth_service import EmailAuthenticationService
from app.services.recommendation_service import RecommendationService
from app.services.scoring_service import ScoringService
from app.services.website_tls_service import WebsiteTLSService
from app.utils.input_parser import normalize_target


BASE_ANALYSIS_NOTES = [
    "DKIM nao pode ser confirmado com confianca apenas a partir do dominio.",
    (
        "Este MVP usa heuristica de selectors comuns e deixa o caminho pronto para "
        "validacao forte via headers reais de e-mail."
    ),
    "A contagem de lookups SPF ainda nao foi implementada; a estrutura ja foi preparada para isso.",
    "Dados RDAP podem ser parciais, dependendo do TLD e da publicacao feita pelo registro.",
]

EMAIL_TLS_NOTE = "O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal."


class DomainAnalysisService:
    """Coordinates the domain analysis workflow."""

    def __init__(
        self,
        dns_service: DNSLookupService | None = None,
        email_auth_service: EmailAuthenticationService | None = None,
        scoring_service: ScoringService | None = None,
        recommendation_service: RecommendationService | None = None,
        website_tls_service: WebsiteTLSService | None = None,
        email_tls_service: EmailTLSService | None = None,
        domain_registration_service: DomainRegistrationService | None = None,
    ) -> None:
        self.dns_service = dns_service or DNSLookupService()
        self.email_auth_service = email_auth_service or EmailAuthenticationService()
        self.scoring_service = scoring_service or ScoringService()
        self.recommendation_service = recommendation_service or RecommendationService()
        self.website_tls_service = website_tls_service or WebsiteTLSService()
        self.email_tls_service = email_tls_service or EmailTLSService()
        self.domain_registration_service = domain_registration_service or DomainRegistrationService()

    def analyze_target(self, target: str) -> AnalysisResponse:
        normalized = normalize_target(target)
        domain = normalized.analysis_domain

        mx_records = self.dns_service.get_mx_records(domain)
        spf_records = self.dns_service.get_txt_records(domain)
        dmarc_name = f"_dmarc.{domain}"
        dmarc_records = self.dns_service.get_txt_records(
            dmarc_name,
            missing_on_nxdomain=True,
        )

        checks = AnalysisChecks(
            mx=self._build_mx_result(domain, mx_records),
            spf=self.email_auth_service.analyze_spf(domain, spf_records),
            dkim=self.email_auth_service.analyze_dkim(domain, self.dns_service),
            dmarc=self.email_auth_service.analyze_dmarc(dmarc_name, dmarc_records),
        )
        website_tls = self.website_tls_service.analyze(domain)
        email_tls = self.email_tls_service.analyze(mx_records)
        domain_registration = self.domain_registration_service.analyze(domain)
        score_outcome = self.scoring_service.calculate(checks)
        findings = self.recommendation_service.build_findings(
            checks,
            score_outcome.breakdown,
            score_outcome.score,
            score_outcome.severity,
            website_tls=website_tls,
            email_tls=email_tls,
            domain_registration=domain_registration,
        )
        recommendations = self.recommendation_service.build_recommendations(
            checks,
            website_tls=website_tls,
            email_tls=email_tls,
            domain_registration=domain_registration,
        )

        return AnalysisResponse(
            normalized=normalized,
            score=score_outcome.score,
            severity=score_outcome.severity,
            summary=self._build_summary(
                domain,
                checks,
                website_tls.ssl_active,
                domain_registration.days_to_expire,
                score_outcome.score,
                score_outcome.severity,
            ),
            checks=checks,
            website_tls=website_tls,
            email_tls=email_tls,
            domain_registration=domain_registration,
            score_breakdown=score_outcome.breakdown,
            findings=findings,
            recommendations=recommendations,
            notes=self._build_notes(email_tls.has_email_tls_data),
        )

    def _build_mx_result(self, domain: str, records: list[MXRecordValue]) -> MXCheckResult:
        serialized_records = [
            MXRecord(preference=record.preference, exchange=record.exchange)
            for record in records
        ]

        if not records:
            return MXCheckResult(
                checked_name=domain,
                status="ausente",
                message="O dominio nao publica registros MX.",
                accepts_mail=None,
                is_null_mx=False,
            )

        if self._is_null_mx(records):
            return MXCheckResult(
                checked_name=domain,
                status="presente",
                message="O dominio publica um Null MX e informa que nao recebe e-mails.",
                records=serialized_records,
                accepts_mail=False,
                is_null_mx=True,
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
    def _build_summary(
        domain: str,
        checks: AnalysisChecks,
        website_tls_active: bool,
        registration_days_to_expire: int | None,
        score: int,
        severity: str,
    ) -> str:
        https_text = "HTTPS ativo" if website_tls_active else "HTTPS nao confirmado"
        if registration_days_to_expire is None:
            registration_text = "registro sem prazo confirmado"
        elif registration_days_to_expire < 0:
            registration_text = "registro expirado"
        else:
            registration_text = f"registro expira em {registration_days_to_expire} dia(s)"
        return (
            f"Analise concluida para {domain}: score {score}/100 ({severity}), "
            f"{https_text}, SPF {checks.spf.posture}, DMARC {checks.dmarc.policy_strength}, "
            f"DKIM {checks.dkim.status} e {registration_text}."
        )

    @staticmethod
    def _build_notes(has_email_tls_data: bool) -> list[str]:
        notes = list(BASE_ANALYSIS_NOTES)
        if has_email_tls_data:
            notes.append(EMAIL_TLS_NOTE)
        return notes

    @staticmethod
    def _is_null_mx(records: list[MXRecordValue]) -> bool:
        return len(records) == 1 and records[0].preference == 0 and records[0].exchange == "."
