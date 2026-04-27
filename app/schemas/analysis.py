from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.history import AnalysisDiffSummary

CategoryName = Literal[
    "dns",
    "mx",
    "spf",
    "dkim",
    "dmarc",
    "mta_sts",
    "tls_rpt",
    "bimi",
    "dnssec",
    "consistencia",
    "tls_site",
    "tls_email",
    "registro_dominio",
]
CheckStatus = Literal["presente", "ausente", "invalido"]
OverallSeverity = Literal["excelente", "bom", "atencao", "alto", "critico"]
FindingSeverity = Literal["baixo", "medio", "alto", "critico"]
RecommendationPriority = Literal["alta", "media", "baixa"]
SPFPosture = Literal["restritivo", "permissivo", "neutro", "desconhecido"]
DMARCStrength = Literal["fraco", "intermediario", "forte", "desconhecido"]
DKIMStatus = Literal[
    "confirmado_presente",
    "provavelmente_presente",
    "desconhecido",
    "provavelmente_ausente",
    "invalido",
]
SPFAllMechanism = Literal["+all", "-all", "~all", "?all"]
TransportConfidence = Literal["baixa", "media", "alta"]
ExpiryStatus = Literal["ok", "proximo_expiracao", "expirado", "desconhecido"]
IPVersion = Literal["ipv4", "ipv6"]
PolicyStatus = Literal["presente", "ausente", "invalido", "desconhecido"]
BIMIReadiness = Literal["nao_pronto", "parcial", "provavel", "desconhecido"]
DNSSECStatus = Literal["nao_implementado", "presente", "ausente", "desconhecido"]


class AnalysisRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=320,
        description="Domain or email address submitted for analysis.",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Informe um dominio ou e-mail.")
        return cleaned


class NormalizedTarget(BaseModel):
    original: str
    normalized_input: str
    target_type: Literal["domain", "email"]
    analysis_domain: str


class MXRecord(BaseModel):
    preference: int = Field(..., ge=0)
    exchange: str


class MXCheckResult(BaseModel):
    checked_name: str
    status: CheckStatus
    message: str
    lookup_error: str | None = None
    records: list[MXRecord] = Field(default_factory=list)
    accepts_mail: bool | None = None
    is_null_mx: bool = False


class SPFCheckResult(BaseModel):
    checked_name: str
    status: CheckStatus
    message: str
    lookup_error: str | None = None
    records: list[str] = Field(default_factory=list)
    effective_record: str | None = None
    final_all: SPFAllMechanism | None = None
    posture: SPFPosture = "desconhecido"
    risks: list[str] = Field(default_factory=list)
    lookup_count: int | None = None
    lookup_count_status: Literal["nao_implementado", "estimado", "exato"] = (
        "nao_implementado"
    )
    void_lookup_count: int | None = None
    void_lookup_count_status: Literal["nao_implementado", "estimado", "exato"] = (
        "nao_implementado"
    )
    lookup_limit_exceeded: bool = False
    lookup_candidates: list[str] = Field(default_factory=list)
    lookup_chain: list[str] = Field(default_factory=list)


class DMARCCheckResult(BaseModel):
    checked_name: str
    status: CheckStatus
    message: str
    lookup_error: str | None = None
    records: list[str] = Field(default_factory=list)
    effective_record: str | None = None
    policy: Literal["none", "quarantine", "reject"] | None = None
    rua: list[str] = Field(default_factory=list)
    ruf: list[str] = Field(default_factory=list)
    pct: int | None = Field(default=None, ge=0, le=100)
    adkim: Literal["r", "s"] | None = None
    aspf: Literal["r", "s"] | None = None
    policy_strength: DMARCStrength = "desconhecido"
    risks: list[str] = Field(default_factory=list)


class DKIMCheckResult(BaseModel):
    checked_name: str
    status: DKIMStatus
    message: str
    lookup_error: str | None = None
    checked_selectors: list[str] = Field(default_factory=list)
    selectors_with_records: list[str] = Field(default_factory=list)
    records: list[str] = Field(default_factory=list)
    heuristic: bool = True
    confidence_note: str


class WebsiteTLSResult(BaseModel):
    ssl_active: bool
    certificate_valid: bool | None = None
    issuer: str | None = None
    subject: str | None = None
    san: list[str] = Field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_to_expire: int | None = None
    expiry_status: ExpiryStatus = "desconhecido"
    tls_version: str | None = None
    provider_guess: str | None = None
    confidence: TransportConfidence = "baixa"
    message: str
    error: str | None = None


class EmailTLSMXResult(BaseModel):
    host: str
    port: int
    starttls_supported: bool | None = None
    has_tls_data: bool = False
    certificate_valid: bool | None = None
    issuer: str | None = None
    subject: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_to_expire: int | None = None
    expiry_status: ExpiryStatus = "desconhecido"
    tls_version: str | None = None
    hostname_match: bool | None = None
    error: str | None = None


class EmailTLSResult(BaseModel):
    mx_results: list[EmailTLSMXResult] = Field(default_factory=list)
    has_email_tls_data: bool = False
    total_mx_count: int = Field(default=0, ge=0)
    tested_mx_count: int = Field(default=0, ge=0)
    probe_limited: bool = False
    probe_note: str | None = None
    message: str
    note: str


class DomainRegistrationResult(BaseModel):
    available: bool = False
    whois_available: bool = False
    rdap_available: bool = False
    created_at: datetime | None = None
    expires_at: datetime | None = None
    days_to_expire: int | None = None
    expiry_status: ExpiryStatus = "desconhecido"
    registrar: str | None = None
    status: list[str] = Field(default_factory=list)
    message: str
    source: str | None = None
    error: str | None = None


class MTASTSResult(BaseModel):
    checked_name: str
    status: PolicyStatus
    dns_record: str | None = None
    policy_url: str | None = None
    policy_id: str | None = None
    mode: Literal["none", "testing", "enforce"] | None = None
    max_age: int | None = None
    mx_patterns: list[str] = Field(default_factory=list)
    lookup_error: str | None = None
    fetch_error: str | None = None
    message: str
    warnings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class TLSRPTResult(BaseModel):
    checked_name: str
    status: PolicyStatus
    records: list[str] = Field(default_factory=list)
    effective_record: str | None = None
    rua: list[str] = Field(default_factory=list)
    lookup_error: str | None = None
    message: str
    warnings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class BIMIResult(BaseModel):
    checked_name: str
    selector: str = "default"
    status: PolicyStatus
    effective_record: str | None = None
    location: str | None = None
    authority: str | None = None
    readiness: BIMIReadiness = "desconhecido"
    dmarc_dependency: str | None = None
    lookup_error: str | None = None
    message: str
    warnings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class DNSSECResult(BaseModel):
    checked_name: str
    status: DNSSECStatus
    message: str
    notes: list[str] = Field(default_factory=list)


class EmailPolicyResult(BaseModel):
    mta_sts: MTASTSResult = Field(
        default_factory=lambda: MTASTSResult(
            checked_name="",
            status="desconhecido",
            message="MTA-STS nao foi avaliado neste snapshot.",
        )
    )
    tls_rpt: TLSRPTResult = Field(
        default_factory=lambda: TLSRPTResult(
            checked_name="",
            status="desconhecido",
            message="SMTP TLS Reporting nao foi avaliado neste snapshot.",
        )
    )
    bimi: BIMIResult = Field(
        default_factory=lambda: BIMIResult(
            checked_name="",
            status="desconhecido",
            message="BIMI nao foi avaliado neste snapshot.",
        )
    )
    dnssec: DNSSECResult = Field(
        default_factory=lambda: DNSSECResult(
            checked_name="",
            status="nao_implementado",
            message="A checagem DNSSEC ainda nao esta integrada ao fluxo principal.",
        )
    )


class ResolvedIPAddress(BaseModel):
    ip: str
    version: IPVersion
    source_record_type: Literal["A", "AAAA"]
    is_public: bool
    reverse_dns: str | None = None


class IPIntelligenceResult(BaseModel):
    resolved_ips: list[ResolvedIPAddress] = Field(default_factory=list)
    primary_ip: str | None = None
    ip_version: IPVersion | None = None
    is_public: bool | None = None
    has_public_ip: bool = False
    multiple_public_ips: bool = False
    reverse_dns: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    asn_name: str | None = None
    isp: str | None = None
    organization: str | None = None
    provider_guess: str | None = None
    country: str | None = None
    country_name: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    timezone: str | None = None
    usage_type: str | None = None
    anonymous_ip_flags: list[str] = Field(default_factory=list)
    is_proxy_or_hosting_guess: bool | None = None
    reputation_source: str | None = None
    reputation_summary: str | None = None
    reputation_tags: list[str] = Field(default_factory=list)
    source: str | None = None
    confidence: TransportConfidence | None = None
    confidence_note: str | None = None
    geo_approximate: bool = True
    message: str
    notes: list[str] = Field(default_factory=list)


class AnalysisChecks(BaseModel):
    mx: MXCheckResult
    spf: SPFCheckResult
    dkim: DKIMCheckResult
    dmarc: DMARCCheckResult


class ScoreBreakdown(BaseModel):
    dns_score: int = Field(..., ge=0, le=100)
    mx_score: int = Field(..., ge=0, le=100)
    spf_score: int = Field(..., ge=0, le=100)
    dkim_score: int = Field(..., ge=0, le=100)
    dmarc_score: int = Field(..., ge=0, le=100)
    consistency_score: int = Field(..., ge=0, le=100)


class AnalysisPerformance(BaseModel):
    total_ms: int = Field(default=0, ge=0)
    normalize_ms: int = Field(default=0, ge=0)
    mx_ms: int = Field(default=0, ge=0)
    spf_ms: int = Field(default=0, ge=0)
    dmarc_ms: int = Field(default=0, ge=0)
    dkim_ms: int = Field(default=0, ge=0)
    website_tls_ms: int = Field(default=0, ge=0)
    email_tls_ms: int = Field(default=0, ge=0)
    domain_registration_ms: int = Field(default=0, ge=0)
    rdap_ms: int = Field(default=0, ge=0)
    ip_intelligence_ms: int = Field(default=0, ge=0)
    cache_hit: bool = False


class Finding(BaseModel):
    category: CategoryName
    severity: FindingSeverity
    title: str
    detail: str


class Recommendation(BaseModel):
    category: CategoryName
    priority: RecommendationPriority
    title: str
    action: str
    rationale: str


class AnalysisResponse(BaseModel):
    normalized: NormalizedTarget
    status: Literal["concluido"] = "concluido"
    score: int = Field(..., ge=0, le=100)
    severity: OverallSeverity
    summary: str
    checks: AnalysisChecks
    website_tls: WebsiteTLSResult
    email_tls: EmailTLSResult
    domain_registration: DomainRegistrationResult
    email_policies: EmailPolicyResult = Field(default_factory=EmailPolicyResult)
    ip_intelligence: IPIntelligenceResult = Field(
        default_factory=lambda: IPIntelligenceResult(
            message="Inteligencia de IP nao estava disponivel neste snapshot.",
        )
    )
    score_breakdown: ScoreBreakdown
    performance: AnalysisPerformance
    changes: AnalysisDiffSummary
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
