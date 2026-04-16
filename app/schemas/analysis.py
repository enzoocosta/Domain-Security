from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

CategoryName = Literal[
    "dns",
    "mx",
    "spf",
    "dkim",
    "dmarc",
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
DKIMStatus = Literal["confirmado_presente", "provavelmente_presente", "desconhecido", "provavelmente_ausente", "invalido"]
SPFAllMechanism = Literal["+all", "-all", "~all", "?all"]
TransportConfidence = Literal["baixa", "media", "alta"]
ExpiryStatus = Literal["ok", "proximo_expiracao", "expirado", "desconhecido"]


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
    records: list[MXRecord] = Field(default_factory=list)
    accepts_mail: bool | None = None
    is_null_mx: bool = False


class SPFCheckResult(BaseModel):
    checked_name: str
    status: CheckStatus
    message: str
    records: list[str] = Field(default_factory=list)
    effective_record: str | None = None
    final_all: SPFAllMechanism | None = None
    posture: SPFPosture = "desconhecido"
    risks: list[str] = Field(default_factory=list)
    lookup_count: int | None = None
    lookup_count_status: Literal["nao_implementado", "estimado", "exato"] = "nao_implementado"
    lookup_candidates: list[str] = Field(default_factory=list)


class DMARCCheckResult(BaseModel):
    checked_name: str
    status: CheckStatus
    message: str
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
    message: str
    note: str


class DomainRegistrationResult(BaseModel):
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
    score_breakdown: ScoreBreakdown
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
