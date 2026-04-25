from typing import Literal

from pydantic import BaseModel, Field


class WordPressAnalysisOptions(BaseModel):
    detect_core: bool = True
    detect_plugins: bool = True
    detect_themes: bool = True


class WordPressAnalysisRequest(BaseModel):
    url: str = Field(min_length=3, max_length=320)
    options: WordPressAnalysisOptions = Field(default_factory=WordPressAnalysisOptions)


class WordPressVulnerability(BaseModel):
    id: str
    titulo: str
    severidade: Literal["critical", "high", "medium", "low"]
    cvssScore: float | None = None
    cve: str | None = None
    corrigidoNaVersao: str | None = None
    referencia: str | None = None


class WordPressItemAnalysis(BaseModel):
    slug: str
    nome: str
    tipo: Literal["core", "plugin", "tema"]
    versaoDetectada: str | None = None
    vulnerabilidades: list[WordPressVulnerability] = Field(default_factory=list)
    status: Literal["seguro", "atencao", "critico", "nao_detectado"]
    referencia: str | None = None


class WordPressVersionDetection(BaseModel):
    version: str | None = None
    source: str | None = None
    warning: str | None = None


class WordPressDetectionSignal(BaseModel):
    layer: int
    name: str
    detected: bool
    value: str | None = None


class WordPressDetectionResult(BaseModel):
    isWordPress: bool
    confidence: Literal["confirmed", "likely", "unlikely"]
    signals: list[WordPressDetectionSignal] = Field(default_factory=list)
    wordpressVersion: str | None = None
    versionHidden: bool = False


class WordPressAnalysisSummary(BaseModel):
    totalItemsAnalisados: int
    totalVulnerabilidades: int
    vulnerabilidadesPorSeveridade: dict[str, int]
    scoreGeral: int
    classificacao: Literal["seguro", "atencao", "em_risco"]


class WordPressAnalysisResponse(BaseModel):
    targetUrl: str
    scannedUrl: str
    siteConfirmed: bool
    cacheHit: bool = False
    detection: WordPressDetectionResult
    versionDetection: WordPressVersionDetection
    items: list[WordPressItemAnalysis] = Field(default_factory=list)
    summary: WordPressAnalysisSummary
    warnings: list[str] = Field(default_factory=list)
    progressSteps: list[str] = Field(default_factory=list)
