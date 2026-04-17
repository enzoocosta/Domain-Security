from dataclasses import dataclass
from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parents[2]
APP_DIR = BASE_DIR / "app"


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    api_v1_prefix: str
    base_dir: Path
    templates_dir: Path
    static_dir: Path
    database_url: str
    dns_timeout_seconds: float
    website_tls_timeout_seconds: float
    email_tls_timeout_seconds: float
    rdap_timeout_seconds: float
    mx_probe_limit: int
    analysis_cache_ttl_seconds: int
    rdap_base_url: str
    session_secret: str
    session_max_age_seconds: int
    monitoring_scheduler_enabled: bool
    monitoring_poll_seconds: int
    monitoring_score_drop_threshold: int


settings = Settings(
    app_name=os.getenv("DSC_APP_NAME", "Domain Security Checker"),
    app_version="0.1.0",
    api_v1_prefix="/api/v1",
    base_dir=BASE_DIR,
    templates_dir=APP_DIR / "templates",
    static_dir=APP_DIR / "static",
    database_url=os.getenv(
        "DSC_DATABASE_URL",
        f"sqlite:///{(BASE_DIR / 'domain_security.db').as_posix()}",
    ),
    dns_timeout_seconds=_env_float("DSC_DNS_TIMEOUT_SECONDS", 3.0),
    website_tls_timeout_seconds=_env_float("DSC_WEBSITE_TLS_TIMEOUT_SECONDS", 3.0),
    email_tls_timeout_seconds=_env_float("DSC_EMAIL_TLS_TIMEOUT_SECONDS", 2.5),
    rdap_timeout_seconds=_env_float("DSC_RDAP_TIMEOUT_SECONDS", 2.0),
    mx_probe_limit=max(1, _env_int("DSC_MX_PROBE_LIMIT", 2)),
    analysis_cache_ttl_seconds=max(0, _env_int("DSC_ANALYSIS_CACHE_TTL_SECONDS", 300)),
    rdap_base_url=os.getenv("DSC_RDAP_BASE_URL", "https://rdap.org/domain/"),
    session_secret=os.getenv("DSC_SESSION_SECRET", "change-me-in-production"),
    session_max_age_seconds=max(300, _env_int("DSC_SESSION_MAX_AGE_SECONDS", 604800)),
    monitoring_scheduler_enabled=_env_bool("DSC_MONITORING_SCHEDULER_ENABLED", True),
    monitoring_poll_seconds=max(15, _env_int("DSC_MONITORING_POLL_SECONDS", 60)),
    monitoring_score_drop_threshold=max(1, _env_int("DSC_MONITORING_SCORE_DROP_THRESHOLD", 15)),
)
