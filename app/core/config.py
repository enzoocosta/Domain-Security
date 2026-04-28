from dataclasses import dataclass
from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parents[2]
APP_DIR = BASE_DIR / "app"


def _env_text(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    cleaned = value.strip()
    return cleaned or default


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
    DEBUG: bool
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
    internal_run_checks_token: str | None
    geoip_enabled: bool
    geoip_provider: str
    geoip_city_db_path: str | None
    geoip_asn_db_path: str | None
    geoip_isp_db_path: str | None
    geoip_anonymous_db_path: str | None
    geoip_account_id: str | None
    geoip_license_key: str | None
    geoip_host: str | None
    geoip_timeout_seconds: float
    email_delivery_enabled: bool
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None
    smtp_use_tls: bool
    smtp_use_ssl: bool
    smtp_timeout_seconds: float
    smtp_from_email: str | None
    smtp_from_name: str | None
    asset_discovery_enabled: bool
    asset_discovery_provider: str
    amass_binary_path: str | None
    amass_timeout_seconds: int
    amass_passive_mode: bool
    monitoring_plus_scheduler_enabled: bool
    monitoring_plus_detection_interval_seconds: int
    monitoring_plus_alert_dispatch_interval_seconds: int
    monitoring_plus_trial_days: int
    monitoring_plus_spike_window_seconds: int
    monitoring_plus_spike_baseline_window_seconds: int
    monitoring_plus_spike_multiplier: float
    monitoring_plus_spike_min_requests: int
    monitoring_plus_scan_window_seconds: int
    monitoring_plus_scan_unique_paths_threshold: int
    monitoring_plus_scan_404_ratio_threshold: float
    monitoring_plus_error_window_seconds: int
    monitoring_plus_error_rate_threshold: float
    monitoring_plus_error_min_requests: int
    monitoring_plus_event_retention_hours: int
    monitoring_plus_ingest_max_batch: int
    monitoring_plus_suspicious_user_agents: tuple[str, ...]


settings = Settings(
    DEBUG=_env_bool("DEBUG", False),
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
    monitoring_score_drop_threshold=max(
        1, _env_int("DSC_MONITORING_SCORE_DROP_THRESHOLD", 15)
    ),
    internal_run_checks_token=_env_text("DSC_INTERNAL_RUN_CHECKS_TOKEN"),
    geoip_enabled=_env_bool("DSC_GEOIP_ENABLED", True),
    geoip_provider=(_env_text("DSC_GEOIP_PROVIDER", "disabled") or "disabled").lower(),
    geoip_city_db_path=_env_text("DSC_GEOIP_CITY_DB_PATH"),
    geoip_asn_db_path=_env_text("DSC_GEOIP_ASN_DB_PATH"),
    geoip_isp_db_path=_env_text("DSC_GEOIP_ISP_DB_PATH"),
    geoip_anonymous_db_path=_env_text("DSC_GEOIP_ANONYMOUS_DB_PATH"),
    geoip_account_id=_env_text("DSC_GEOIP_ACCOUNT_ID"),
    geoip_license_key=_env_text("DSC_GEOIP_LICENSE_KEY"),
    geoip_host=_env_text("DSC_GEOIP_HOST"),
    geoip_timeout_seconds=_env_float("DSC_GEOIP_TIMEOUT_SECONDS", 2.5),
    email_delivery_enabled=_env_bool("DSC_EMAIL_DELIVERY_ENABLED", False),
    smtp_host=_env_text("DSC_SMTP_HOST"),
    smtp_port=max(1, _env_int("DSC_SMTP_PORT", 587)),
    smtp_username=_env_text("DSC_SMTP_USERNAME"),
    smtp_password=_env_text("DSC_SMTP_PASSWORD"),
    smtp_use_tls=_env_bool("DSC_SMTP_USE_TLS", True),
    smtp_use_ssl=_env_bool("DSC_SMTP_USE_SSL", False),
    smtp_timeout_seconds=_env_float("DSC_SMTP_TIMEOUT_SECONDS", 5.0),
    smtp_from_email=_env_text("DSC_SMTP_FROM_EMAIL"),
    smtp_from_name=_env_text("DSC_SMTP_FROM_NAME", "Domain Security Checker"),
    asset_discovery_enabled=_env_bool("DSC_ASSET_DISCOVERY_ENABLED", False),
    asset_discovery_provider=(
        _env_text("DSC_ASSET_DISCOVERY_PROVIDER", "disabled") or "disabled"
    ).lower(),
    amass_binary_path=_env_text("DSC_AMASS_BINARY_PATH", "amass"),
    amass_timeout_seconds=max(10, _env_int("DSC_AMASS_TIMEOUT_SECONDS", 300)),
    amass_passive_mode=_env_bool("DSC_AMASS_PASSIVE_MODE", True),
    monitoring_plus_scheduler_enabled=_env_bool(
        "DSC_MONITORING_PLUS_SCHEDULER_ENABLED", True
    ),
    monitoring_plus_detection_interval_seconds=max(
        15, _env_int("DSC_MONITORING_PLUS_DETECTION_INTERVAL_SECONDS", 60)
    ),
    monitoring_plus_alert_dispatch_interval_seconds=max(
        15, _env_int("DSC_MONITORING_PLUS_ALERT_DISPATCH_INTERVAL_SECONDS", 60)
    ),
    monitoring_plus_trial_days=max(1, _env_int("DSC_MONITORING_PLUS_TRIAL_DAYS", 14)),
    monitoring_plus_spike_window_seconds=max(
        30, _env_int("DSC_MONITORING_PLUS_SPIKE_WINDOW_SECONDS", 60)
    ),
    monitoring_plus_spike_baseline_window_seconds=max(
        300, _env_int("DSC_MONITORING_PLUS_SPIKE_BASELINE_WINDOW_SECONDS", 86400)
    ),
    monitoring_plus_spike_multiplier=max(
        1.5, _env_float("DSC_MONITORING_PLUS_SPIKE_MULTIPLIER", 10.0)
    ),
    monitoring_plus_spike_min_requests=max(
        5, _env_int("DSC_MONITORING_PLUS_SPIKE_MIN_REQUESTS", 50)
    ),
    monitoring_plus_scan_window_seconds=max(
        60, _env_int("DSC_MONITORING_PLUS_SCAN_WINDOW_SECONDS", 300)
    ),
    monitoring_plus_scan_unique_paths_threshold=max(
        5, _env_int("DSC_MONITORING_PLUS_SCAN_UNIQUE_PATHS_THRESHOLD", 20)
    ),
    monitoring_plus_scan_404_ratio_threshold=max(
        0.1, _env_float("DSC_MONITORING_PLUS_SCAN_404_RATIO_THRESHOLD", 0.5)
    ),
    monitoring_plus_error_window_seconds=max(
        60, _env_int("DSC_MONITORING_PLUS_ERROR_WINDOW_SECONDS", 300)
    ),
    monitoring_plus_error_rate_threshold=max(
        0.05, _env_float("DSC_MONITORING_PLUS_ERROR_RATE_THRESHOLD", 0.3)
    ),
    monitoring_plus_error_min_requests=max(
        10, _env_int("DSC_MONITORING_PLUS_ERROR_MIN_REQUESTS", 30)
    ),
    monitoring_plus_event_retention_hours=max(
        1, _env_int("DSC_MONITORING_PLUS_EVENT_RETENTION_HOURS", 168)
    ),
    monitoring_plus_ingest_max_batch=max(
        1, _env_int("DSC_MONITORING_PLUS_INGEST_MAX_BATCH", 500)
    ),
    monitoring_plus_suspicious_user_agents=tuple(
        item.strip().lower()
        for item in (
            _env_text(
                "DSC_MONITORING_PLUS_SUSPICIOUS_USER_AGENTS",
                "nikto,sqlmap,nmap,masscan,acunetix,nessus,wpscan,zgrab,dirbuster,gobuster",
            )
            or ""
        ).split(",")
        if item.strip()
    ),
)
