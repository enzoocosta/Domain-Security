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
    network_timeout_seconds: float
    rdap_base_url: str


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
    network_timeout_seconds=_env_float("DSC_NETWORK_TIMEOUT_SECONDS", 4.0),
    rdap_base_url=os.getenv("DSC_RDAP_BASE_URL", "https://rdap.org/domain/"),
)
