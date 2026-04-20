from __future__ import annotations

from dataclasses import dataclass, field
import re
import shutil
import subprocess


_HOST_RE = re.compile(r"(?P<host>[a-z0-9][a-z0-9\.-]*\.[a-z]{2,})", re.IGNORECASE)


@dataclass(frozen=True)
class DiscoveredAssetRecord:
    fqdn: str
    source: str | None = None
    ip_addresses: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AssetDiscoveryResult:
    provider: str
    status: str
    assets: list[DiscoveredAssetRecord] = field(default_factory=list)
    error_message: str | None = None


class AmassRunner:
    """Runs OWASP Amass as an external binary and normalizes the observed subdomains."""

    provider_name = "amass"

    def __init__(
        self,
        *,
        binary_path: str,
        timeout_seconds: int,
        passive_mode: bool = True,
        enabled: bool = False,
    ) -> None:
        self.binary_path = binary_path
        self.timeout_seconds = timeout_seconds
        self.passive_mode = passive_mode
        self.enabled = enabled

    def is_available(self) -> bool:
        if not self.enabled:
            return False
        return shutil.which(self.binary_path) is not None

    def discover(self, domain: str) -> AssetDiscoveryResult:
        if not self.is_available():
            return AssetDiscoveryResult(
                provider=self.provider_name,
                status="unavailable",
                error_message="O binario do Amass nao esta disponivel neste ambiente.",
            )

        command = [self.binary_path, "enum", "-d", domain]
        if self.passive_mode:
            command.append("-passive")

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return AssetDiscoveryResult(
                provider=self.provider_name,
                status="failed",
                error_message=f"Amass excedeu o tempo limite configurado ({self.timeout_seconds}s).",
            )
        except OSError as exc:
            return AssetDiscoveryResult(
                provider=self.provider_name,
                status="failed",
                error_message=str(exc),
            )

        assets = self._parse_assets(domain, completed.stdout, completed.stderr)
        if completed.returncode != 0 and not assets:
            return AssetDiscoveryResult(
                provider=self.provider_name,
                status="failed",
                error_message=(completed.stderr or completed.stdout or "Amass retornou erro sem resultados utilizaveis.").strip(),
            )
        if completed.returncode != 0:
            return AssetDiscoveryResult(
                provider=self.provider_name,
                status="partial",
                assets=assets,
                error_message=(completed.stderr or "Amass retornou parcialmente com codigo diferente de zero.").strip(),
            )
        return AssetDiscoveryResult(
            provider=self.provider_name,
            status="completed",
            assets=assets,
        )

    def _parse_assets(self, domain: str, stdout: str, stderr: str) -> list[DiscoveredAssetRecord]:
        observed: dict[str, DiscoveredAssetRecord] = {}
        suffix = f".{domain.lower()}"

        for line in (stdout.splitlines() + stderr.splitlines()):
            candidate = self._extract_host(line, suffix=suffix, apex=domain.lower())
            if candidate is None:
                continue
            if candidate not in observed:
                observed[candidate] = DiscoveredAssetRecord(fqdn=candidate, source="amass")

        return sorted(observed.values(), key=lambda item: item.fqdn)

    @staticmethod
    def _extract_host(line: str, *, suffix: str, apex: str) -> str | None:
        for match in _HOST_RE.finditer(line):
            host = match.group("host").rstrip(".").lower()
            if host == apex or host.endswith(suffix):
                return host
        return None
