from datetime import UTC, datetime
import json
from urllib import error, parse, request

from app.core.config import settings
from app.schemas.analysis import DomainRegistrationResult
from app.utils.tls_helpers import certificate_expiry_label


class DomainRegistrationService:
    """Queries RDAP data for the domain lifecycle when available."""

    def __init__(self, fetcher=None, timeout_seconds: float | None = None, base_url: str | None = None) -> None:
        self.fetcher = fetcher or self._fetch_rdap_payload
        self.timeout_seconds = timeout_seconds or settings.network_timeout_seconds
        self.base_url = base_url or settings.rdap_base_url

    def analyze(self, domain: str) -> DomainRegistrationResult:
        try:
            payload = self.fetcher(domain)
        except TimeoutError as exc:
            return DomainRegistrationResult(
                rdap_available=False,
                message="A consulta RDAP excedeu o tempo limite.",
                error=str(exc),
                source="RDAP",
            )
        except Exception as exc:
            return DomainRegistrationResult(
                rdap_available=False,
                message="Nao foi possivel obter dados RDAP para o dominio.",
                error=str(exc),
                source="RDAP",
            )

        created_at = self._extract_event_datetime(payload, ("registration", "registered", "creation"))
        expires_at = self._extract_event_datetime(payload, ("expiration", "expiry"))
        days_to_expire = self._calculate_days_to_expire(expires_at)
        registrar = self._extract_registrar(payload)
        status = [str(item) for item in payload.get("status", [])]

        return DomainRegistrationResult(
            rdap_available=True,
            created_at=created_at,
            expires_at=expires_at,
            days_to_expire=days_to_expire,
            expiry_status=certificate_expiry_label(days_to_expire),
            registrar=registrar,
            status=status,
            message=self._build_message(created_at, expires_at, registrar),
            source="RDAP",
        )

    def _fetch_rdap_payload(self, domain: str) -> dict:
        url = f"{self.base_url.rstrip('/')}/{parse.quote(domain)}"
        req = request.Request(
            url,
            headers={"Accept": "application/rdap+json, application/json"},
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                return json.load(response)
        except error.URLError as exc:
            if isinstance(getattr(exc, "reason", None), TimeoutError):
                raise TimeoutError("Timeout de rede na consulta RDAP.") from exc
            raise RuntimeError(f"Falha de rede na consulta RDAP: {exc}") from exc
        except error.HTTPError as exc:
            raise RuntimeError(f"Consulta RDAP retornou HTTP {exc.code}.") from exc

    @staticmethod
    def _extract_event_datetime(payload: dict, keywords: tuple[str, ...]) -> datetime | None:
        for event in payload.get("events", []):
            action = str(event.get("eventAction", "")).lower()
            if any(keyword in action for keyword in keywords):
                parsed = DomainRegistrationService._parse_datetime(event.get("eventDate"))
                if parsed is not None:
                    return parsed
        return None

    @staticmethod
    def _extract_registrar(payload: dict) -> str | None:
        if payload.get("registrarName"):
            return str(payload["registrarName"])

        for entity in payload.get("entities", []):
            roles = [str(role).lower() for role in entity.get("roles", [])]
            if "registrar" not in roles:
                continue
            vcard = entity.get("vcardArray")
            if not isinstance(vcard, list) or len(vcard) < 2:
                continue
            for item in vcard[1]:
                if len(item) >= 4 and item[0] in {"fn", "org"}:
                    return str(item[3])
        return None

    @staticmethod
    def _parse_datetime(value) -> datetime | None:
        if not value:
            return None
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    @staticmethod
    def _calculate_days_to_expire(expires_at: datetime | None) -> int | None:
        if expires_at is None:
            return None
        delta = expires_at - datetime.now(tz=UTC)
        return int(delta.total_seconds() // 86400)

    @staticmethod
    def _build_message(created_at: datetime | None, expires_at: datetime | None, registrar: str | None) -> str:
        if created_at and expires_at:
            return "Dados RDAP obtidos com datas de criacao e expiracao."
        if registrar:
            return "Dados RDAP obtidos parcialmente; algumas datas nao foram publicadas."
        return "Dados RDAP obtidos parcialmente para o dominio."
