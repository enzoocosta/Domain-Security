from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import UTC, datetime
from importlib import import_module
import json
from typing import Any
from urllib import error, parse, request

from app.core.config import settings
from app.schemas.analysis import DomainRegistrationResult
from app.utils.tls_helpers import domain_expiry_label


class DomainRegistrationService:
    """Collects domain lifecycle metadata primarily through WHOIS with safe fallback handling."""

    def __init__(
        self,
        fetcher=None,
        fallback_fetcher=None,
        timeout_seconds: float | None = None,
        base_url: str | None = None,
    ) -> None:
        self.fetcher = fetcher or self._fetch_whois_payload
        self.timeout_seconds = timeout_seconds or settings.rdap_timeout_seconds
        self.base_url = base_url or settings.rdap_base_url
        if fallback_fetcher is not None:
            self.fallback_fetcher = fallback_fetcher
        elif fetcher is None:
            self.fallback_fetcher = self._fetch_rdap_payload
        else:
            self.fallback_fetcher = None

    def analyze(self, domain: str) -> DomainRegistrationResult:
        primary_error: str | None = None

        try:
            payload = self._run_lookup(self.fetcher, domain)
            result = self._build_whois_result(payload)
            if self._has_meaningful_registration_data(result):
                return result
            primary_error = "WHOIS nao retornou dados suficientes para o dominio."
        except TimeoutError as exc:
            primary_error = str(exc)
        except Exception as exc:
            primary_error = str(exc)

        if self.fallback_fetcher is not None:
            try:
                payload = self._run_lookup(self.fallback_fetcher, domain)
                fallback_result = self._build_rdap_result(payload)
                if self._has_meaningful_registration_data(fallback_result):
                    return fallback_result
                fallback_error = "O fallback de registro tambem nao retornou dados suficientes."
            except TimeoutError as exc:
                fallback_error = str(exc)
            except Exception as exc:
                fallback_error = str(exc)
            primary_error = self._join_errors(primary_error, fallback_error)

        return DomainRegistrationResult(
            available=False,
            whois_available=False,
            rdap_available=False,
            message="Nao foi possivel obter dados WHOIS para o dominio.",
            error=primary_error,
            source="WHOIS",
        )

    def _fetch_whois_payload(self, domain: str):
        try:
            whois_module = import_module("whois")
        except Exception as exc:  # pragma: no cover - optional dependency/runtime path
            raise RuntimeError("Biblioteca python-whois indisponivel no ambiente.") from exc

        try:
            return whois_module.whois(domain)
        except Exception as exc:
            raise RuntimeError(f"Falha na consulta WHOIS: {exc}") from exc

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

    def _run_lookup(self, lookup_func, domain: str):
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dsc-registration")
        future: Future = executor.submit(lookup_func, domain)
        try:
            return future.result(timeout=self.timeout_seconds)
        except FutureTimeoutError as exc:
            future.cancel()
            raise TimeoutError(
                f"A consulta de registro para '{domain}' excedeu o tempo limite configurado."
            ) from exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def _build_whois_result(self, payload: Any) -> DomainRegistrationResult:
        created_at = self._pick_datetime(
            self._pick_first(
                self._mapping_get(payload, "creation_date"),
                self._mapping_get(payload, "created"),
            ),
            prefer="min",
        )
        expires_at = self._pick_datetime(
            self._pick_first(
                self._mapping_get(payload, "expiration_date"),
                self._mapping_get(payload, "expires"),
                self._mapping_get(payload, "registry_expiry_date"),
            ),
            prefer="max",
        )
        days_to_expire = self._calculate_days_to_expire(expires_at)
        registrar = self._stringify(self._pick_first(
            self._mapping_get(payload, "registrar"),
            self._mapping_get(payload, "registrar_name"),
        ))
        status = self._normalize_list(self._mapping_get(payload, "status"))
        available = any([created_at, expires_at, registrar, status])

        return DomainRegistrationResult(
            available=available,
            whois_available=available,
            rdap_available=available,
            created_at=created_at,
            expires_at=expires_at,
            days_to_expire=days_to_expire,
            expiry_status=domain_expiry_label(days_to_expire),
            registrar=registrar,
            status=status,
            message=self._build_message(created_at, expires_at, registrar, available=available),
            source="WHOIS",
        )

    def _build_rdap_result(self, payload: dict[str, Any]) -> DomainRegistrationResult:
        created_at = self._extract_event_datetime(payload, ("registration", "registered", "creation"))
        expires_at = self._extract_event_datetime(payload, ("expiration", "expiry"))
        days_to_expire = self._calculate_days_to_expire(expires_at)
        registrar = self._extract_registrar(payload)
        status = [str(item) for item in payload.get("status", []) if str(item).strip()]
        available = any([created_at, expires_at, registrar, status])

        return DomainRegistrationResult(
            available=available,
            whois_available=False,
            rdap_available=available,
            created_at=created_at,
            expires_at=expires_at,
            days_to_expire=days_to_expire,
            expiry_status=domain_expiry_label(days_to_expire),
            registrar=registrar,
            status=status,
            message=self._build_message(created_at, expires_at, registrar, available=available),
            source="RDAP fallback",
        )

    @staticmethod
    def _mapping_get(payload: Any, key: str):
        if payload is None:
            return None
        if isinstance(payload, Mapping):
            return payload.get(key)
        return getattr(payload, key, None)

    @classmethod
    def _pick_datetime(cls, value: Any, *, prefer: str) -> datetime | None:
        candidates = [item for item in cls._flatten_values(value) if item is not None]
        parsed_values = [cls._parse_datetime(item) for item in candidates]
        valid_values = [item for item in parsed_values if item is not None]
        if not valid_values:
            return None
        return min(valid_values) if prefer == "min" else max(valid_values)

    @classmethod
    def _flatten_values(cls, value: Any) -> list[Any]:
        if isinstance(value, (list, tuple, set)):
            flattened: list[Any] = []
            for item in value:
                flattened.extend(cls._flatten_values(item))
            return flattened
        return [value]

    @staticmethod
    def _extract_event_datetime(payload: dict[str, Any], keywords: tuple[str, ...]) -> datetime | None:
        for event in payload.get("events", []):
            action = str(event.get("eventAction", "")).lower()
            if any(keyword in action for keyword in keywords):
                parsed = DomainRegistrationService._parse_datetime(event.get("eventDate"))
                if parsed is not None:
                    return parsed
        return None

    @staticmethod
    def _extract_registrar(payload: dict[str, Any]) -> str | None:
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
    def _parse_datetime(value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)

        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        for candidate in (
            text,
            text.replace(" ", "T", 1) if " " in text and "T" not in text else text,
        ):
            try:
                parsed = datetime.fromisoformat(candidate)
            except ValueError:
                continue
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        return None

    @staticmethod
    def _normalize_list(value: Any) -> list[str]:
        items = value if isinstance(value, (list, tuple, set)) else [value]
        normalized: list[str] = []
        seen: set[str] = set()
        for item in items:
            text = DomainRegistrationService._stringify(item)
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    @staticmethod
    def _stringify(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _calculate_days_to_expire(expires_at: datetime | None) -> int | None:
        if expires_at is None:
            return None
        delta = expires_at - datetime.now(tz=UTC)
        return int(delta.total_seconds() // 86400)

    @staticmethod
    def _build_message(
        created_at: datetime | None,
        expires_at: datetime | None,
        registrar: str | None,
        *,
        available: bool,
    ) -> str:
        if not available:
            return "Nenhum dado util de registro foi retornado para o dominio."
        if created_at and expires_at:
            return "Dados de registro obtidos com datas de criacao e expiracao."
        if registrar:
            return "Dados de registro obtidos parcialmente; algumas datas nao foram publicadas."
        return "Dados de registro obtidos parcialmente para o dominio."

    @staticmethod
    def _has_meaningful_registration_data(result: DomainRegistrationResult) -> bool:
        return bool(
            result.available
            or result.registrar
            or result.created_at
            or result.expires_at
            or result.status
        )

    @staticmethod
    def _pick_first(*values: Any):
        for value in values:
            if value is not None:
                return value
        return None

    @staticmethod
    def _join_errors(*errors: str | None) -> str | None:
        cleaned = [item.strip() for item in errors if item and item.strip()]
        if not cleaned:
            return None
        return " | ".join(cleaned)
