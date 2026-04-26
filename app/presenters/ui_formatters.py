from collections.abc import Iterable
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates

from app.core.config import settings

_EMPTY = object()

_CATEGORY_LABELS = {
    "dns": "DNS",
    "mx": "MX",
    "spf": "SPF",
    "dkim": "DKIM",
    "dmarc": "DMARC",
    "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT",
    "bimi": "BIMI",
    "dnssec": "DNSSEC",
    "consistencia": "Consistency",
    "tls_site": "Website TLS",
    "tls_email": "Mail Transport",
    "registro_dominio": "Domain Registration",
}

_OVERALL_SEVERITY_META = {
    "excelente": ("Excelente", "success"),
    "bom": ("Bom", "info"),
    "atencao": ("Atencao", "warning"),
    "alto": ("Alto risco", "danger"),
    "critico": ("Critico", "danger"),
}

_FINDING_SEVERITY_META = {
    "baixo": ("Baixo", "info"),
    "medio": ("Medio", "warning"),
    "alto": ("Alto", "danger"),
    "critico": ("Critico", "danger"),
}

_PRIORITY_META = {
    "alta": ("Alta prioridade", "danger"),
    "media": ("Media prioridade", "warning"),
    "baixa": ("Baixa prioridade", "info"),
}

_CHECK_STATUS_META = {
    "presente": ("Presente", "success"),
    "ausente": ("Ausente", "warning"),
    "invalido": ("Invalido", "danger"),
}

_DKIM_STATUS_META = {
    "confirmado_presente": ("Confirmado presente", "success"),
    "provavelmente_presente": ("Provavelmente presente", "info"),
    "desconhecido": ("Desconhecido", "neutral"),
    "provavelmente_ausente": ("Provavelmente ausente", "warning"),
    "invalido": ("Invalido", "danger"),
}

_EXPIRY_STATUS_META = {
    "ok": ("Valido", "success"),
    "proximo_expiracao": ("Proximo da expiracao", "warning"),
    "expirado": ("Expirado", "danger"),
    "desconhecido": ("Desconhecido", "neutral"),
}

_SPF_POSTURE_LABELS = {
    "restritivo": "Restritivo",
    "permissivo": "Permissivo",
    "neutro": "Neutro",
    "desconhecido": "Desconhecido",
}

_DMARC_STRENGTH_LABELS = {
    "fraco": "Fraco",
    "intermediario": "Intermediario",
    "forte": "Forte",
    "desconhecido": "Desconhecido",
}

_ALIGNMENT_LABELS = {
    "r": "Relaxado",
    "s": "Estrito",
}

_BOOLEAN_LABELS = {
    True: "Sim",
    False: "Nao",
}


def configure_template_filters(templates: Jinja2Templates) -> Jinja2Templates:
    templates.env.filters["format_datetime"] = format_datetime
    templates.env.filters["yes_no"] = yes_no
    templates.env.filters["humanize_token"] = humanize_token
    templates.env.globals["static_asset"] = static_asset
    return templates


@lru_cache(maxsize=256)
def _asset_version(path: str) -> str:
    asset_path = settings.static_dir / Path(path)
    try:
        return str(asset_path.stat().st_mtime_ns)
    except OSError:
        return settings.app_version


def static_asset(request: Any, path: str) -> str:
    base_url = str(request.url_for("static", path=path))
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}v={_asset_version(path)}"


def is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def format_datetime(value: datetime | None, empty: str = "-") -> str:
    if value is None:
        return empty
    rendered = value.strftime("%d/%m/%Y %H:%M")
    if value.tzinfo is None or value.utcoffset() is None:
        return rendered
    tz_name = value.tzname() or "UTC"
    return f"{rendered} {tz_name}"


def yes_no(value: bool | None, empty: str = "-") -> str:
    if value is None:
        return empty
    return _BOOLEAN_LABELS[value]


def humanize_token(value: str | None, empty: str = "-") -> str:
    if is_blank(value):
        return empty
    normalized = str(value).strip().replace("_", " ")
    return normalized[:1].upper() + normalized[1:]


def category_label(value: str) -> str:
    return _CATEGORY_LABELS.get(value, humanize_token(value))


def overall_severity_badge(value: str) -> dict[str, str]:
    label, tone = _OVERALL_SEVERITY_META.get(value, (humanize_token(value), "neutral"))
    return {"value": value, "label": label, "tone": tone}


def finding_severity_badge(value: str) -> dict[str, str]:
    label, tone = _FINDING_SEVERITY_META.get(value, (humanize_token(value), "neutral"))
    return {"value": value, "label": label, "tone": tone}


def recommendation_priority_badge(value: str) -> dict[str, str]:
    label, tone = _PRIORITY_META.get(value, (humanize_token(value), "neutral"))
    return {"value": value, "label": label, "tone": tone}


def check_status_badge(value: str) -> dict[str, str]:
    label, tone = _CHECK_STATUS_META.get(value, (humanize_token(value), "neutral"))
    return {"value": value, "label": label, "tone": tone}


def dkim_status_badge(value: str) -> dict[str, str]:
    label, tone = _DKIM_STATUS_META.get(value, (humanize_token(value), "neutral"))
    return {"value": value, "label": label, "tone": tone}


def expiry_status_badge(value: str) -> dict[str, str]:
    label, tone = _EXPIRY_STATUS_META.get(value, (humanize_token(value), "neutral"))
    return {"value": value, "label": label, "tone": tone}


def spf_posture_label(value: str | None) -> str:
    if is_blank(value):
        return "-"
    return _SPF_POSTURE_LABELS.get(str(value), humanize_token(str(value)))


def dmarc_strength_label(value: str | None) -> str:
    if is_blank(value):
        return "-"
    return _DMARC_STRENGTH_LABELS.get(str(value), humanize_token(str(value)))


def alignment_label(value: str | None) -> str:
    if is_blank(value):
        return "-"
    return _ALIGNMENT_LABELS.get(str(value), humanize_token(str(value)))


def confidence_label(value: str | None) -> str:
    return humanize_token(value)


def field_value(value: Any, empty: str = "-") -> str:
    if value is _EMPTY:
        return empty
    if isinstance(value, bool):
        return yes_no(value, empty=empty)
    if isinstance(value, datetime):
        return format_datetime(value, empty=empty)
    if is_blank(value):
        return empty
    return str(value)


def make_field(
    label: str,
    value: Any,
    *,
    tone: str = "neutral",
    detail: str | None = None,
    skip_if_empty: bool = True,
    empty: str = "-",
    classes: str = "",
    badge: dict[str, str] | None = None,
) -> dict[str, str] | None:
    if skip_if_empty and is_blank(value):
        return None
    rendered = field_value(value, empty=empty)
    if skip_if_empty and rendered == empty:
        return None
    return {
        "label": label,
        "value": rendered,
        "tone": tone,
        "detail": detail or "",
        "classes": classes,
        "badge": badge,
    }


def compact_fields(fields: Iterable[dict[str, str] | None]) -> list[dict[str, str]]:
    return [field for field in fields if field is not None]


def make_list_block(label: str, items: Iterable[Any]) -> dict[str, Any] | None:
    cleaned = [field_value(item) for item in items if not is_blank(item)]
    if not cleaned:
        return None
    return {"label": label, "items": cleaned}


def compact_list_blocks(blocks: Iterable[dict[str, Any] | None]) -> list[dict[str, Any]]:
    return [block for block in blocks if block is not None]
