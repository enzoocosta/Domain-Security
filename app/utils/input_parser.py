import re

from app.core.exceptions import InputValidationError
from app.schemas.analysis import NormalizedTarget


DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_target(target: str) -> NormalizedTarget:
    cleaned = target.strip()
    if not cleaned:
        raise InputValidationError("Informe um domínio ou e-mail.")
    if len(cleaned) > 320:
        raise InputValidationError("A entrada excede o tamanho máximo permitido.")
    if any(char.isspace() for char in cleaned):
        raise InputValidationError("A entrada não pode conter espaços.")
    if "://" in cleaned or "/" in cleaned:
        raise InputValidationError("Use apenas um domínio ou e-mail, não uma URL.")

    if "@" in cleaned:
        local_part, separator, domain_part = cleaned.rpartition("@")
        if separator != "@" or not local_part or not domain_part or "@" in local_part:
            raise InputValidationError("E-mail inválido.")
        normalized_domain = _normalize_domain(domain_part)
        return NormalizedTarget(
            original=cleaned,
            normalized_input=f"{local_part}@{normalized_domain}",
            target_type="email",
            analysis_domain=normalized_domain,
        )

    normalized_domain = _normalize_domain(cleaned)
    return NormalizedTarget(
        original=cleaned,
        normalized_input=normalized_domain,
        target_type="domain",
        analysis_domain=normalized_domain,
    )


def _normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    if not candidate:
        raise InputValidationError("Domínio inválido.")

    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InputValidationError("Domínio inválido.") from exc

    if len(ascii_domain) > 253:
        raise InputValidationError("Domínio excede o tamanho máximo permitido.")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise InputValidationError("Informe um domínio completo, como exemplo.com.")

    for label in labels:
        if not DOMAIN_LABEL_RE.fullmatch(label):
            raise InputValidationError("Domínio inválido.")

    return ascii_domain
