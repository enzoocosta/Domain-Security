from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import MonitoringRun

ALERT_RULES = [
    {
        "id": "cert_expiring_critical",
        "label": "Certificado TLS expirando em menos de 7 dias",
        "severity": "critical",
        "cooldown_hours": 12,
    },
    {
        "id": "cert_expiring_warning",
        "label": "Certificado TLS expirando em menos de 30 dias",
        "severity": "warning",
        "cooldown_hours": 24,
    },
    {
        "id": "score_drop",
        "label": "Score de seguranca caiu mais de 10 pontos",
        "severity": "warning",
        "cooldown_hours": 6,
    },
    {
        "id": "ip_changed",
        "label": "Endereco IP do dominio mudou",
        "severity": "critical",
        "cooldown_hours": 1,
    },
    {
        "id": "dmarc_regressed",
        "label": "DMARC policy regrediu",
        "severity": "critical",
        "cooldown_hours": 1,
    },
]


def check_and_fire_alerts(
    db: Session,
    target,
    current_check: MonitoringRun,
    *,
    candidate_ids: list[str] | None = None,
) -> list[str]:
    """Aplica cooldown por regra sem duplicar o dispatch já existente do monitoramento.

    O projeto já entrega notificacoes por ``NotificationEmailService`` depois de
    sincronizar ``AlertEvent``. Aqui guardamos apenas quais regras passaram no
    cooldown para suportar scheduler, auditoria e deduplicacao temporal.
    """

    configured_rules = {rule["id"]: rule for rule in ALERT_RULES}
    candidates = list(dict.fromkeys(candidate_ids or []))
    fired: list[str] = []
    for candidate_id in candidates:
        rule = configured_rules.get(candidate_id)
        if rule is None:
            fired.append(candidate_id)
            continue
        if not _check_cooldown(db, target.id, rule["id"], rule["cooldown_hours"]):
            continue
        _dispatch_alert(target, rule)
        fired.append(candidate_id)

    current_check.alerts_fired = fired
    db.flush()
    return fired


def _check_cooldown(
    db: Session, target_id: int, rule_id: str, cooldown_hours: int
) -> bool:
    cutoff = datetime.now(tz=UTC) - timedelta(hours=cooldown_hours)
    recent_checks = db.scalars(
        select(MonitoringRun).where(
            MonitoringRun.monitored_domain_id == target_id,
            MonitoringRun.completed_at.is_not(None),
            MonitoringRun.completed_at >= cutoff,
        )
    ).all()

    for check in recent_checks:
        alerts = list(check.alerts_fired or [])
        if rule_id in alerts:
            return False
    return True


def _dispatch_alert(target, rule: dict) -> None:
    # A entrega real continua centralizada em NotificationEmailService para nao
    # duplicar e-mails e webhooks nesta adaptacao.
    _ = (target, rule)
