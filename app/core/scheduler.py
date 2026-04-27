from __future__ import annotations

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from app.core.config import settings
from app.db.models import MonitoredDomain
from app.db.session import SessionLocal
from app.services.monitoring_service import run_check_for_target

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler(timezone="America/Sao_Paulo")


async def monitoring_cycle() -> None:
    """Ciclo principal de monitoramento baseado no modelo real do projeto."""

    logger.info("Iniciando ciclo de monitoramento")
    db = SessionLocal()
    try:
        now = datetime.now(tz=UTC)
        targets = db.scalars(
            select(MonitoredDomain).where(
                MonitoredDomain.monitoring_status == "active",
                MonitoredDomain.is_active.is_(True),
            )
        ).all()

        for target in targets:
            try:
                next_check = target.next_check_at or target.next_run_at
                if next_check is not None and next_check.tzinfo is None:
                    next_check = next_check.replace(tzinfo=UTC)
                if next_check is not None and next_check > now:
                    continue

                await run_check_for_target(db, target)
                logger.info("Check concluido: %s", target.normalized_domain)
            except Exception as exc:
                db.rollback()
                logger.error("Erro no check de %s: %s", target.normalized_domain, exc)
    finally:
        db.close()
    logger.info("Ciclo de monitoramento finalizado")


def start_scheduler() -> None:
    if not settings.monitoring_scheduler_enabled:
        return
    scheduler.add_job(
        monitoring_cycle,
        trigger=IntervalTrigger(minutes=30),
        id="monitoring_cycle",
        replace_existing=True,
        misfire_grace_time=300,
    )
    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler iniciado")


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler parado")
