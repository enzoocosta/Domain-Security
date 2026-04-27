from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base


connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
)


def init_db(bind_engine=None) -> None:
    import app.db.models  # noqa: F401

    active_engine = bind_engine or engine
    Base.metadata.create_all(bind=active_engine)
    _ensure_schema_compatibility(active_engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_schema_compatibility(bind_engine) -> None:
    inspector = inspect(bind_engine)
    table_names = set(inspector.get_table_names())
    if "users" in table_names:
        _ensure_columns(
            bind_engine,
            "users",
            {
                "role": "VARCHAR(32) NOT NULL DEFAULT 'client'",
            },
        )
        with bind_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE users
                    SET role = 'client'
                    WHERE role IS NULL OR role = ''
                    """
                )
            )

    if "monitored_domains" in table_names:
        _ensure_columns(
            bind_engine,
            "monitored_domains",
            {
                "monitoring_status": "VARCHAR(16) NOT NULL DEFAULT 'active'",
                "paused_at": "DATETIME",
                "deleted_at": "DATETIME",
                "plan": "VARCHAR(16) NOT NULL DEFAULT 'standard'",
                "check_interval_minutes": "INTEGER NOT NULL DEFAULT 60",
                "next_check_at": "DATETIME",
                "last_alert_sent_at": "DATETIME",
                "last_alert_reason": "VARCHAR(255)",
                "alert_contacts": "TEXT NOT NULL DEFAULT '[]'",
            },
        )
        with bind_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE monitored_domains
                    SET monitoring_status = CASE
                        WHEN is_active = 1 THEN 'active'
                        ELSE 'paused'
                    END
                    WHERE monitoring_status IS NULL OR monitoring_status = ''
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE monitored_domains
                    SET plan = 'standard'
                    WHERE plan IS NULL OR plan = ''
                    """
                )
            )
            if "premium_subscriptions" in table_names:
                connection.execute(
                    text(
                        """
                        UPDATE monitored_domains
                        SET plan = 'plus'
                        WHERE EXISTS (
                            SELECT 1
                            FROM premium_subscriptions
                            WHERE premium_subscriptions.monitored_domain_id = monitored_domains.id
                              AND premium_subscriptions.status IN ('trial', 'active', 'past_due')
                        )
                        """
                    )
                )
            connection.execute(
                text(
                    """
                    UPDATE monitored_domains
                    SET check_interval_minutes = CASE
                        WHEN monitoring_frequency = 'weekly' THEN 10080
                        WHEN monitoring_frequency = 'monthly' THEN 43200
                        ELSE 1440
                    END
                    WHERE check_interval_minutes IS NULL OR check_interval_minutes <= 0
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE monitored_domains
                    SET next_check_at = COALESCE(next_check_at, next_run_at)
                    WHERE next_check_at IS NULL
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE monitored_domains
                    SET alert_contacts = '[]'
                    WHERE alert_contacts IS NULL OR alert_contacts = ''
                    """
                )
            )

    if "alert_events" in table_names:
        _ensure_columns(
            bind_engine,
            "alert_events",
            {
                "email_delivery_status": "VARCHAR(16) NOT NULL DEFAULT 'skipped'",
                "email_last_attempt_at": "DATETIME",
                "email_sent_at": "DATETIME",
                "email_last_error": "TEXT",
            },
        )
        with bind_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE alert_events
                    SET email_delivery_status = 'skipped'
                    WHERE email_delivery_status IS NULL OR email_delivery_status = ''
                    """
                )
            )

    if "monitoring_runs" in table_names:
        _ensure_columns(
            bind_engine,
            "monitoring_runs",
            {
                "trigger_type": "VARCHAR(16) NOT NULL DEFAULT 'scheduled'",
                "alerts_fired": "TEXT NOT NULL DEFAULT '[]'",
                "check_duration_ms": "INTEGER",
            },
        )
        with bind_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE monitoring_runs
                    SET trigger_type = 'scheduled'
                    WHERE trigger_type IS NULL OR trigger_type = ''
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE monitoring_runs
                    SET alerts_fired = '[]'
                    WHERE alerts_fired IS NULL OR alerts_fired = ''
                    """
                )
            )


def _ensure_columns(bind_engine, table_name: str, definitions: dict[str, str]) -> None:
    inspector = inspect(bind_engine)
    current_columns = {column["name"] for column in inspector.get_columns(table_name)}
    for column_name, definition in definitions.items():
        if column_name in current_columns:
            continue
        with bind_engine.begin() as connection:
            connection.execute(
                text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")
            )
