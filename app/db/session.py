from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


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
    if "monitored_domains" in table_names:
        _ensure_columns(
            bind_engine,
            "monitored_domains",
            {
                "monitoring_status": "VARCHAR(16) NOT NULL DEFAULT 'active'",
                "paused_at": "DATETIME",
                "deleted_at": "DATETIME",
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


def _ensure_columns(bind_engine, table_name: str, definitions: dict[str, str]) -> None:
    inspector = inspect(bind_engine)
    current_columns = {
        column["name"]
        for column in inspector.get_columns(table_name)
    }
    for column_name, definition in definitions.items():
        if column_name in current_columns:
            continue
        with bind_engine.begin() as connection:
            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"))
