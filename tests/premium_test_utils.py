from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.services.auth_service import AuthenticationService
from app.services.monitoring_service import MonitoringService


def build_test_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    Base.metadata.create_all(bind=engine)
    return session_factory


def create_test_user(session_factory, email: str = "owner@example.com"):
    auth_service = AuthenticationService(session_factory=session_factory)
    return auth_service.register_user(email, "supersecret")


def create_monitored_domain(
    session_factory,
    *,
    user_id: int,
    domain: str = "example.com",
    monitoring_frequency: str = "daily",
    input_label: str | None = "Dominio principal",
):
    monitoring_service = MonitoringService(session_factory=session_factory)
    return monitoring_service.create_monitored_domain(
        user_id=user_id,
        domain=domain,
        monitoring_frequency=monitoring_frequency,
        input_label=input_label,
    )
