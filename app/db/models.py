from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    notification_preference: Mapped["NotificationPreference | None"] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
    )
    monitored_domains: Mapped[list["MonitoredDomain"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class NotificationPreference(Base):
    __tablename__ = "notification_preferences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    email_alerts_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    user: Mapped[User] = relationship(back_populates="notification_preference")


class TrackedDomain(Base):
    __tablename__ = "tracked_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    normalized_domain: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    snapshots: Mapped[list["AnalysisSnapshot"]] = relationship(
        back_populates="tracked_domain",
        cascade="all, delete-orphan",
    )


class AnalysisSnapshot(Base):
    __tablename__ = "analysis_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tracked_domain_id: Mapped[int] = mapped_column(
        ForeignKey("tracked_domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    input_target: Mapped[str] = mapped_column(String(320), nullable=False)
    analysis_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    tracked_domain: Mapped[TrackedDomain] = relationship(back_populates="snapshots")
    monitoring_runs: Mapped[list["MonitoringRun"]] = relationship(back_populates="analysis_snapshot")


class MonitoredDomain(Base):
    __tablename__ = "monitored_domains"
    __table_args__ = (
        UniqueConstraint("user_id", "normalized_domain", name="uq_monitored_domains_user_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    normalized_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    input_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    monitoring_frequency: Mapped[str] = mapped_column(String(16), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    user: Mapped[User] = relationship(back_populates="monitored_domains")
    monitoring_runs: Mapped[list["MonitoringRun"]] = relationship(
        back_populates="monitored_domain",
        cascade="all, delete-orphan",
    )
    alert_events: Mapped[list["AlertEvent"]] = relationship(
        back_populates="monitored_domain",
        cascade="all, delete-orphan",
    )


class MonitoringRun(Base):
    __tablename__ = "monitoring_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitored_domain_id: Mapped[int] = mapped_column(
        ForeignKey("monitored_domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analysis_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("analysis_snapshots.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    snapshot_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    diff_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    run_status: Mapped[str] = mapped_column(String(32), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    monitored_domain: Mapped[MonitoredDomain] = relationship(back_populates="monitoring_runs")
    analysis_snapshot: Mapped[AnalysisSnapshot | None] = relationship(back_populates="monitoring_runs")
    alert_events: Mapped[list["AlertEvent"]] = relationship(back_populates="monitoring_run")


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitored_domain_id: Mapped[int] = mapped_column(
        ForeignKey("monitored_domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    monitoring_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitoring_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    monitored_domain: Mapped[MonitoredDomain] = relationship(back_populates="alert_events")
    monitoring_run: Mapped[MonitoringRun | None] = relationship(back_populates="alert_events")
