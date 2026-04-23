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
    discovery_runs: Mapped[list["DiscoveryRun"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    api_tokens: Mapped[list["ApiToken"]] = relationship(
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
    monitoring_status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", index=True)
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    premium_subscription: Mapped["PremiumSubscription | None"] = relationship(
        back_populates="monitored_domain",
        cascade="all, delete-orphan",
        uselist=False,
    )
    premium_ingest_tokens: Mapped[list["PremiumIngestToken"]] = relationship(
        back_populates="monitored_domain",
        cascade="all, delete-orphan",
    )
    traffic_events: Mapped[list["TrafficEvent"]] = relationship(
        back_populates="monitored_domain",
        cascade="all, delete-orphan",
    )
    traffic_incidents: Mapped[list["TrafficIncident"]] = relationship(
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
    email_delivery_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    email_last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    monitored_domain: Mapped[MonitoredDomain] = relationship(back_populates="alert_events")
    monitoring_run: Mapped[MonitoringRun | None] = relationship(back_populates="alert_events")


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (
        UniqueConstraint("token_identifier", name="uq_api_tokens_identifier"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    token_identifier: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    token_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    user: Mapped[User] = relationship(back_populates="api_tokens")


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    normalized_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    run_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="discovery_runs")
    subdomains: Mapped[list["DiscoveredSubdomain"]] = relationship(
        back_populates="discovery_run",
        cascade="all, delete-orphan",
    )


class DiscoveredSubdomain(Base):
    __tablename__ = "discovered_subdomains"
    __table_args__ = (
        UniqueConstraint("discovery_run_id", "fqdn", name="uq_discovered_subdomains_run_fqdn"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    discovery_run_id: Mapped[int] = mapped_column(
        ForeignKey("discovery_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fqdn: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    is_new: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    discovery_run: Mapped[DiscoveryRun] = relationship(back_populates="subdomains")


class PremiumSubscription(Base):
    """Commercial state of the Monitoring Plus add-on for a monitored domain."""

    __tablename__ = "premium_subscriptions"
    __table_args__ = (
        UniqueConstraint("monitored_domain_id", name="uq_premium_subscriptions_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitored_domain_id: Mapped[int] = mapped_column(
        ForeignKey("monitored_domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    plan_code: Mapped[str] = mapped_column(String(32), nullable=False, default="monitoring_plus")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="trial", index=True)
    trial_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    monitored_domain: Mapped[MonitoredDomain] = relationship(back_populates="premium_subscription")


class PremiumIngestToken(Base):
    """Authenticates traffic ingestion from a monitored domain to Monitoring Plus."""

    __tablename__ = "premium_ingest_tokens"
    __table_args__ = (
        UniqueConstraint("token_identifier", name="uq_premium_ingest_tokens_identifier"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitored_domain_id: Mapped[int] = mapped_column(
        ForeignKey("monitored_domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    token_identifier: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    token_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    monitored_domain: Mapped[MonitoredDomain] = relationship(back_populates="premium_ingest_tokens")


class TrafficEvent(Base):
    """Append-only log of HTTP requests reported by a customer for Monitoring Plus."""

    __tablename__ = "premium_traffic_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitored_domain_id: Mapped[int] = mapped_column(
        ForeignKey("monitored_domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    referer: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    monitored_domain: Mapped[MonitoredDomain] = relationship(back_populates="traffic_events")


class TrafficIncident(Base):
    """Detected suspicious behavior derived from ingested traffic events."""

    __tablename__ = "premium_traffic_incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitored_domain_id: Mapped[int] = mapped_column(
        ForeignKey("monitored_domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    email_delivery_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    email_last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    monitored_domain: Mapped[MonitoredDomain] = relationship(back_populates="traffic_incidents")
