from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AuthorizationError, InputValidationError
from app.db.models import DiscoveredSubdomain, DiscoveryRun, User
from app.db.session import SessionLocal
from app.schemas.discovery import DiscoveryRunCreateInput, DiscoveryRunDetail, DiscoveryRunSummary, DiscoveredSubdomainItem
from app.services.providers.amass_runner import AmassRunner, AssetDiscoveryResult, DiscoveredAssetRecord
from app.utils.input_parser import normalize_target


class AssetDiscoveryService:
    """Owns discovery runs, persistence and comparison of newly observed subdomains."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session] | None = None,
        runner: AmassRunner | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal
        self.runner = runner or AmassRunner(
            binary_path=settings.amass_binary_path or "amass",
            timeout_seconds=settings.amass_timeout_seconds,
            passive_mode=settings.amass_passive_mode,
            enabled=settings.asset_discovery_enabled and settings.asset_discovery_provider == "amass",
        )

    def create_run(self, *, user_id: int, domain: str) -> DiscoveryRunDetail:
        try:
            payload = DiscoveryRunCreateInput(domain=domain)
        except ValidationError as exc:
            raise InputValidationError(str(exc.errors()[0]["msg"])) from exc

        normalized_domain = normalize_target(payload.domain).analysis_domain
        started_at = self._utcnow()
        with self.session_factory() as db:
            self._require_user(db, user_id)
            run = DiscoveryRun(
                user_id=user_id,
                normalized_domain=normalized_domain,
                provider=self.runner.provider_name,
                run_status="running",
                asset_count=0,
                new_asset_count=0,
                started_at=started_at,
            )
            db.add(run)
            db.flush()

            result = self.runner.discover(normalized_domain)
            inserted_assets = self._persist_assets(
                db,
                user_id=user_id,
                normalized_domain=normalized_domain,
                run=run,
                assets=result.assets,
            )

            run.provider = result.provider
            run.run_status = result.status
            run.asset_count = len(inserted_assets)
            run.new_asset_count = sum(1 for item in inserted_assets if item.is_new)
            run.error_message = result.error_message
            run.completed_at = self._utcnow()
            db.commit()
            db.refresh(run)
            return self._to_detail(db, run)

    def list_runs(self, *, user_id: int, domain: str | None = None) -> list[DiscoveryRunSummary]:
        with self.session_factory() as db:
            self._require_user(db, user_id)
            stmt: Select[tuple[DiscoveryRun]] = (
                select(DiscoveryRun)
                .where(DiscoveryRun.user_id == user_id)
                .order_by(DiscoveryRun.started_at.desc(), DiscoveryRun.id.desc())
            )
            if domain:
                stmt = stmt.where(DiscoveryRun.normalized_domain == normalize_target(domain).analysis_domain)
            runs = db.scalars(stmt).all()
            return [self._to_summary(item) for item in runs]

    def get_run_detail(self, *, user_id: int, run_id: int) -> DiscoveryRunDetail:
        with self.session_factory() as db:
            run = self._require_run_for_user(db, user_id, run_id)
            return self._to_detail(db, run)

    def _persist_assets(
        self,
        db: Session,
        *,
        user_id: int,
        normalized_domain: str,
        run: DiscoveryRun,
        assets: list[DiscoveredAssetRecord],
    ) -> list[DiscoveredSubdomain]:
        inserted: list[DiscoveredSubdomain] = []
        for asset in assets:
            fqdn = asset.fqdn.lower()
            seen_before = db.scalar(
                select(DiscoveredSubdomain.id)
                .join(DiscoveryRun, DiscoveredSubdomain.discovery_run_id == DiscoveryRun.id)
                .where(
                    DiscoveryRun.user_id == user_id,
                    DiscoveryRun.normalized_domain == normalized_domain,
                    DiscoveredSubdomain.fqdn == fqdn,
                )
                .limit(1)
            )
            record = DiscoveredSubdomain(
                discovery_run_id=run.id,
                fqdn=fqdn,
                source=asset.source,
                ip_addresses=list(asset.ip_addresses),
                is_new=seen_before is None,
                created_at=self._utcnow(),
            )
            db.add(record)
            inserted.append(record)
        db.flush()
        return inserted

    @staticmethod
    def _require_user(db: Session, user_id: int) -> User:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            raise AuthorizationError("Usuario nao autenticado ou inativo.")
        return user

    @staticmethod
    def _require_run_for_user(db: Session, user_id: int, run_id: int) -> DiscoveryRun:
        run = db.get(DiscoveryRun, run_id)
        if run is None or run.user_id != user_id:
            raise AuthorizationError("Voce nao tem acesso a esta execucao de discovery.")
        return run

    def _to_detail(self, db: Session, run: DiscoveryRun) -> DiscoveryRunDetail:
        subdomains = db.scalars(
            select(DiscoveredSubdomain)
            .where(DiscoveredSubdomain.discovery_run_id == run.id)
            .order_by(DiscoveredSubdomain.fqdn.asc(), DiscoveredSubdomain.id.asc())
        ).all()
        return DiscoveryRunDetail(
            run=self._to_summary(run),
            subdomains=[
                DiscoveredSubdomainItem(
                    id=item.id,
                    fqdn=item.fqdn,
                    source=item.source,
                    ip_addresses=list(item.ip_addresses or []),
                    is_new=item.is_new,
                    created_at=item.created_at,
                )
                for item in subdomains
            ],
        )

    @staticmethod
    def _to_summary(run: DiscoveryRun) -> DiscoveryRunSummary:
        return DiscoveryRunSummary(
            id=run.id,
            normalized_domain=run.normalized_domain,
            provider=run.provider,
            status=run.run_status,
            asset_count=run.asset_count,
            new_asset_count=run.new_asset_count,
            error_message=run.error_message,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
