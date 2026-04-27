"""Owns ingest tokens used by Monitoring Plus to authenticate traffic events.

A ``PremiumIngestToken`` is bound to a single ``MonitoredDomain`` (not to the
user) so the customer can rotate or revoke a per-domain credential safely from
the Monitoring Plus dashboard without affecting the read/write API tokens used
by ``ApiTokenService``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import secrets

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InputValidationError,
)
from app.db.models import MonitoredDomain, PremiumIngestToken
from app.db.session import SessionLocal
from app.schemas.monitoring_plus import (
    PremiumIngestTokenCreateInput,
    PremiumIngestTokenCreateResult,
    PremiumIngestTokenSummary,
)


@dataclass(frozen=True)
class PremiumIngestPrincipal:
    token_id: int
    monitored_domain_id: int
    user_id: int
    normalized_domain: str


class PremiumIngestTokenService:
    HASH_NAME = "sha256"
    TOKEN_PREFIX = "mp"

    def __init__(self, session_factory: Callable[[], Session] | None = None) -> None:
        self.session_factory = session_factory or SessionLocal

    def create_token(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
        name: str,
    ) -> PremiumIngestTokenCreateResult:
        try:
            payload = PremiumIngestTokenCreateInput(name=name)
        except ValidationError as exc:
            raise InputValidationError(str(exc.errors()[0]["msg"])) from exc

        raw_token, identifier, token_prefix = self._generate_token_material()
        current_time = self._utcnow()
        with self.session_factory() as db:
            domain = self._require_owned_domain(
                db, user_id=user_id, monitored_domain_id=monitored_domain_id
            )
            token = PremiumIngestToken(
                monitored_domain_id=domain.id,
                name=payload.name,
                token_identifier=identifier,
                token_prefix=token_prefix,
                token_hash=self._hash_token(raw_token),
                is_active=True,
                created_at=current_time,
                updated_at=current_time,
            )
            db.add(token)
            db.commit()
            db.refresh(token)
            return PremiumIngestTokenCreateResult(
                token=raw_token,
                token_item=self._to_summary(token),
            )

    def list_tokens(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
    ) -> list[PremiumIngestTokenSummary]:
        with self.session_factory() as db:
            self._require_owned_domain(
                db, user_id=user_id, monitored_domain_id=monitored_domain_id
            )
            tokens = db.scalars(
                select(PremiumIngestToken)
                .where(PremiumIngestToken.monitored_domain_id == monitored_domain_id)
                .order_by(
                    PremiumIngestToken.created_at.desc(), PremiumIngestToken.id.desc()
                )
            ).all()
            return [self._to_summary(item) for item in tokens]

    def list_tokens_in_session(
        self,
        db: Session,
        *,
        monitored_domain_id: int,
    ) -> list[PremiumIngestTokenSummary]:
        tokens = db.scalars(
            select(PremiumIngestToken)
            .where(PremiumIngestToken.monitored_domain_id == monitored_domain_id)
            .order_by(
                PremiumIngestToken.created_at.desc(), PremiumIngestToken.id.desc()
            )
        ).all()
        return [self._to_summary(item) for item in tokens]

    def set_token_active_state(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
        token_id: int,
        is_active: bool,
    ) -> PremiumIngestTokenSummary:
        with self.session_factory() as db:
            self._require_owned_domain(
                db, user_id=user_id, monitored_domain_id=monitored_domain_id
            )
            token = db.get(PremiumIngestToken, token_id)
            if token is None or token.monitored_domain_id != monitored_domain_id:
                raise AuthorizationError("Token de ingestao nao encontrado.")
            token.is_active = is_active
            token.updated_at = self._utcnow()
            db.commit()
            db.refresh(token)
            return self._to_summary(token)

    def revoke_token(
        self,
        *,
        user_id: int,
        monitored_domain_id: int,
        token_id: int,
    ) -> None:
        with self.session_factory() as db:
            self._require_owned_domain(
                db, user_id=user_id, monitored_domain_id=monitored_domain_id
            )
            token = db.get(PremiumIngestToken, token_id)
            if token is None or token.monitored_domain_id != monitored_domain_id:
                raise AuthorizationError("Token de ingestao nao encontrado.")
            db.delete(token)
            db.commit()

    def authenticate_token(self, raw_token: str) -> PremiumIngestPrincipal:
        identifier = self._extract_identifier(raw_token)
        if not identifier:
            raise AuthenticationError("Token de ingestao invalido.")

        with self.session_factory() as db:
            token = db.scalar(
                select(PremiumIngestToken)
                .join(
                    MonitoredDomain,
                    PremiumIngestToken.monitored_domain_id == MonitoredDomain.id,
                )
                .where(
                    PremiumIngestToken.token_identifier == identifier,
                    PremiumIngestToken.is_active.is_(True),
                    MonitoredDomain.deleted_at.is_(None),
                )
            )
            if token is None or not hmac.compare_digest(
                token.token_hash, self._hash_token(raw_token)
            ):
                raise AuthenticationError("Token de ingestao invalido.")

            token.last_used_at = self._utcnow()
            token.updated_at = token.last_used_at
            domain = token.monitored_domain
            db.commit()
            db.refresh(token)
            return PremiumIngestPrincipal(
                token_id=token.id,
                monitored_domain_id=domain.id,
                user_id=domain.user_id,
                normalized_domain=domain.normalized_domain,
            )

    # -- helpers ------------------------------------------------------

    @classmethod
    def _generate_token_material(cls) -> tuple[str, str, str]:
        identifier = secrets.token_hex(8)
        secret = secrets.token_urlsafe(24)
        raw_token = f"{cls.TOKEN_PREFIX}_{identifier}_{secret}"
        return raw_token, identifier, f"{cls.TOKEN_PREFIX}_{identifier}"

    @classmethod
    def _extract_identifier(cls, raw_token: str) -> str | None:
        parts = raw_token.strip().split("_", 2)
        if len(parts) != 3 or parts[0] != cls.TOKEN_PREFIX:
            return None
        return parts[1] or None

    @classmethod
    def _hash_token(cls, raw_token: str) -> str:
        return hashlib.new(cls.HASH_NAME, raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _require_owned_domain(
        db: Session,
        *,
        user_id: int,
        monitored_domain_id: int,
    ) -> MonitoredDomain:
        domain = db.get(MonitoredDomain, monitored_domain_id)
        if domain is None or domain.user_id != user_id or domain.deleted_at is not None:
            raise AuthorizationError(
                "Dominio monitorado nao encontrado para este usuario."
            )
        return domain

    @staticmethod
    def _to_summary(token: PremiumIngestToken) -> PremiumIngestTokenSummary:
        return PremiumIngestTokenSummary(
            id=token.id,
            monitored_domain_id=token.monitored_domain_id,
            name=token.name,
            token_prefix=token.token_prefix,
            is_active=token.is_active,
            last_used_at=token.last_used_at,
            created_at=token.created_at,
        )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
