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

from app.core.exceptions import AuthenticationError, AuthorizationError, InputValidationError
from app.db.models import ApiToken, User
from app.db.session import SessionLocal
from app.schemas.api_tokens import ApiTokenCreateInput, ApiTokenCreateResult, ApiTokenSummary


@dataclass(frozen=True)
class ApiTokenPrincipal:
    token_id: int
    user_id: int
    user_email: str


class ApiTokenService:
    HASH_NAME = "sha256"

    def __init__(self, session_factory: Callable[[], Session] | None = None) -> None:
        self.session_factory = session_factory or SessionLocal

    def create_token(self, *, user_id: int, name: str) -> ApiTokenCreateResult:
        try:
            payload = ApiTokenCreateInput(name=name)
        except ValidationError as exc:
            raise InputValidationError(str(exc.errors()[0]["msg"])) from exc

        raw_token, identifier, token_prefix = self._generate_token_material()
        current_time = self._utcnow()
        with self.session_factory() as db:
            user = self._require_user(db, user_id)
            token = ApiToken(
                user_id=user.id,
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
            return ApiTokenCreateResult(
                token=raw_token,
                token_item=self._to_summary(token),
            )

    def list_tokens(self, *, user_id: int) -> list[ApiTokenSummary]:
        with self.session_factory() as db:
            self._require_user(db, user_id)
            tokens = db.scalars(
                select(ApiToken)
                .where(ApiToken.user_id == user_id)
                .order_by(ApiToken.created_at.desc(), ApiToken.id.desc())
            ).all()
            return [self._to_summary(item) for item in tokens]

    def set_token_active_state(self, *, user_id: int, token_id: int, is_active: bool) -> ApiTokenSummary:
        with self.session_factory() as db:
            self._require_user(db, user_id)
            token = db.get(ApiToken, token_id)
            if token is None or token.user_id != user_id:
                raise AuthorizationError("Voce nao tem acesso a este token.")
            token.is_active = is_active
            token.updated_at = self._utcnow()
            db.commit()
            db.refresh(token)
            return self._to_summary(token)

    def authenticate_token(self, raw_token: str) -> ApiTokenPrincipal:
        identifier = self._extract_identifier(raw_token)
        if not identifier:
            raise AuthenticationError("Token invalido.")

        with self.session_factory() as db:
            token = db.scalar(
                select(ApiToken)
                .join(User, ApiToken.user_id == User.id)
                .where(
                    ApiToken.token_identifier == identifier,
                    ApiToken.is_active.is_(True),
                    User.is_active.is_(True),
                )
            )
            if token is None or not hmac.compare_digest(token.token_hash, self._hash_token(raw_token)):
                raise AuthenticationError("Token invalido.")

            token.last_used_at = self._utcnow()
            token.updated_at = token.last_used_at
            db.commit()
            db.refresh(token)
            return ApiTokenPrincipal(
                token_id=token.id,
                user_id=token.user_id,
                user_email=token.user.email,
            )

    @staticmethod
    def _generate_token_material() -> tuple[str, str, str]:
        identifier = secrets.token_hex(8)
        secret = secrets.token_urlsafe(24)
        raw_token = f"dsc_{identifier}_{secret}"
        return raw_token, identifier, f"dsc_{identifier}"

    @staticmethod
    def _extract_identifier(raw_token: str) -> str | None:
        parts = raw_token.strip().split("_", 2)
        if len(parts) != 3 or parts[0] != "dsc":
            return None
        return parts[1] or None

    @classmethod
    def _hash_token(cls, raw_token: str) -> str:
        return hashlib.new(cls.HASH_NAME, raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _require_user(db: Session, user_id: int) -> User:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            raise AuthorizationError("Usuario nao autenticado ou inativo.")
        return user

    @staticmethod
    def _to_summary(token: ApiToken) -> ApiTokenSummary:
        return ApiTokenSummary(
            id=token.id,
            name=token.name,
            token_prefix=token.token_prefix,
            is_active=token.is_active,
            last_used_at=token.last_used_at,
            created_at=token.created_at,
        )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
