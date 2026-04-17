from collections.abc import Callable
from datetime import UTC, datetime
import hashlib
import hmac
import secrets

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import Response

from app.core.auth_session import SESSION_COOKIE_NAME, decode_session_cookie, encode_session_cookie
from app.core.config import settings
from app.core.exceptions import AuthenticationError, AuthorizationError, InputValidationError, ResourceConflictError
from app.db.models import NotificationPreference, User
from app.db.session import SessionLocal
from app.schemas.auth import UserLoginInput, UserRegistrationInput, UserSession


class AuthenticationService:
    """Handles user registration, authentication and session state."""

    HASH_NAME = "sha256"
    ITERATIONS = 150_000

    def __init__(self, session_factory: Callable[[], Session] | None = None) -> None:
        self.session_factory = session_factory or SessionLocal

    def register_user(self, email: str, password: str) -> UserSession:
        try:
            payload = UserRegistrationInput(email=email, password=password)
        except ValidationError as exc:
            raise InputValidationError(str(exc.errors()[0]["msg"])) from exc
        with self.session_factory() as db:
            existing = self._get_user_by_email(db, payload.email)
            if existing is not None:
                raise ResourceConflictError("Ja existe um usuario cadastrado com este e-mail.")

            user = User(
                email=payload.email,
                password_hash=self._hash_password(payload.password),
                is_active=True,
                created_at=self._utcnow(),
                updated_at=self._utcnow(),
            )
            db.add(user)
            db.flush()
            db.add(NotificationPreference(user_id=user.id, email_alerts_enabled=True))
            db.commit()
            db.refresh(user)
            return self._to_user_session(user)

    def authenticate(self, email: str, password: str) -> UserSession:
        try:
            payload = UserLoginInput(email=email, password=password)
        except ValidationError as exc:
            raise InputValidationError(str(exc.errors()[0]["msg"])) from exc
        with self.session_factory() as db:
            user = self._get_user_by_email(db, payload.email)
            if user is None or not self._verify_password(payload.password, user.password_hash):
                raise AuthenticationError("Credenciais invalidas.")
            if not user.is_active:
                raise AuthorizationError("A conta do usuario esta inativa.")
            return self._to_user_session(user)

    def get_user_session(self, request: Request) -> UserSession | None:
        session_payload = getattr(request.state, "auth_session", None)
        if session_payload is None:
            session_payload = decode_session_cookie(
                request.cookies.get(SESSION_COOKIE_NAME, ""),
                settings.session_secret,
            ) or {}
        user_id = session_payload.get("user_id")
        if not user_id:
            return None
        with self.session_factory() as db:
            user = db.get(User, int(user_id))
            if user is None or not user.is_active:
                return None
            return self._to_user_session(user)

    def require_user_session(self, request: Request) -> UserSession:
        user = self.get_user_session(request)
        if user is None:
            raise AuthorizationError("Esta area exige autenticacao.")
        return user

    def apply_login(self, response: Response, user: UserSession) -> None:
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=encode_session_cookie({"user_id": user.id, "email": user.email}, settings.session_secret),
            max_age=settings.session_max_age_seconds,
            httponly=True,
            samesite="lax",
        )

    @staticmethod
    def clear_login(response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE_NAME)

    @staticmethod
    def _hash_password(password: str) -> str:
        AuthenticationService._validate_password(password)
        salt = secrets.token_hex(16)
        derived_key = hashlib.pbkdf2_hmac(
            AuthenticationService.HASH_NAME,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            AuthenticationService.ITERATIONS,
        )
        return (
            f"pbkdf2_{AuthenticationService.HASH_NAME}$"
            f"{AuthenticationService.ITERATIONS}$"
            f"{salt}$"
            f"{derived_key.hex()}"
        )

    @staticmethod
    def _verify_password(password: str, encoded_hash: str) -> bool:
        try:
            algorithm, iterations_text, salt, stored_hash = encoded_hash.split("$", 3)
        except ValueError:
            return False

        if not algorithm.startswith("pbkdf2_"):
            return False

        try:
            iterations = int(iterations_text)
        except ValueError:
            return False

        digest_name = algorithm.removeprefix("pbkdf2_")
        candidate = hashlib.pbkdf2_hmac(
            digest_name,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
        return hmac.compare_digest(candidate, stored_hash)

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 8:
            raise InputValidationError("A senha deve ter pelo menos 8 caracteres.")

    @staticmethod
    def _get_user_by_email(db: Session, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        return db.scalar(stmt)

    @staticmethod
    def _to_user_session(user: User) -> UserSession:
        return UserSession(
            id=user.id,
            email=user.email,
            is_active=user.is_active,
            created_at=user.created_at,
        )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(tz=UTC)
