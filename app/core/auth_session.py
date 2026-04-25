import base64
import hashlib
import hmac
import json

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


SESSION_COOKIE_NAME = "dsc_session"


def encode_session_cookie(payload: dict, secret: str) -> str:
    raw_payload = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(raw_payload).decode("ascii").rstrip("=")
    signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{encoded_payload}.{signature}"


def decode_session_cookie(value: str, secret: str) -> dict | None:
    try:
        encoded_payload, signature = value.split(".", 1)
    except ValueError:
        return None
    expected_signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None
    padding = "=" * (-len(encoded_payload) % 4)
    try:
        raw_payload = base64.urlsafe_b64decode(encoded_payload + padding)
        payload = json.loads(raw_payload.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


class AuthSessionMiddleware(BaseHTTPMiddleware):
    """Loads the signed authentication cookie into request.state."""

    def __init__(self, app, *, secret: str) -> None:
        super().__init__(app)
        self.secret = secret

    async def dispatch(self, request: Request, call_next) -> Response:
        payload = decode_session_cookie(request.cookies.get(SESSION_COOKIE_NAME, ""), self.secret) or {}
        request.state.auth_session = payload
        request.state.user_email = payload.get("email")
        request.state.user_id = payload.get("user_id")
        request.state.user_role = payload.get("role", "client")
        return await call_next(request)
