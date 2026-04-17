from fastapi import status

from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    DNSDomainNotFoundError,
    DNSNoResponseError,
    DNSTimeoutError,
    DomainSecurityError,
    InputValidationError,
    ResourceConflictError,
)


def get_http_status_code(exc: DomainSecurityError) -> int:
    if isinstance(exc, InputValidationError):
        return status.HTTP_422_UNPROCESSABLE_ENTITY
    if isinstance(exc, AuthenticationError):
        return status.HTTP_401_UNAUTHORIZED
    if isinstance(exc, AuthorizationError):
        return status.HTTP_403_FORBIDDEN
    if isinstance(exc, ResourceConflictError):
        return status.HTTP_409_CONFLICT
    if isinstance(exc, DNSDomainNotFoundError):
        return status.HTTP_404_NOT_FOUND
    if isinstance(exc, DNSTimeoutError):
        return status.HTTP_504_GATEWAY_TIMEOUT
    if isinstance(exc, DNSNoResponseError):
        return status.HTTP_502_BAD_GATEWAY
    return status.HTTP_500_INTERNAL_SERVER_ERROR
