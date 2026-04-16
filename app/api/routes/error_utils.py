from fastapi import status

from app.core.exceptions import (
    DNSDomainNotFoundError,
    DNSNoResponseError,
    DNSTimeoutError,
    DomainSecurityError,
    InputValidationError,
)


def get_http_status_code(exc: DomainSecurityError) -> int:
    if isinstance(exc, InputValidationError):
        return status.HTTP_422_UNPROCESSABLE_ENTITY
    if isinstance(exc, DNSDomainNotFoundError):
        return status.HTTP_404_NOT_FOUND
    if isinstance(exc, DNSTimeoutError):
        return status.HTTP_504_GATEWAY_TIMEOUT
    if isinstance(exc, DNSNoResponseError):
        return status.HTTP_502_BAD_GATEWAY
    return status.HTTP_500_INTERNAL_SERVER_ERROR
