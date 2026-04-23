class DomainSecurityError(Exception):
    """Base exception for the application."""


class InputValidationError(DomainSecurityError, ValueError):
    """Raised when the submitted domain or email is invalid."""


class DNSLookupError(DomainSecurityError):
    """Base exception for DNS lookup failures."""


class DNSDomainNotFoundError(DNSLookupError):
    """Raised when the requested domain does not exist in DNS."""


class DNSTimeoutError(DNSLookupError):
    """Raised when a DNS query exceeds the configured timeout."""


class DNSNoResponseError(DNSLookupError):
    """Raised when DNS servers do not return a usable answer."""


class ResourceConflictError(DomainSecurityError):
    """Raised when the requested resource conflicts with existing data."""


class AuthenticationError(DomainSecurityError):
    """Raised when user authentication fails."""


class AuthorizationError(DomainSecurityError):
    """Raised when access to a protected resource is denied."""


class FeatureUnavailableError(DomainSecurityError):
    """Raised when an optional feature is not available in the current environment."""


class SubscriptionRequiredError(DomainSecurityError):
    """Raised when a premium subscription is required to access the resource."""
