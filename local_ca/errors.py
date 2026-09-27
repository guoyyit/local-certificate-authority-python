"""Typed errors raised by the CA service."""


class CAError(Exception):
    """Base error for all CA failures."""


class NotFoundError(CAError):
    """Requested resource does not exist."""


class ConflictError(CAError):
    """Request conflicts with existing state (duplicate or invalid transition)."""


class PermissionDeniedError(CAError):
    """Actor is not allowed to perform the operation."""


class ValidationError(CAError):
    """Preconditions for the operation are not met."""
