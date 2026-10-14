"""Domain errors mapped to HTTP status codes by the API layer."""

from __future__ import annotations


class RedTeamError(Exception):
    code = "invalid_request"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(RedTeamError):
    code = "not_found"
    status = 404


class ConflictError(RedTeamError):
    code = "conflict"
    status = 409


class InvalidStateError(RedTeamError):
    code = "invalid_state"
    status = 409


class SuiteValidationError(RedTeamError):
    code = "invalid_suite"
    status = 422


class TargetPolicyError(RedTeamError):
    """A target registration violates the egress policy (scheme, host allow list)."""

    code = "target_not_permitted"
    status = 422


class UnauthorizedError(RedTeamError):
    code = "unauthorized"
    status = 401


class ForbiddenError(RedTeamError):
    code = "forbidden"
    status = 403


class AdapterError(RedTeamError):
    """The target could not be invoked or answered outside the wire contract."""

    code = "target_unavailable"
    status = 502

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class DependencyUnavailableError(RedTeamError):
    """A dependency needed for a decision is down; the platform fails closed."""

    code = "temporarily_unavailable"
    status = 503


class ApprovalRequiredError(RedTeamError):
    code = "approval_required"
    status = 403


class CapacityError(RedTeamError):
    code = "capacity_exceeded"
    status = 429
