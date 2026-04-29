from __future__ import annotations


class KCashError(Exception):
    """Base exception for all kcrash-agent errors."""

    def __init__(self, message: str, code: str = "", details: dict | None = None) -> None:
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class VMCoreError(KCashError):
    """Errors related to vmcore reading or parsing."""

    def __init__(self, message: str, vmcore_path: str = "", **kwargs) -> None:
        super().__init__(message, details={"vmcore_path": vmcore_path, **kwargs})


class VMCoreNotFoundError(VMCoreError):
    """vmcore file does not exist."""

    pass


class VMCoreCorruptedError(VMCoreError):
    """vmcore file is corrupted or unreadable."""

    pass


class DrgnError(VMCoreError):
    """drgn library failed to process vmcore."""

    pass


class LLMError(KCashError):
    """Base for LLM-related errors."""

    def __init__(
        self, message: str, model: str = "", retry_count: int = 0, **kwargs
    ) -> None:
        super().__init__(
            message, details={"model": model, "retry_count": retry_count, **kwargs}
        )


class LLMTimeoutError(LLMError):
    """LLM call timed out."""

    pass


class LLMRateLimitError(LLMError):
    """LLM rate limit exceeded."""

    pass


class LLMAuthError(LLMError):
    """LLM API authentication failed."""

    pass


class LLMResponseParseError(LLMError):
    """Failed to parse LLM response."""

    pass


class AnalysisError(KCashError):
    """Errors during analysis pipeline execution."""

    def __init__(
        self, message: str, stage: str = "", crash_id: str = "", **kwargs
    ) -> None:
        super().__init__(
            message, details={"stage": stage, "crash_id": crash_id, **kwargs}
        )


class PatchError(KCashError):
    """Errors during patch generation or validation."""

    pass


class PatchGenerationError(PatchError):
    """Failed to generate patch code."""

    pass


class PatchValidationError(PatchError):
    """Patch code failed validation."""

    pass


class CacheError(KCashError):
    """Cache-related errors."""

    pass


class ConfigError(KCashError):
    """Configuration errors."""

    pass


class ConfigMissingError(ConfigError):
    """Required configuration value is missing."""

    pass


class NotificationError(KCashError):
    """Notification delivery failed."""

    pass


class DatabaseError(KCashError):
    """Database operation failed."""

    pass


class AuthenticationError(KCashError):
    """API authentication failed."""

    pass


class RateLimitExceededError(KCashError):
    """API rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60) -> None:
        self.retry_after = retry_after
        super().__init__(message, details={"retry_after": retry_after})
