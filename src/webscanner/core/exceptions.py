"""Custom exception hierarchy for the web scanner."""


class ScannerError(Exception):
    """Base exception for all scanner errors."""


class ScopeValidationError(ScannerError):
    """Raised when scope configuration is invalid."""


class ScopeViolationError(ScannerError):
    """Raised when a target is outside the authorized scope."""


class NetworkError(ScannerError):
    """Raised when a network operation fails."""


class ScanAbortedError(ScannerError):
    """Raised when a scan is aborted due to safety checks."""


class ReportGenerationError(ScannerError):
    """Raised when report generation fails."""
