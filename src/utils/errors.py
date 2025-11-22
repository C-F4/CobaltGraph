#!/usr/bin/env python3
"""
CobaltGraph Custom Exception Classes

Defines a hierarchy of custom exceptions for better error handling
and categorization throughout the CobaltGraph system.
"""


class CobaltGraphError(Exception):
    """
    Base exception for all CobaltGraph-related errors.

    All custom CobaltGraph exceptions should inherit from this class.
    This allows catching all CobaltGraph-specific errors with a single except clause.
    """

    def __init__(self, message: str, details: dict = None):
        """
        Initialize CobaltGraph error.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional error context
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self):
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


class ConfigurationError(CobaltGraphError):
    """
    Configuration-related errors.

    Raised when:
    - Configuration file is missing or unreadable
    - Configuration values are invalid
    - Required configuration keys are missing
    - Configuration validation fails
    """
    pass


class DatabaseError(CobaltGraphError):
    """
    Database-related errors.

    Raised when:
    - Database connection fails
    - SQL query errors
    - Transaction failures
    - Database migration issues
    - Integrity constraint violations
    """
    pass


class CaptureError(CobaltGraphError):
    """
    Network capture-related errors.

    Raised when:
    - Insufficient permissions (not root)
    - Network interface not found
    - Raw socket creation fails
    - Packet parsing errors
    - Capture buffer overflows
    """
    pass


class IntegrationError(CobaltGraphError):
    """
    Third-party integration errors.

    Raised when:
    - External API calls fail
    - API rate limits exceeded
    - Authentication failures
    - Timeout errors
    - Invalid API responses
    """
    pass


class DashboardError(CobaltGraphError):
    """
    Dashboard/UI-related errors.

    Raised when:
    - Web server fails to start
    - Port already in use
    - Static files not found
    - Template rendering errors
    - Request/response processing fails
    """
    pass


class GeolocationError(CobaltGraphError):
    """
    Geolocation service errors.

    Raised when:
    - GeoIP database not found
    - IP lookup fails
    - Invalid IP address format
    - Database corruption
    """
    pass


class SupervisorError(CobaltGraphError):
    """
    Supervisor/watchdog errors.

    Raised when:
    - Process monitoring fails
    - Auto-restart logic errors
    - Health check failures
    - Resource limit violations
    """
    pass


# Convenience function for creating errors with context
def create_error(error_class, message, **details):
    """
    Create an error with additional context.

    Args:
        error_class: Exception class to instantiate
        message: Error message
        **details: Additional context as keyword arguments

    Returns:
        Instance of error_class

    Example:
        raise create_error(
            DatabaseError,
            "Failed to connect to database",
            host="localhost",
            port=5432,
            database="cobaltgraph"
        )
    """
    return error_class(message, details=details)
