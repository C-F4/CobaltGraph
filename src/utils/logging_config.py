#!/usr/bin/env python3
"""
CobaltGraph Logging Configuration

Provides centralized logging configuration for all CobaltGraph components.
Supports both console and file logging with rotating log files.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

# Default log format
DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DETAILED_FORMAT = "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds color to log messages in terminal output.

    Only applies colors when outputting to a TTY.
    """

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[0;36m",  # Cyan
        "INFO": "\033[0;32m",  # Green
        "WARNING": "\033[1;33m",  # Yellow
        "ERROR": "\033[0;31m",  # Red
        "CRITICAL": "\033[1;31m",  # Bold Red
    }
    RESET = "\033[0m"

    def __init__(self, fmt=None, datefmt=None, use_color=True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

    def format(self, record):
        if self.use_color and record.levelname in self.COLORS:
            # Save original levelname
            levelname_orig = record.levelname

            # Color the level name
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"

            # Format the message
            result = super().format(record)

            # Restore original levelname
            record.levelname = levelname_orig

            return result
        else:
            return super().format(record)


def setup_logging(
    log_level: int = logging.INFO,
    log_file: Optional[str] = None,
    log_dir: str = "logs",
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    console_level: Optional[int] = None,
    file_level: Optional[int] = None,
    use_color: bool = True,
    detailed_file_logs: bool = True,
) -> None:
    """
    Configure comprehensive logging for CobaltGraph.

    Args:
        log_level: Default log level (applies to both console and file if not overridden)
        log_file: Name of log file (default: cobaltgraph.log in log_dir)
        log_dir: Directory for log files (created if doesn't exist)
        max_bytes: Maximum size of each log file before rotation
        backup_count: Number of backup log files to keep
        console_level: Console log level (overrides log_level for console)
        file_level: File log level (overrides log_level for file)
        use_color: Whether to use colored output in console
        detailed_file_logs: Whether to include file/line numbers in file logs

    Example:
        >>> from src.utils.logging_config import setup_logging
        >>> setup_logging(
        ...     log_level=logging.INFO,
        ...     log_file='cobaltgraph.log',
        ...     use_color=True
        ... )
    """

    # Create logs directory if it doesn't exist
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Determine log file path
    if log_file is None:
        log_file = log_path / "cobaltgraph.log"
    else:
        log_file = log_path / log_file

    # Set levels
    if console_level is None:
        console_level = log_level
    if file_level is None:
        file_level = logging.DEBUG  # Always log DEBUG to file

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture everything, handlers will filter

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler (with color)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(console_level)
    console_formatter = ColoredFormatter(fmt=DEFAULT_FORMAT, use_color=use_color)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler (rotating, with detailed format)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file), maxBytes=max_bytes, backupCount=backup_count
        )
        file_handler.setLevel(file_level)

        if detailed_file_logs:
            file_formatter = logging.Formatter(DETAILED_FORMAT)
        else:
            file_formatter = logging.Formatter(DEFAULT_FORMAT)

        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    except Exception as e:
        # If file logging fails, log to console only
        root_logger.warning("Failed to setup file logging: %s", e)
        root_logger.warning("Continuing with console logging only")

    # Log the logging configuration
    root_logger.debug(
        f"Logging configured: console={logging.getLevelName(console_level)}, "
        f"file={logging.getLevelName(file_level)} → {log_file}"
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        name: Logger name (typically __name__)

    Returns:
        logging.Logger: Configured logger instance

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("This is an info message")
    """
    return logging.getLogger(name)


def silence_noisy_loggers():
    """
    Silence overly verbose third-party loggers.

    Call this after setup_logging() to reduce noise from dependencies.
    """
    # Common noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # Flask
    logging.getLogger("scapy").setLevel(logging.ERROR)


# Convenience function for quick setup
def quick_setup(verbose: bool = False, debug: bool = False):
    """
    Quick logging setup with sensible defaults.

    Args:
        verbose: If True, set console to DEBUG level
        debug: If True, enable debug mode (detailed file logs)

    Example:
        >>> from src.utils.logging_config import quick_setup
        >>> quick_setup(verbose=True)
    """
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    setup_logging(log_level=log_level, use_color=True, detailed_file_logs=debug)

    if not verbose:
        silence_noisy_loggers()


# ============================================================================
# UI EVENT LOGGER
# ============================================================================

class UIEventHandler(logging.Handler):
    """
    Custom logging handler that sends events to the UI.

    This allows log messages to be displayed in the dashboard's event log
    while still going to file/console via normal logging.
    """

    # Class-level callback registry
    _callbacks = []

    def __init__(self, min_level: int = logging.WARNING):
        super().__init__(min_level)
        self.setFormatter(logging.Formatter("%(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord):
        """Send log record to all registered callbacks"""
        try:
            # Map logging levels to UI severity
            level_map = {
                logging.CRITICAL: "CRITICAL",
                logging.ERROR: "HIGH",
                logging.WARNING: "MEDIUM",
                logging.INFO: "LOW",
                logging.DEBUG: "INFO",
            }
            severity = level_map.get(record.levelno, "INFO")

            # Create event dict
            event = {
                'timestamp': record.created,
                'type': record.name.split('.')[-1].upper()[:8],
                'message': self.format(record),
                'severity': severity,
                'metadata': {
                    'logger': record.name,
                    'level': record.levelname,
                    'filename': record.filename,
                    'lineno': record.lineno,
                }
            }

            # Send to all registered callbacks
            for callback in UIEventHandler._callbacks:
                try:
                    callback(event)
                except Exception:
                    pass  # Don't let callback errors break logging

        except Exception:
            pass  # Never let handler errors break logging

    @classmethod
    def register_callback(cls, callback):
        """Register a callback to receive UI events"""
        if callback not in cls._callbacks:
            cls._callbacks.append(callback)

    @classmethod
    def unregister_callback(cls, callback):
        """Unregister a callback"""
        if callback in cls._callbacks:
            cls._callbacks.remove(callback)

    @classmethod
    def clear_callbacks(cls):
        """Clear all registered callbacks"""
        cls._callbacks.clear()


def setup_ui_logging(min_level: int = logging.WARNING):
    """
    Enable UI event logging.

    Call this after setup_logging() to add UI event handler.
    Register callbacks with UIEventHandler.register_callback().

    Args:
        min_level: Minimum level to send to UI (default WARNING)

    Example:
        >>> setup_ui_logging(logging.INFO)
        >>> UIEventHandler.register_callback(my_dashboard.add_event)
    """
    root_logger = logging.getLogger()

    # Check if handler already exists
    for handler in root_logger.handlers:
        if isinstance(handler, UIEventHandler):
            return  # Already configured

    # Add UI handler
    ui_handler = UIEventHandler(min_level)
    root_logger.addHandler(ui_handler)

    root_logger.debug("UI event logging enabled at %s level",
                     logging.getLevelName(min_level))


# Direct event posting for non-logging events
class UIEventPoster:
    """
    Direct event poster for UI events that don't go through Python logging.

    Use this for connection events, alerts, and other real-time updates.
    """

    @staticmethod
    def post(event_type: str, message: str, severity: str = "INFO",
             metadata: Optional[dict] = None):
        """
        Post an event directly to the UI.

        Args:
            event_type: Short event type (max 8 chars displayed)
            message: Event message
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
            metadata: Optional additional data
        """
        import time

        event = {
            'timestamp': time.time(),
            'type': event_type[:8],
            'message': message,
            'severity': severity,
            'metadata': metadata or {},
        }

        for callback in UIEventHandler._callbacks:
            try:
                callback(event)
            except Exception:
                pass

    @staticmethod
    def connection_event(dst_ip: str, dst_port: int, threat_score: float,
                        org: str = "", country: str = ""):
        """Post a connection event"""
        severity = "INFO"
        if threat_score >= 0.8:
            severity = "CRITICAL"
        elif threat_score >= 0.6:
            severity = "HIGH"
        elif threat_score >= 0.4:
            severity = "MEDIUM"
        elif threat_score >= 0.2:
            severity = "LOW"

        message = f"{dst_ip}:{dst_port}"
        if org:
            message += f" ({org})"
        if country:
            message += f" [{country}]"

        UIEventPoster.post("CONN", message, severity, {
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'threat_score': threat_score,
            'org': org,
            'country': country,
        })

    @staticmethod
    def alert(message: str, severity: str = "HIGH"):
        """Post an alert event"""
        UIEventPoster.post("ALERT", message, severity)

    @staticmethod
    def system(message: str, severity: str = "INFO"):
        """Post a system event"""
        UIEventPoster.post("SYSTEM", message, severity)
