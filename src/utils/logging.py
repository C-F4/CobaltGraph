"""
CobaltGraph Logging Utilities
Centralized logging configuration

Features:
- Colored console output
- File logging with rotation
- Log level configuration
- Module-specific loggers
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

# ANSI color codes
COLORS = {
    'DEBUG': '\033[0;36m',    # Cyan
    'INFO': '\033[0;32m',     # Green
    'WARNING': '\033[1;33m',  # Yellow
    'ERROR': '\033[0;31m',    # Red
    'CRITICAL': '\033[1;31m', # Bold Red
    'RESET': '\033[0m',       # Reset
}

class ColoredFormatter(logging.Formatter):
    """Formatter that adds color to console output"""

    def format(self, record):
        # Add color to level name
        levelname = record.levelname
        if levelname in COLORS:
            record.levelname = f"{COLORS[levelname]}{levelname}{COLORS['RESET']}"

        return super().format(record)


def setup_logging(
    log_level: str = 'INFO',
    log_file: str = None,
    console: bool = True
):
    """
    Setup logging configuration for CobaltGraph

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Path to log file (None = no file logging)
        console: Enable console output
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers = []

    # Console handler with colors
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_formatter = ColoredFormatter(
            '[%(asctime)s] %(levelname)s :: %(name)s :: %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handler with rotation
    if log_file:
        # Create logs directory
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10_000_000,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s :: %(name)s :: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module

    Args:
        name: Module name (e.g., 'cobaltgraph.capture')

    Returns:
        logging.Logger instance
    """
    return logging.getLogger(name)
