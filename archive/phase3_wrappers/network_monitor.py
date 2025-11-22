#!/usr/bin/env python3
"""
DEPRECATED: network_monitor.py (root) - Thin Wrapper for Backward Compatibility

This file is deprecated and maintained only for backward compatibility.

MIGRATION GUIDE:
  Old: from network_monitor import NetworkMonitor
  New: from src.capture.network_monitor import NetworkMonitor

The actual implementation is in: src/capture/network_monitor.py

This wrapper will be removed in a future version.
Please update your imports to use the src/ module directly.
"""

import warnings

# Show deprecation warning once
warnings.warn(
    "network_monitor.py (root) is deprecated. "
    "Use 'from src.capture.network_monitor import NetworkMonitor' instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export everything from the src module
from src.capture.network_monitor import *

# Explicitly import and re-export main symbols for clarity
from src.capture.network_monitor import (
    NetworkMonitor,
)

__all__ = [
    'NetworkMonitor',
]
