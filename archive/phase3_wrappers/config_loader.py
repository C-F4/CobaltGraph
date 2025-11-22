#!/usr/bin/env python3
"""
DEPRECATED: config_loader.py (root) - Thin Wrapper for Backward Compatibility

This file is deprecated and maintained only for backward compatibility.

MIGRATION GUIDE:
  Old: from config_loader import load_config
  New: from src.core.config import load_config

The actual implementation is in: src/core/config.py

This wrapper will be removed in a future version.
Please update your imports to use the src/ module directly.
"""

import warnings

# Show deprecation warning once
warnings.warn(
    "config_loader.py (root) is deprecated. "
    "Use 'from src.core.config import load_config' instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export everything from the src module
from src.core.config import *

# Explicitly import and re-export main symbols for clarity
from src.core.config import (
    load_config,
    ConfigLoader,
    Colors,
)

__all__ = [
    'load_config',
    'ConfigLoader',
    'Colors',
]
