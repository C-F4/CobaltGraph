#!/usr/bin/env python3
"""
DEPRECATED: ip_reputation.py (root) - Thin Wrapper for Backward Compatibility

This file is deprecated and maintained only for backward compatibility.

MIGRATION GUIDE:
  Old: from ip_reputation import IPReputationManager
  New: from src.intelligence.ip_reputation import IPReputationManager

The actual implementation is in: src/intelligence/ip_reputation.py

This wrapper will be removed in a future version.
Please update your imports to use the src/ module directly.
"""

import warnings

# Show deprecation warning once
warnings.warn(
    "ip_reputation.py (root) is deprecated. "
    "Use 'from src.intelligence.ip_reputation import IPReputationManager' instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export everything from the src module
from src.intelligence.ip_reputation import *

# Explicitly import and re-export main symbols for clarity
from src.intelligence.ip_reputation import (
    IPReputationManager,
    VirusTotalClient,
    AbuseIPDBClient,
    RateLimiter,
    IPReputationCache,
    create_reputation_manager,
)

__all__ = [
    'IPReputationManager',
    'VirusTotalClient',
    'AbuseIPDBClient',
    'RateLimiter',
    'IPReputationCache',
    'create_reputation_manager',
]
