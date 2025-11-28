#!/usr/bin/env python3
"""
CobaltGraph Base Dashboard Compatibility Module

Provides DeviceDashboardBase and NetworkDashboardBase classes
for backward compatibility with existing device_dashboard.py and network_dashboard.py.

These are subclasses of BaseReconnaissanceDashboard that provide the
foundation for mode-specific dashboard implementations.
"""

import logging
from typing import Optional

from src.ui.base_reconnaissance_dashboard import BaseReconnaissanceDashboard

logger = logging.getLogger(__name__)


class DeviceDashboardBase(BaseReconnaissanceDashboard):
    """
    Base class for Device Mode Dashboard

    Device mode focuses on a single machine's outbound connections:
    - Personal security perspective ("What am I connecting to?")
    - No MAC/vendor columns (single device)
    - Full enrichment data visible
    - Organization/ASN analysis prominent
    - Temporal patterns and anomaly detection
    """

    def __init__(self, **kwargs):
        """Initialize Device Dashboard Base"""
        super().__init__(mode="device", **kwargs)


class NetworkDashboardBase(BaseReconnaissanceDashboard):
    """
    Base class for Network Mode Dashboard

    Network mode focuses on segment-wide visibility:
    - Network administration perspective ("What's on my network?")
    - Multi-device discovery and tracking
    - Device state machine (active/idle/offline)
    - MAC vendor identification
    - Network-wide threat aggregation
    - Topology visualization
    """

    def __init__(self, **kwargs):
        """Initialize Network Dashboard Base"""
        super().__init__(mode="network", **kwargs)
