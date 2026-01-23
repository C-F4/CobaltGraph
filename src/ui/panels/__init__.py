"""
Panels Module
=============

UI panel components for CobaltGraph's 4-panel dashboard layout.

CobaltGraph uses a consistent 4-panel grid layout:

    ┌─────────────────┬─────────────────┐
    │  Threat Posture │   Intel Map     │
    │   (top-left)    │  (top-right)    │
    ├─────────────────┼─────────────────┤
    │ Connection Table│ Network Devices │
    │ (bottom-left)   │ (bottom-right)  │
    └─────────────────┴─────────────────┘

Each panel is a self-contained Textual widget that can be updated
independently with reactive data binding.

Panel Types:
    - ThreatPosturePanel: Current threat level and top threats
    - IntelMapPanel: Geographic threat visualization (uses maps module)
    - ConnectionTablePanel: Recent connections with threat scores
    - NetworkDevicesPanel: Discovered devices and their flows

Modal Panels (overlays):
    - ConnectionDetailModal: Detailed connection analysis
    - InvestigationPanel: Investigation workflow
"""

import logging

logger = logging.getLogger(__name__)

# Core 4-panel components
try:
    from .threat_posture import ThreatPosturePanel
except ImportError as e:
    logger.debug(f"ThreatPosturePanel unavailable: {e}")
    ThreatPosturePanel = None

try:
    from .intel_map import IntelMapPanel
except ImportError as e:
    logger.debug(f"IntelMapPanel unavailable: {e}")
    IntelMapPanel = None

try:
    from .connection_table import ConnectionTablePanel
except ImportError as e:
    logger.debug(f"ConnectionTablePanel unavailable: {e}")
    ConnectionTablePanel = None

try:
    from .network_devices import NetworkDevicesPanel
except ImportError as e:
    logger.debug(f"NetworkDevicesPanel unavailable: {e}")
    NetworkDevicesPanel = None

# Modal components
try:
    from .modals import ConnectionDetailModal
except ImportError as e:
    logger.debug(f"ConnectionDetailModal unavailable: {e}")
    ConnectionDetailModal = None


__all__ = [
    'ThreatPosturePanel',
    'IntelMapPanel',
    'ConnectionTablePanel',
    'NetworkDevicesPanel',
    'ConnectionDetailModal',
]
