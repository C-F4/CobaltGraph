"""
CobaltGraph Reconnaissance UI Module

Comprehensive passive reconnaissance visualization for device and network modes.

Modules:
- device_state: Device state machine and tracking engine
- discovery: Device discovery and inventory panels
- details: Device detail drill-down views
- timeline: Threat and activity timeline visualizations
- fingerprint: Passive fingerprinting and OS detection panels
- correlation: Device-to-device relationship analysis
- topology: Network topology and flow visualization
- unified: Unified reconnaissance dashboard
"""

from src.ui.reconnaissance.device_state import (
    DeviceState,
    DeviceRole,
    DeviceReconRecord,
    PassiveFingerprint,
    ConnectionMetrics,
    DeviceReconnaissanceEngine,
)

from src.ui.reconnaissance.discovery import DeviceDiscoveryPanel
from src.ui.reconnaissance.details import DeviceDetailPanel
from src.ui.reconnaissance.timeline import (
    DeviceThreatTimelinePanel,
    ActivityPatternPanel,
    AnomalyTimelinePanel,
)
from src.ui.reconnaissance.fingerprint import PassiveFingerprintPanel
from src.ui.reconnaissance.correlation import DeviceCorrelationPanel
from src.ui.reconnaissance.topology import (
    NetworkTopologyPanel,
    InteractiveTopologyPanel,
    TopologyHeatmapPanel,
)

__all__ = [
    "DeviceState",
    "DeviceRole",
    "DeviceReconRecord",
    "PassiveFingerprint",
    "ConnectionMetrics",
    "DeviceReconnaissanceEngine",
    "DeviceDiscoveryPanel",
    "DeviceDetailPanel",
    "DeviceThreatTimelinePanel",
    "ActivityPatternPanel",
    "AnomalyTimelinePanel",
    "PassiveFingerprintPanel",
    "DeviceCorrelationPanel",
    "NetworkTopologyPanel",
    "InteractiveTopologyPanel",
    "TopologyHeatmapPanel",
]
