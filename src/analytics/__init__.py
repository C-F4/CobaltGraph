"""
CobaltGraph Analytics Engine
Advanced threat intelligence and detection

Provides:
- Statistical anomaly detection (scipy)
- Connection graph topology analysis (networkx)
- Time-series aggregation and patterns
- C2 beaconing detection
- TCP connection state analysis
- JA3 TLS fingerprinting
"""

from .threat_analytics import ThreatAnalytics, ConnectionGraph, AnomalyDetector
from .aggregator import MetadataAggregator, ThreatTimeSeries
from .beaconing_detector import BeaconingDetector, BeaconingResult
from .connection_state import ConnectionStateTracker, ConnectionMetrics
from .ja3_fingerprint import JA3Calculator, JA3Result

__all__ = [
    "ThreatAnalytics",
    "ConnectionGraph",
    "AnomalyDetector",
    "MetadataAggregator",
    "ThreatTimeSeries",
    # Phase 4 analytics
    "BeaconingDetector",
    "BeaconingResult",
    "ConnectionStateTracker",
    "ConnectionMetrics",
    "JA3Calculator",
    "JA3Result",
]
