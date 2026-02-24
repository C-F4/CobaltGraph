"""
CobaltGraph Analytics Engine
Advanced threat intelligence and detection

Provides:
- Statistical anomaly detection (pure Python with optional scipy acceleration)
- Connection graph topology analysis (networkx)
- Time-series aggregation and patterns (pure Python with optional pandas)
- C2 beaconing detection
- TCP connection state analysis
- JA3 TLS fingerprinting
"""

import logging

logger = logging.getLogger(__name__)

# Core analytics (numpy/scipy optional - pure Python fallbacks available)
try:
    from .threat_analytics import ThreatAnalytics, ConnectionGraph, AnomalyDetector
except ImportError as e:
    ThreatAnalytics = None
    ConnectionGraph = None
    AnomalyDetector = None
    logger.warning(f"ThreatAnalytics unavailable: {e}")

try:
    from .aggregator import MetadataAggregator, ThreatTimeSeries
except ImportError as e:
    MetadataAggregator = None
    ThreatTimeSeries = None
    logger.warning(f"MetadataAggregator unavailable: {e}")

# Phase 4 analytics (no numpy/scipy dependency)
try:
    from .beaconing_detector import BeaconingDetector, BeaconingResult
except ImportError as e:
    BeaconingDetector = None
    BeaconingResult = None
    logger.warning(f"BeaconingDetector unavailable: {e}")

try:
    from .connection_state import ConnectionStateTracker, ConnectionMetrics
except ImportError as e:
    ConnectionStateTracker = None
    ConnectionMetrics = None
    logger.warning(f"ConnectionStateTracker unavailable: {e}")

try:
    from .ja3_fingerprint import JA3Calculator, JA3Result
except ImportError as e:
    JA3Calculator = None
    JA3Result = None
    logger.warning(f"JA3Calculator unavailable: {e}")

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
