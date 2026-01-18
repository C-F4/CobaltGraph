"""
CobaltGraph Pipeline Module

Clean, stage-based data processing pipeline for network intelligence.
Replaces the monolithic DataPipeline with modular, testable stages.

Architecture:
    Packet (bidirectional) → ConnectionCorrelator → ValidationStage → EnrichmentStage
                                                  → ScoringStage → AnalyticsStage → StorageStage

Bidirectional Capture:
    - NetworkMonitor emits both outbound AND inbound packets
    - ConnectionCorrelator correlates them into unified connections
    - Response packet TTL enables accurate hop estimation

Each stage:
- Has single responsibility
- Returns StageResult with success/failure
- Can be tested independently
- Reports metrics for monitoring
"""

from .config import PipelineConfig
from .events import (
    ConnectionEvent,
    DeviceEvent,
    StageResult,
    GeoData,
    ASNData,
    ThreatIntelData,
    HopData,
    ConsensusResult,
    AnomalyData,
    ThreatLevel,
    EventType,
    PipelineStats,
)
from .stages import (
    PipelineStage,
    StageContext,
    CompositeStage,
    ConnectionCorrelator,
    ValidationStage,
    EnrichmentStage,
    ScoringStage,
    AnalyticsStage,
    StorageStage,
)

__all__ = [
    # Configuration
    "PipelineConfig",
    # Events
    "ConnectionEvent",
    "DeviceEvent",
    "StageResult",
    "GeoData",
    "ASNData",
    "ThreatIntelData",
    "HopData",
    "ConsensusResult",
    "AnomalyData",
    "ThreatLevel",
    "EventType",
    "PipelineStats",
    # Stages
    "PipelineStage",
    "StageContext",
    "CompositeStage",
    "ConnectionCorrelator",
    "ValidationStage",
    "EnrichmentStage",
    "ScoringStage",
    "AnalyticsStage",
    "StorageStage",
]
