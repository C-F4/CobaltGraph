"""
Pipeline Stages

Only the stages the live pipeline uses remain here. ConnectionCorrelator turns
bidirectional packets into connection events; DataPipeline (core/orchestrator.py)
performs validation, enrichment, scoring, analytics and storage.
"""

from .base import PipelineStage, StageContext, CompositeStage
from .correlator import ConnectionCorrelator

__all__ = [
    "PipelineStage",
    "StageContext",
    "CompositeStage",
    "ConnectionCorrelator",
]
