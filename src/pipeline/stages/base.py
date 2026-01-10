"""
Base Pipeline Stage

Abstract base class for all pipeline stages. Each stage processes
events in a single-responsibility manner.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Generic, Optional, TypeVar
import logging
import time

from ..config import PipelineConfig
from ..events import ConnectionEvent, DeviceEvent, StageResult

logger = logging.getLogger(__name__)

# Type variable for stage input/output
T = TypeVar('T')


@dataclass
class StageContext:
    """
    Shared context passed between stages.

    Contains configuration and shared resources like database
    connections, API clients, etc.
    """
    config: PipelineConfig
    database: Any = None  # Database instance
    geo_lookup: Any = None  # GeoLookup service
    asn_lookup: Any = None  # ASN lookup service
    threat_intel: Any = None  # Threat intel service
    traceroute_service: Any = None  # Traceroute service for hop verification
    consensus_scorer: Any = None  # Consensus scoring engine
    device_enrichment: Any = None  # Device hostname resolution

    # Analytics services
    threat_analytics: Any = None  # ThreatAnalytics engine
    metadata_aggregator: Any = None  # MetadataAggregator for reporting

    # Export
    exporter: Any = None  # Assessment exporter

    # Runtime state
    is_running: bool = True
    debug_mode: bool = False

    # Metrics collection
    metrics: Dict[str, float] = field(default_factory=dict)

    def add_metric(self, stage: str, name: str, value: float):
        """Add a metric for a stage"""
        key = f"{stage}.{name}"
        self.metrics[key] = value


class PipelineStage(ABC, Generic[T]):
    """
    Abstract base class for pipeline stages.

    Each stage:
    - Has a single responsibility
    - Takes an event and returns a StageResult
    - Can be tested independently
    - Reports metrics for monitoring

    Example implementation:
        class ValidationStage(PipelineStage[ConnectionEvent]):
            def process(self, event: ConnectionEvent, context: StageContext) -> StageResult:
                # Validate the event
                if not event.dst_ip:
                    return StageResult(success=False, errors=["Missing dst_ip"])
                return StageResult(success=True, data=event)
    """

    def __init__(self, name: Optional[str] = None):
        """
        Initialize the stage.

        Args:
            name: Stage name for logging/metrics. Defaults to class name.
        """
        self.name = name or self.__class__.__name__
        self.logger = logging.getLogger(f"pipeline.{self.name}")

        # Performance tracking
        self._total_processed = 0
        self._total_errors = 0
        self._total_time_ms = 0.0

    @abstractmethod
    def process(self, event: T, context: StageContext) -> StageResult:
        """
        Process a single event.

        Args:
            event: The event to process
            context: Shared pipeline context

        Returns:
            StageResult with success status and processed data
        """
        pass

    def initialize(self, context: StageContext) -> bool:
        """
        Initialize the stage with context.

        Called once when the pipeline starts. Override to set up
        resources like connections, caches, etc.

        Args:
            context: Shared pipeline context

        Returns:
            True if initialization successful
        """
        self.logger.debug(f"Initializing {self.name}")
        return True

    def shutdown(self) -> None:
        """
        Cleanup stage resources.

        Called when the pipeline stops. Override to close connections,
        flush buffers, etc.
        """
        self.logger.debug(f"Shutting down {self.name}")

    def health_check(self) -> bool:
        """
        Check if the stage is healthy.

        Returns:
            True if stage is functioning correctly
        """
        return True

    def get_stats(self) -> Dict[str, Any]:
        """
        Get stage statistics.

        Returns:
            Dict with stage metrics
        """
        avg_time = (
            self._total_time_ms / self._total_processed
            if self._total_processed > 0 else 0
        )
        return {
            "name": self.name,
            "total_processed": self._total_processed,
            "total_errors": self._total_errors,
            "total_time_ms": self._total_time_ms,
            "avg_time_ms": avg_time,
            "error_rate": (
                self._total_errors / self._total_processed
                if self._total_processed > 0 else 0
            ),
        }

    def _wrap_process(self, event: T, context: StageContext) -> StageResult:
        """
        Wrapper that handles timing and error tracking.

        Internal method - use process() in implementations.
        """
        start_time = time.perf_counter()

        try:
            result = self.process(event, context)
            self._total_processed += 1

            if not result.success:
                self._total_errors += 1

        except Exception as e:
            self.logger.error(f"Stage {self.name} error: {e}", exc_info=True)
            self._total_errors += 1
            result = StageResult(
                success=False,
                errors=[f"Stage error: {str(e)}"]
            )

        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            self._total_time_ms += elapsed_ms
            result.processing_time_ms = elapsed_ms

            # Add timing to context metrics
            context.add_metric(self.name, "last_processing_ms", elapsed_ms)

        return result


class CompositeStage(PipelineStage[T]):
    """
    A stage that chains multiple sub-stages together.

    Useful for grouping related stages or creating pipelines within pipelines.
    """

    def __init__(self, name: str, stages: list):
        """
        Initialize composite stage.

        Args:
            name: Name for this composite stage
            stages: List of stages to chain
        """
        super().__init__(name)
        self.stages = stages

    def initialize(self, context: StageContext) -> bool:
        """Initialize all sub-stages"""
        for stage in self.stages:
            if not stage.initialize(context):
                self.logger.error(f"Failed to initialize sub-stage: {stage.name}")
                return False
        return True

    def shutdown(self) -> None:
        """Shutdown all sub-stages"""
        for stage in self.stages:
            stage.shutdown()

    def process(self, event: T, context: StageContext) -> StageResult:
        """Process through all sub-stages in order"""
        current_event = event

        for stage in self.stages:
            result = stage._wrap_process(current_event, context)

            if not result.success:
                return result

            # Pass output to next stage
            if result.data is not None:
                current_event = result.data

        return StageResult(success=True, data=current_event)

    def health_check(self) -> bool:
        """Check health of all sub-stages"""
        return all(stage.health_check() for stage in self.stages)

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregated stats from all sub-stages"""
        stats = super().get_stats()
        stats["sub_stages"] = [stage.get_stats() for stage in self.stages]
        return stats
