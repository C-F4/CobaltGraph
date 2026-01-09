"""
Validation Stage

Validates incoming connections and performs deduplication.
Extracted from DataPipeline._is_duplicate() and validation logic.
"""

import logging
import time
import threading
from typing import Dict, Optional

from .base import PipelineStage, StageContext
from ..config import PipelineConfig
from ..events import ConnectionEvent, StageResult

logger = logging.getLogger(__name__)


class ValidationStage(PipelineStage[ConnectionEvent]):
    """
    Validates and deduplicates incoming connection events.

    Responsibilities:
    - Validate required fields (dst_ip, dst_port)
    - Check for duplicate connections within dedup window
    - Filter invalid or malformed events
    - Track validation metrics

    Extracted from:
    - orchestrator.py lines 482-503 (_is_duplicate)
    - orchestrator.py connection validation in _process_connection
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        super().__init__("ValidationStage")
        self.config = config or PipelineConfig()

        # Deduplication state
        self._seen_connections: Dict[str, float] = {}
        self._dedup_lock = threading.Lock()

        # Stats
        self._dedup_hits = 0
        self._validation_failures = 0

    def initialize(self, context: StageContext) -> bool:
        """Initialize with context configuration"""
        if context.config:
            self.config = context.config
        self.logger.info(
            f"ValidationStage initialized (dedup_window={self.config.deduplication.window_seconds}s)"
        )
        return True

    def process(self, event: ConnectionEvent, context: StageContext) -> StageResult:
        """
        Validate and deduplicate a connection event.

        Args:
            event: Connection event to validate
            context: Pipeline context

        Returns:
            StageResult with validated event or error
        """
        result = StageResult()

        # Validate required fields
        validation_errors = self._validate_fields(event)
        if validation_errors:
            self._validation_failures += 1
            result.success = False
            result.errors = validation_errors
            result.add_metric("validation_failed", 1)
            return result

        # Check for duplicates
        if self._is_duplicate(event.dst_ip, event.dst_port):
            event.is_duplicate = True
            result.success = True
            result.data = event
            result.add_metric("is_duplicate", 1)
            result.items_skipped = 1
            return result

        # Valid, non-duplicate event
        result.success = True
        result.data = event
        result.items_processed = 1
        return result

    def _validate_fields(self, event: ConnectionEvent) -> list:
        """
        Validate required fields on the event.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not event.dst_ip:
            errors.append("Missing destination IP")

        if event.dst_port < 0 or event.dst_port > 65535:
            errors.append(f"Invalid port number: {event.dst_port}")

        # Validate IP format (basic check)
        if event.dst_ip:
            parts = event.dst_ip.split('.')
            if len(parts) != 4:
                # Could be IPv6 - check for colons
                if ':' not in event.dst_ip:
                    errors.append(f"Invalid IP format: {event.dst_ip}")

        if event.protocol not in ("TCP", "UDP", "ICMP", ""):
            errors.append(f"Unknown protocol: {event.protocol}")

        return errors

    def _is_duplicate(self, dst_ip: str, dst_port: int) -> bool:
        """
        Check if connection is duplicate within dedup window.

        Uses a thread-safe cache with periodic cleanup.

        Args:
            dst_ip: Destination IP
            dst_port: Destination port

        Returns:
            True if duplicate, False otherwise
        """
        key = f"{dst_ip}:{dst_port}"
        now = time.time()
        window = self.config.deduplication.window_seconds
        max_cache = self.config.deduplication.max_cache_size
        cleanup_threshold = self.config.deduplication.cleanup_threshold

        with self._dedup_lock:
            last_seen = self._seen_connections.get(key, 0)

            if now - last_seen < window:
                self._dedup_hits += 1
                return True

            self._seen_connections[key] = now

            # Cleanup old entries when cache is full
            # (Moved cleanup outside hot path for better performance)
            cache_size = len(self._seen_connections)
            if cache_size > max_cache * cleanup_threshold:
                self._cleanup_cache(now, window)

        return False

    def _cleanup_cache(self, now: float, window: float):
        """
        Remove expired entries from dedup cache.

        Called when cache exceeds threshold.
        """
        cutoff = now - window
        initial_size = len(self._seen_connections)

        self._seen_connections = {
            k: v for k, v in self._seen_connections.items()
            if v > cutoff
        }

        removed = initial_size - len(self._seen_connections)
        if removed > 0:
            self.logger.debug(f"Cleaned {removed} expired dedup entries")

    def get_stats(self) -> Dict:
        """Get validation stage statistics"""
        stats = super().get_stats()
        stats.update({
            "dedup_hits": self._dedup_hits,
            "validation_failures": self._validation_failures,
            "dedup_cache_size": len(self._seen_connections),
        })
        return stats

    def shutdown(self) -> None:
        """Cleanup on shutdown"""
        self.logger.info(
            f"ValidationStage shutting down "
            f"(processed={self._total_processed}, dedup_hits={self._dedup_hits})"
        )
        self._seen_connections.clear()

    def health_check(self) -> bool:
        """Check if validation stage is healthy"""
        # Check if cache is not growing unbounded
        max_cache = self.config.deduplication.max_cache_size
        current_size = len(self._seen_connections)

        if current_size > max_cache * 1.5:
            self.logger.warning(f"Dedup cache exceeds limit: {current_size} > {max_cache}")
            return False

        return True
