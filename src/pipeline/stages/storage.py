"""
Storage Stage

Persists connection events to database and handles export.
Extracted from DataPipeline storage and export logic.
"""

import logging
from typing import Dict, Optional, Any

from .base import PipelineStage, StageContext
from ..config import PipelineConfig
from ..events import ConnectionEvent, StageResult

logger = logging.getLogger(__name__)


class StorageStage(PipelineStage[ConnectionEvent]):
    """
    Persists connection events to database and exports assessments.

    Features:
    - Database storage of connections
    - Device record updates
    - Consensus assessment export
    - Batch optimization (future)

    Extracted from:
    - orchestrator.py lines 747-811 (storage + export)
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        super().__init__("StorageStage")
        self.config = config or PipelineConfig()

        # Stats
        self._connections_stored = 0
        self._devices_updated = 0
        self._assessments_exported = 0
        self._storage_failures = 0
        self._export_failures = 0

    def initialize(self, context: StageContext) -> bool:
        """Initialize with database and exporter"""
        if context.config:
            self.config = context.config

        if not context.database:
            self.logger.warning("No database available - storage disabled")

        self.logger.info("StorageStage initialized")
        return True

    def process(self, event: ConnectionEvent, context: StageContext) -> StageResult:
        """
        Store connection event to database and export if applicable.

        Args:
            event: Fully processed connection event
            context: Pipeline context with database and exporter

        Returns:
            StageResult with storage status
        """
        result = StageResult()

        # Skip storage for duplicates
        if event.is_duplicate:
            result.success = True
            result.data = event
            result.items_skipped = 1
            return result

        # Store to database
        stored = self._store_connection(event, context)
        if stored:
            self._connections_stored += 1
            result.add_metric("stored", 1)
        else:
            result.add_metric("storage_failed", 1)

        # Update device record
        device_updated = self._update_device(event, context)
        if device_updated:
            self._devices_updated += 1

        # Export assessment
        exported = self._export_assessment(event, context)
        if exported:
            self._assessments_exported += 1
            result.add_metric("exported", 1)

        result.success = True
        result.data = event
        result.items_processed = 1
        return result

    def _store_connection(
        self,
        event: ConnectionEvent,
        context: StageContext
    ) -> bool:
        """
        Store connection to database.

        Args:
            event: Connection event to store
            context: Pipeline context with database

        Returns:
            True if stored successfully
        """
        if not context.database:
            return False

        try:
            context.database.add_connection({
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "src_mac": event.src_mac,
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "protocol": event.protocol,
                "threat_score": event.consensus.final_score,

                # Geo data
                "dst_country": event.geo.country,
                "dst_lat": event.geo.latitude,
                "dst_lon": event.geo.longitude,
                "dst_hostname": event.device_hostname,

                # Device info
                "device_vendor": event.device_vendor,

                # ASN data
                "dst_asn": event.asn.asn,
                "dst_asn_name": event.asn.asn_name,
                "dst_org": event.asn.organization,
                "dst_org_type": event.asn.org_type,
                "dst_cidr": event.asn.cidr,
                "org_trust_score": event.asn.trust_score,

                # Scoring metadata
                "confidence": event.consensus.confidence,
                "high_uncertainty": event.consensus.high_uncertainty,
                "scoring_method": "consensus",

                # Individual scorer results
                "score_statistical": event.consensus.score_statistical,
                "score_rule_based": event.consensus.score_rule_based,
                "score_ml_based": event.consensus.score_ml,
                "score_organization": event.consensus.score_organization,
                "score_spread": abs(
                    max(
                        event.consensus.score_statistical,
                        event.consensus.score_rule_based,
                        event.consensus.score_ml,
                        event.consensus.score_organization
                    ) - min(
                        event.consensus.score_statistical,
                        event.consensus.score_rule_based,
                        event.consensus.score_ml,
                        event.consensus.score_organization
                    )
                ),

                # Anomaly data
                "anomaly_score": (
                    event.anomaly.score if event.anomaly and event.anomaly.score > 0
                    else None
                ),
            })
            return True

        except Exception as e:
            self._storage_failures += 1
            self.logger.debug(f"Database storage failed: {e}")
            return False

    def _update_device(
        self,
        event: ConnectionEvent,
        context: StageContext
    ) -> bool:
        """
        Update device record with connection threat score.

        Args:
            event: Connection event
            context: Pipeline context with database

        Returns:
            True if device updated
        """
        if not context.database or not event.src_mac:
            return False

        try:
            context.database.upsert_device(
                mac=event.src_mac,
                ip=event.src_ip,
                vendor=event.device_vendor,
                packet_type="connection",
                threat_score=event.consensus.final_score
            )
            return True
        except Exception:
            return False

    def _export_assessment(
        self,
        event: ConnectionEvent,
        context: StageContext
    ) -> bool:
        """
        Export consensus assessment if exporter available.

        Args:
            event: Connection event
            context: Pipeline context with exporter

        Returns:
            True if exported
        """
        if not hasattr(context, 'exporter') or not context.exporter:
            return False

        # Only export consensus-scored connections
        if event.consensus.high_uncertainty:
            return False

        try:
            consensus_details = {
                "final_score": event.consensus.final_score,
                "confidence": event.consensus.confidence,
                "score_statistical": event.consensus.score_statistical,
                "score_rule_based": event.consensus.score_rule_based,
                "score_ml_based": event.consensus.score_ml,
                "score_organization": event.consensus.score_organization,
                "dst_asn": event.asn.asn,
                "dst_org": event.asn.organization,
                "dst_org_type": event.asn.org_type,
                "org_trust_score": event.asn.trust_score,
            }

            context.exporter.export_assessment(
                dst_ip=event.dst_ip,
                consensus_result=consensus_details,
                connection_metadata={
                    "dst_port": event.dst_port,
                    "protocol": event.protocol,
                },
            )
            return True

        except Exception:
            self._export_failures += 1
            return False

    def get_stats(self) -> Dict:
        """Get storage stage statistics"""
        stats = super().get_stats()
        stats.update({
            "connections_stored": self._connections_stored,
            "devices_updated": self._devices_updated,
            "assessments_exported": self._assessments_exported,
            "storage_failures": self._storage_failures,
            "export_failures": self._export_failures,
            "storage_success_rate": (
                self._connections_stored /
                max(self._connections_stored + self._storage_failures, 1)
            ),
        })
        return stats

    def health_check(self) -> bool:
        """Check if storage stage is healthy"""
        # Check storage failure rate
        total_attempts = self._connections_stored + self._storage_failures
        if total_attempts > 0:
            failure_rate = self._storage_failures / total_attempts
            if failure_rate > 0.1:
                self.logger.warning(f"High storage failure rate: {failure_rate:.2%}")
                return False
        return True

    def shutdown(self) -> None:
        """Cleanup on shutdown"""
        self.logger.info(
            f"StorageStage shutting down "
            f"(stored={self._connections_stored}, exported={self._assessments_exported})"
        )
