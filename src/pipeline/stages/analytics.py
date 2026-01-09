"""
Analytics Stage

Performs anomaly detection and threat analytics on scored connection events.
Extracted from DataPipeline analytics processing logic.
"""

import logging
from typing import Dict, Optional, Any

from .base import PipelineStage, StageContext
from ..config import PipelineConfig
from ..events import ConnectionEvent, AnomalyData, StageResult

logger = logging.getLogger(__name__)


class AnalyticsStage(PipelineStage[ConnectionEvent]):
    """
    Applies threat analytics and anomaly detection to connection events.

    Features:
    - Statistical anomaly detection via ThreatAnalytics
    - Connection pattern analysis
    - Metadata aggregation for reporting
    - Anomaly event posting for dashboard alerts

    Extracted from:
    - orchestrator.py lines 677-745 (analytics processing + metadata aggregation)
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        super().__init__("AnalyticsStage")
        self.config = config or PipelineConfig()

        # Stats
        self._analytics_processed = 0
        self._anomalies_detected = 0
        self._critical_anomalies = 0
        self._analytics_failures = 0

    def initialize(self, context: StageContext) -> bool:
        """Initialize with analytics services"""
        if context.config:
            self.config = context.config

        # Check for required analytics services
        if not hasattr(context, 'threat_analytics') or not context.threat_analytics:
            self.logger.warning("No threat analytics available - anomaly detection disabled")

        if not hasattr(context, 'metadata_aggregator') or not context.metadata_aggregator:
            self.logger.debug("No metadata aggregator available")

        self.logger.info("AnalyticsStage initialized")
        return True

    def process(self, event: ConnectionEvent, context: StageContext) -> StageResult:
        """
        Apply analytics to the connection event.

        Args:
            event: Scored connection event
            context: Pipeline context with analytics services

        Returns:
            StageResult with analytics-enriched event
        """
        result = StageResult()

        # Skip analytics for duplicates
        if event.is_duplicate:
            result.success = True
            result.data = event
            result.items_skipped = 1
            return result

        # Process anomaly detection
        anomaly_data = self._detect_anomalies(event, context)
        if anomaly_data:
            event.anomaly = anomaly_data

            # Track anomaly stats
            if anomaly_data.anomaly_type not in ("normal", None):
                self._anomalies_detected += 1
                if anomaly_data.score >= self.config.anomaly.critical_threshold:
                    self._critical_anomalies += 1

                # Post alert to UI
                self._post_anomaly_alert(event, anomaly_data)

        # Feed to metadata aggregator
        self._aggregate_metadata(event, context)

        self._analytics_processed += 1
        result.success = True
        result.data = event
        result.items_processed = 1

        if anomaly_data and anomaly_data.score > 0:
            result.add_metric("anomaly_score", anomaly_data.score)

        return result

    def _detect_anomalies(
        self,
        event: ConnectionEvent,
        context: StageContext
    ) -> Optional[AnomalyData]:
        """
        Run anomaly detection on the connection.

        Args:
            event: Connection event to analyze
            context: Pipeline context with threat_analytics

        Returns:
            AnomalyData if anomaly detected, None otherwise
        """
        if not hasattr(context, 'threat_analytics') or not context.threat_analytics:
            return None

        try:
            analytics_result = context.threat_analytics.process_connection(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                threat_score=event.consensus.final_score,
                confidence=event.consensus.confidence,
                dst_port=event.dst_port,
                dst_asn=event.asn.asn if event.asn else None,
                dst_org=event.asn.organization if event.asn else None,
                dst_org_type=event.asn.org_type if event.asn else None,
                org_trust=event.asn.trust_score if event.asn else 0.5,
                hop_count=0,  # Will be filled if available
                geo_risk=0.5,  # Default geo risk
                timestamp=event.timestamp,
            )

            if analytics_result and analytics_result.get("anomaly"):
                anomaly = analytics_result["anomaly"]
                return AnomalyData(
                    score=float(anomaly.get("score", 0)),
                    anomaly_type=anomaly.get("type", "normal"),
                    z_score=float(anomaly.get("z_score", 0)),
                    percentile=float(anomaly.get("percentile", 50)),
                    factors=anomaly.get("factors", []),
                )

            return None

        except Exception as e:
            self._analytics_failures += 1
            self.logger.debug(f"Anomaly detection failed for {event.dst_ip}: {e}")
            return None

    def _post_anomaly_alert(self, event: ConnectionEvent, anomaly: AnomalyData):
        """
        Post anomaly alert to dashboard UI.

        Args:
            event: Connection event with anomaly
            anomaly: Detected anomaly data
        """
        try:
            from src.utils.logging_config import UIEventPoster

            # Determine severity based on score
            if anomaly.score >= self.config.anomaly.critical_threshold:
                severity = "CRITICAL"
            elif anomaly.score >= self.config.anomaly.warning_threshold:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            message = (
                f"{anomaly.anomaly_type.upper()}: {event.dst_ip} "
                f"(score: {anomaly.score:.2f})"
            )

            UIEventPoster.anomaly(message, severity, {
                'dst_ip': event.dst_ip,
                'anomaly_type': anomaly.anomaly_type,
                'anomaly_score': anomaly.score,
                'factors': anomaly.factors,
            })

        except Exception as e:
            self.logger.debug(f"Failed to post anomaly event: {e}")

    def _aggregate_metadata(self, event: ConnectionEvent, context: StageContext):
        """
        Feed connection data to metadata aggregator.

        Args:
            event: Connection event to aggregate
            context: Pipeline context with metadata_aggregator
        """
        if not hasattr(context, 'metadata_aggregator') or not context.metadata_aggregator:
            return

        try:
            context.metadata_aggregator.process_connection({
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "threat_score": event.consensus.final_score,
                "confidence": event.consensus.confidence,
                "dst_asn": event.asn.asn if event.asn else None,
                "dst_org": event.asn.organization if event.asn else None,
                "dst_org_type": event.asn.org_type if event.asn else None,
                "dst_country": event.geo.country if event.geo else None,
                "hop_count": None,
                "org_trust_score": event.asn.trust_score if event.asn else 0.5,
            })
        except Exception:
            pass  # Non-critical aggregation failure

    def get_stats(self) -> Dict:
        """Get analytics stage statistics"""
        stats = super().get_stats()
        stats.update({
            "analytics_processed": self._analytics_processed,
            "anomalies_detected": self._anomalies_detected,
            "critical_anomalies": self._critical_anomalies,
            "analytics_failures": self._analytics_failures,
            "anomaly_rate": (
                self._anomalies_detected / max(self._analytics_processed, 1)
            ),
        })
        return stats

    def health_check(self) -> bool:
        """Check if analytics stage is healthy"""
        # Check failure rate
        failure_rate = self._analytics_failures / max(self._analytics_processed, 1)
        if failure_rate > 0.2:
            self.logger.warning(f"High analytics failure rate: {failure_rate:.2%}")
            return False
        return True
