"""
Scoring Stage

Applies consensus threat scoring to enriched connection events.
Extracted from DataPipeline consensus scoring logic.
"""

import logging
from typing import Dict, Optional, Any

from .base import PipelineStage, StageContext
from ..config import PipelineConfig
from ..events import (
    ConnectionEvent, ConsensusResult, ASNData, ThreatLevel, StageResult
)

logger = logging.getLogger(__name__)


class ScoringStage(PipelineStage[ConnectionEvent]):
    """
    Applies consensus threat scoring to connection events.

    Uses the BFT consensus engine to combine scores from multiple
    scorers (statistical, rule-based, ML, organization).

    Extracted from:
    - orchestrator.py lines 623-673 (consensus scoring)
    - orchestrator.py lines 665-675 (ASN data extraction)
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        super().__init__("ScoringStage")
        self.config = config or PipelineConfig()

        # Stats
        self._high_threat_count = 0
        self._medium_threat_count = 0
        self._low_threat_count = 0
        self._uncertainty_count = 0
        self._scorer_failures = 0

    def initialize(self, context: StageContext) -> bool:
        """Initialize with consensus scorer"""
        if context.config:
            self.config = context.config

        if not context.consensus_scorer:
            self.logger.warning("No consensus scorer available - will use fallback scoring")

        self.logger.info("ScoringStage initialized")
        return True

    def process(self, event: ConnectionEvent, context: StageContext) -> StageResult:
        """
        Apply consensus scoring to the connection event.

        Args:
            event: Enriched connection event
            context: Pipeline context with consensus scorer

        Returns:
            StageResult with scored event
        """
        result = StageResult()

        # Skip scoring for duplicates
        if event.is_duplicate:
            result.success = True
            result.data = event
            result.items_skipped = 1
            return result

        # Get consensus score
        consensus_result = self._apply_consensus(event, context)
        event.consensus = consensus_result

        # Classify threat level
        event.threat_level = self._classify_threat(consensus_result.final_score)

        # Track stats
        self._update_stats(event)

        result.success = True
        result.data = event
        result.items_processed = 1
        result.add_metric("threat_score", consensus_result.final_score)
        result.add_metric("confidence", consensus_result.confidence)

        return result

    def _apply_consensus(
        self,
        event: ConnectionEvent,
        context: StageContext
    ) -> ConsensusResult:
        """
        Apply consensus scoring using the BFT consensus engine.

        Args:
            event: Connection event to score
            context: Pipeline context

        Returns:
            ConsensusResult with final score and details
        """
        consensus = ConsensusResult()

        if not context.consensus_scorer:
            # Fallback scoring when no scorer available
            return self._fallback_scoring(event)

        try:
            # Build input for consensus scorer
            scorer_input = self._build_scorer_input(event)

            # Get consensus result
            scorer_result = context.consensus_scorer.score(
                event.dst_ip,
                **scorer_input
            )

            if scorer_result:
                # Extract results
                consensus.final_score = float(scorer_result.get("final_score", 0.2))
                consensus.confidence = float(scorer_result.get("confidence", 0.5))
                consensus.high_uncertainty = scorer_result.get("high_uncertainty", False)

                # Individual scorer results
                consensus.score_statistical = float(scorer_result.get("score_statistical", 0))
                consensus.score_rule_based = float(scorer_result.get("score_rule_based", 0))
                consensus.score_ml = float(scorer_result.get("score_ml", 0))
                consensus.score_organization = float(scorer_result.get("score_organization", 0))

                # Agreement metrics
                consensus.scorer_agreement = float(scorer_result.get("agreement", 0))
                consensus.outlier_detected = scorer_result.get("outlier_detected", False)
                consensus.outlier_scorer = scorer_result.get("outlier_scorer")

                # Extract ASN data if returned by scorer
                if "dst_asn" in scorer_result:
                    event.asn = ASNData(
                        asn=scorer_result.get("dst_asn", 0),
                        asn_name=scorer_result.get("dst_asn_name", ""),
                        organization=scorer_result.get("dst_org", ""),
                        org_type=scorer_result.get("dst_org_type", "unknown"),
                        trust_score=float(scorer_result.get("org_trust_score", 0.5)),
                    )

                if consensus.high_uncertainty:
                    self._uncertainty_count += 1

            return consensus

        except Exception as e:
            self._scorer_failures += 1
            self.logger.warning(f"Consensus scoring failed: {e}")
            return self._fallback_scoring(event)

    def _build_scorer_input(self, event: ConnectionEvent) -> Dict[str, Any]:
        """
        Build input dict for consensus scorer from event data.

        Args:
            event: Connection event

        Returns:
            Dict with scorer input fields
        """
        return {
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "geo_data": {
                "country": event.geo.country,
                "country_code": event.geo.country_code,
                "city": event.geo.city,
                "lat": event.geo.latitude,
                "lon": event.geo.longitude,
                "isp": event.geo.isp,
            } if event.geo.country else None,
            "threat_intel": {
                "is_malicious": event.threat_intel.is_malicious,
                "is_tor": event.threat_intel.is_tor_exit,
                "abuse_score": event.threat_intel.abuse_score,
            } if event.threat_intel.abuse_score > 0 else None,
        }

    def _fallback_scoring(self, event: ConnectionEvent) -> ConsensusResult:
        """
        Apply fallback scoring when consensus scorer unavailable.

        Uses simple heuristics based on available data.

        Args:
            event: Connection event

        Returns:
            ConsensusResult with fallback score
        """
        consensus = ConsensusResult()
        score = self.config.scoring.fallback_threat_score

        # Boost score for known threat indicators
        if event.threat_intel.is_malicious:
            score = max(score, 0.8)
        if event.threat_intel.is_tor_exit:
            score = max(score, 0.6)
        if event.threat_intel.abuse_score > 50:
            score = max(score, 0.7)

        # Consider high-risk ports
        high_risk_ports = {22, 23, 25, 445, 3389, 4444, 5900}
        if event.dst_port in high_risk_ports:
            score = max(score, 0.5)

        consensus.final_score = min(score, 1.0)
        consensus.confidence = self.config.scoring.fallback_confidence
        consensus.high_uncertainty = True  # Fallback always uncertain

        return consensus

    def _classify_threat(self, score: float) -> ThreatLevel:
        """
        Classify threat level based on score.

        Args:
            score: Final threat score (0-1)

        Returns:
            ThreatLevel enum
        """
        if score >= self.config.scoring.high_threat_threshold:
            return ThreatLevel.CRITICAL if score >= 0.85 else ThreatLevel.HIGH
        elif score >= self.config.scoring.medium_threat_threshold:
            return ThreatLevel.MEDIUM
        elif score >= self.config.scoring.low_threat_threshold:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.LOW

    def _update_stats(self, event: ConnectionEvent):
        """Update threat level statistics"""
        if event.threat_level == ThreatLevel.CRITICAL:
            self._high_threat_count += 1
        elif event.threat_level == ThreatLevel.HIGH:
            self._high_threat_count += 1
        elif event.threat_level == ThreatLevel.MEDIUM:
            self._medium_threat_count += 1
        else:
            self._low_threat_count += 1

    def get_stats(self) -> Dict:
        """Get scoring stage statistics"""
        stats = super().get_stats()
        total = self._high_threat_count + self._medium_threat_count + self._low_threat_count
        stats.update({
            "high_threat_count": self._high_threat_count,
            "medium_threat_count": self._medium_threat_count,
            "low_threat_count": self._low_threat_count,
            "uncertainty_count": self._uncertainty_count,
            "scorer_failures": self._scorer_failures,
            "high_threat_rate": self._high_threat_count / max(total, 1),
        })
        return stats

    def health_check(self) -> bool:
        """Check if scoring stage is healthy"""
        # Check failure rate
        failure_rate = self._scorer_failures / max(self._total_processed, 1)
        if failure_rate > 0.1:
            self.logger.warning(f"High scorer failure rate: {failure_rate:.2%}")
            return False
        return True
