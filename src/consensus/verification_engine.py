"""
CobaltGraph AI Verification Engine

Autonomous local AI assessment for threat verification.
Provides triangulation scoring and verification status based on:
- Multi-scorer consensus agreement
- Cross-source correlation
- Historical pattern matching
- Confidence thresholds

Verification States:
- verified: High confidence, sources agree, threat assessment reliable
- flagged: High uncertainty, requires attention, sources disagree
- pending: Awaiting sufficient data for assessment
- unknown: Insufficient sources or data anomaly detected

This runs entirely locally - no external AI calls required.
"""

import logging
import time
from dataclasses import dataclass, field
from collections import deque
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of AI verification assessment"""
    status: str  # verified, flagged, pending, unknown
    reason: str  # Human-readable explanation
    confidence: float  # 0.0-1.0 confidence in this assessment
    triangulation_score: float  # Cross-correlation score
    triangulation_sources: int  # Number of agreeing sources
    metrics_explained: Dict[str, str] = field(default_factory=dict)  # Metric -> explanation


class VerificationEngine:
    """
    Local AI verification engine for autonomous threat assessment.

    Computes verification status by triangulating:
    1. Statistical scorer assessment
    2. Rule-based scorer assessment
    3. ML scorer assessment
    4. Organization trust scorer assessment
    5. Historical baseline comparison
    6. Anomaly detection results

    Provides human-readable explanations for why metrics are scored as they are.
    """

    # Thresholds for verification decisions
    AGREEMENT_THRESHOLD = 0.15  # Max spread for "verified" status
    FLAGGED_THRESHOLD = 0.30    # Spread above this = "flagged"
    MIN_SOURCES_FOR_VERIFIED = 3  # Minimum scorers needed
    HIGH_CONFIDENCE_THRESHOLD = 0.75
    LOW_CONFIDENCE_THRESHOLD = 0.40

    # Organization type risk explanations
    ORG_TYPE_EXPLANATIONS = {
        'cloud': "Major cloud provider - generally trusted infrastructure",
        'cdn': "Content delivery network - distributed trusted service",
        'enterprise': "Corporate network - business traffic expected",
        'education': "Educational institution - typically low risk",
        'government': "Government network - legitimate but monitor for anomalies",
        'isp': "Internet service provider - mixed traffic, baseline risk",
        'isp_residential': "Residential ISP - consumer traffic, moderate risk",
        'isp_business': "Business ISP - enterprise traffic, lower risk",
        'hosting': "Hosting provider - mixed content, requires scrutiny",
        'vpn': "VPN service - anonymization layer, elevated risk for masking",
        'proxy': "Proxy service - traffic obfuscation, elevated risk",
        'tor': "Tor exit node - maximum anonymization, high risk for malicious use",
        'unknown': "Unclassified network - insufficient data for trust assessment",
    }

    # Threat level explanations
    THREAT_EXPLANATIONS = {
        'critical': "Multiple high-confidence indicators of malicious activity",
        'high': "Significant threat indicators requiring immediate attention",
        'medium': "Moderate risk indicators - monitor for escalation",
        'low': "Minimal threat indicators - normal traffic patterns",
        'info': "Informational only - no significant threat detected",
    }

    def __init__(self, history_size: int = 500):
        """Initialize verification engine with history buffer"""
        self.history_size = history_size
        self._history: deque = deque(maxlen=history_size)
        self._ip_baseline: Dict[str, Dict] = {}  # IP -> historical stats
        self._org_baseline: Dict[str, Dict] = {}  # Org -> historical stats
        self._lock = Lock()

        # Performance metrics
        self.total_verifications = 0
        self.verified_count = 0
        self.flagged_count = 0
        self.unknown_count = 0

        logger.info("VerificationEngine initialized (local AI assessment)")

    def verify_connection(
        self,
        dst_ip: str,
        threat_score: float,
        confidence: float,
        score_statistical: Optional[float],
        score_rule_based: Optional[float],
        score_ml_based: Optional[float],
        score_organization: Optional[float],
        score_spread: Optional[float],
        high_uncertainty: bool,
        org_type: str,
        org_trust_score: float,
        hop_count: Optional[int],
        anomaly_score: float = 0.0,
    ) -> VerificationResult:
        """
        Perform AI verification assessment on a connection.

        Args:
            dst_ip: Destination IP address
            threat_score: Final consensus threat score
            confidence: Consensus confidence level
            score_*: Individual scorer results
            score_spread: Disagreement between scorers
            high_uncertainty: Flag from BFT consensus
            org_type: Organization classification
            org_trust_score: Organization trust level
            hop_count: Network hop distance
            anomaly_score: Statistical anomaly score

        Returns:
            VerificationResult with status, reason, and metric explanations
        """
        self.total_verifications += 1

        # Collect available scores
        scores = []
        source_names = []

        if score_statistical is not None:
            scores.append(score_statistical)
            source_names.append("Statistical")
        if score_rule_based is not None:
            scores.append(score_rule_based)
            source_names.append("Rule-Based")
        if score_ml_based is not None:
            scores.append(score_ml_based)
            source_names.append("ML Model")
        if score_organization is not None:
            scores.append(score_organization)
            source_names.append("Organization")

        num_sources = len(scores)

        # Calculate triangulation score (agreement level)
        if num_sources >= 2:
            spread = score_spread if score_spread is not None else self._calculate_spread(scores)
            triangulation_score = max(0.0, 1.0 - (spread * 2))  # Higher = more agreement
        else:
            spread = 0.5  # Unknown spread
            triangulation_score = 0.5  # Neutral

        # Build metric explanations
        metrics_explained = self._build_metric_explanations(
            threat_score=threat_score,
            confidence=confidence,
            org_type=org_type,
            org_trust_score=org_trust_score,
            hop_count=hop_count,
            score_statistical=score_statistical,
            score_rule_based=score_rule_based,
            score_ml_based=score_ml_based,
            score_organization=score_organization,
            spread=spread,
            anomaly_score=anomaly_score,
        )

        # Determine verification status
        status, reason, ver_confidence = self._determine_status(
            num_sources=num_sources,
            spread=spread,
            high_uncertainty=high_uncertainty,
            confidence=confidence,
            threat_score=threat_score,
            anomaly_score=anomaly_score,
            org_type=org_type,
            triangulation_score=triangulation_score,
        )

        # Track metrics
        with self._lock:
            if status == "verified":
                self.verified_count += 1
            elif status == "flagged":
                self.flagged_count += 1
            elif status == "unknown":
                self.unknown_count += 1

            # Update IP baseline
            self._update_baseline(dst_ip, threat_score, confidence)

        return VerificationResult(
            status=status,
            reason=reason,
            confidence=ver_confidence,
            triangulation_score=triangulation_score,
            triangulation_sources=num_sources,
            metrics_explained=metrics_explained,
        )

    def _calculate_spread(self, scores: List[float]) -> float:
        """Calculate spread (disagreement) between scores"""
        if len(scores) < 2:
            return 0.5
        return max(scores) - min(scores)

    def _determine_status(
        self,
        num_sources: int,
        spread: float,
        high_uncertainty: bool,
        confidence: float,
        threat_score: float,
        anomaly_score: float,
        org_type: str,
        triangulation_score: float,
    ) -> Tuple[str, str, float]:
        """
        Determine verification status with reason.

        Returns:
            Tuple of (status, reason, confidence)
        """
        reasons = []

        # Insufficient sources = pending
        if num_sources < 2:
            return (
                "pending",
                f"Awaiting scorer data ({num_sources}/4 sources available)",
                0.3
            )

        # High uncertainty from BFT consensus = flagged
        if high_uncertainty:
            reasons.append("Scorer disagreement detected")

        # Very high spread = flagged
        if spread > self.FLAGGED_THRESHOLD:
            reasons.append(f"High scorer variance ({spread:.2f})")

        # Anomaly detected = flagged
        if anomaly_score > 0.5:
            reasons.append(f"Statistical anomaly detected ({anomaly_score:.2f})")

        # High-risk org type with low scorer confidence = flagged
        if org_type in ['tor', 'proxy', 'vpn'] and confidence < 0.6:
            reasons.append(f"High-risk org type ({org_type}) with low confidence")

        # If we have flagging reasons
        if reasons:
            return (
                "flagged",
                "; ".join(reasons),
                max(0.3, min(0.7, triangulation_score))
            )

        # Good agreement and sufficient sources = verified
        if num_sources >= self.MIN_SOURCES_FOR_VERIFIED and spread < self.AGREEMENT_THRESHOLD:
            if confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
                return (
                    "verified",
                    f"Strong consensus ({num_sources} sources agree, spread={spread:.2f})",
                    min(0.95, triangulation_score + 0.1)
                )
            else:
                return (
                    "verified",
                    f"Consensus achieved ({num_sources} sources, confidence={confidence:.2f})",
                    min(0.85, triangulation_score)
                )

        # Moderate agreement
        if num_sources >= 2 and spread < self.AGREEMENT_THRESHOLD:
            return (
                "verified",
                f"Basic consensus ({num_sources} sources, spread={spread:.2f})",
                min(0.75, triangulation_score)
            )

        # Default: unknown (edge cases)
        return (
            "unknown",
            f"Insufficient data for reliable assessment ({num_sources} sources)",
            0.4
        )

    def _build_metric_explanations(
        self,
        threat_score: float,
        confidence: float,
        org_type: str,
        org_trust_score: float,
        hop_count: Optional[int],
        score_statistical: Optional[float],
        score_rule_based: Optional[float],
        score_ml_based: Optional[float],
        score_organization: Optional[float],
        spread: float,
        anomaly_score: float,
    ) -> Dict[str, str]:
        """Build human-readable explanations for each metric"""
        explanations = {}

        # Threat level explanation
        if threat_score >= 0.8:
            level = "critical"
        elif threat_score >= 0.6:
            level = "high"
        elif threat_score >= 0.4:
            level = "medium"
        elif threat_score >= 0.2:
            level = "low"
        else:
            level = "info"

        explanations["threat_score"] = (
            f"{level.upper()}: {self.THREAT_EXPLANATIONS[level]}"
        )

        # Confidence explanation
        if confidence >= 0.8:
            explanations["confidence"] = "HIGH: Multiple scorers strongly agree on assessment"
        elif confidence >= 0.6:
            explanations["confidence"] = "MODERATE: Scorers mostly agree, minor variance"
        elif confidence >= 0.4:
            explanations["confidence"] = "LOW: Significant scorer disagreement, interpret with caution"
        else:
            explanations["confidence"] = "VERY LOW: Major uncertainty in assessment, requires manual review"

        # Organization type explanation
        org_type_lower = (org_type or 'unknown').lower()
        explanations["org_type"] = self.ORG_TYPE_EXPLANATIONS.get(
            org_type_lower, self.ORG_TYPE_EXPLANATIONS['unknown']
        )

        # Organization trust explanation
        if org_trust_score >= 0.8:
            explanations["org_trust"] = "HIGHLY TRUSTED: Well-known, reputable organization"
        elif org_trust_score >= 0.6:
            explanations["org_trust"] = "TRUSTED: Generally reliable organization"
        elif org_trust_score >= 0.4:
            explanations["org_trust"] = "NEUTRAL: Standard network, no specific trust indicators"
        elif org_trust_score >= 0.2:
            explanations["org_trust"] = "LOW TRUST: Limited reputation or concerning indicators"
        else:
            explanations["org_trust"] = "UNTRUSTED: High-risk or unknown organization"

        # Hop count explanation
        if hop_count is not None:
            if hop_count < 5:
                explanations["hop_count"] = f"{hop_count} hops: Very close (local/regional network)"
            elif hop_count < 10:
                explanations["hop_count"] = f"{hop_count} hops: Normal internet distance"
            elif hop_count < 15:
                explanations["hop_count"] = f"{hop_count} hops: Moderate distance, possibly international"
            elif hop_count < 25:
                explanations["hop_count"] = f"{hop_count} hops: Far - possible tunneling or VPN"
            else:
                explanations["hop_count"] = f"{hop_count} hops: Very far - likely tunneled or obfuscated"
        else:
            explanations["hop_count"] = "UNKNOWN: Awaiting response packet for TTL analysis"

        # Individual scorer explanations
        if score_statistical is not None:
            if score_statistical >= 0.7:
                explanations["score_statistical"] = f"{score_statistical:.2f}: Statistical outlier detected (unusual patterns)"
            elif score_statistical >= 0.4:
                explanations["score_statistical"] = f"{score_statistical:.2f}: Minor statistical deviation from baseline"
            else:
                explanations["score_statistical"] = f"{score_statistical:.2f}: Within normal statistical bounds"
        else:
            explanations["score_statistical"] = "N/A: Insufficient historical data for statistical analysis"

        if score_rule_based is not None:
            if score_rule_based >= 0.7:
                explanations["score_rule_based"] = f"{score_rule_based:.2f}: Multiple threat rules triggered"
            elif score_rule_based >= 0.4:
                explanations["score_rule_based"] = f"{score_rule_based:.2f}: Some threat patterns matched"
            else:
                explanations["score_rule_based"] = f"{score_rule_based:.2f}: No significant rule matches"
        else:
            explanations["score_rule_based"] = "N/A: Rule engine awaiting initialization"

        if score_ml_based is not None:
            if score_ml_based >= 0.7:
                explanations["score_ml_based"] = f"{score_ml_based:.2f}: ML model predicts high threat probability"
            elif score_ml_based >= 0.4:
                explanations["score_ml_based"] = f"{score_ml_based:.2f}: ML model indicates moderate concern"
            else:
                explanations["score_ml_based"] = f"{score_ml_based:.2f}: ML model predicts low threat"
        else:
            explanations["score_ml_based"] = "N/A: ML model requires training data"

        if score_organization is not None:
            if score_organization >= 0.7:
                explanations["score_organization"] = f"{score_organization:.2f}: Organization/ASN has concerning history"
            elif score_organization >= 0.4:
                explanations["score_organization"] = f"{score_organization:.2f}: Organization has mixed reputation"
            else:
                explanations["score_organization"] = f"{score_organization:.2f}: Organization is well-regarded"
        else:
            explanations["score_organization"] = "N/A: Organization data not available"

        # Spread explanation
        if spread < 0.15:
            explanations["spread"] = f"{spread:.3f}: Strong scorer agreement (high confidence)"
        elif spread < 0.25:
            explanations["spread"] = f"{spread:.3f}: Moderate scorer agreement"
        else:
            explanations["spread"] = f"{spread:.3f}: Significant scorer disagreement (review recommended)"

        # Anomaly explanation
        if anomaly_score > 0.7:
            explanations["anomaly"] = f"{anomaly_score:.2f}: Strong statistical anomaly - unusual behavior"
        elif anomaly_score > 0.4:
            explanations["anomaly"] = f"{anomaly_score:.2f}: Moderate anomaly - warrants attention"
        elif anomaly_score > 0:
            explanations["anomaly"] = f"{anomaly_score:.2f}: Minor anomaly - within tolerance"
        else:
            explanations["anomaly"] = "0.00: No anomaly detected - normal traffic pattern"

        return explanations

    def _update_baseline(self, ip: str, threat_score: float, confidence: float) -> None:
        """Update baseline statistics for IP"""
        if ip not in self._ip_baseline:
            self._ip_baseline[ip] = {
                'count': 0,
                'threat_sum': 0.0,
                'conf_sum': 0.0,
                'last_seen': 0.0,
            }

        baseline = self._ip_baseline[ip]
        baseline['count'] += 1
        baseline['threat_sum'] += threat_score
        baseline['conf_sum'] += confidence
        baseline['last_seen'] = time.time()

        # Cleanup old entries if baseline gets too large
        if len(self._ip_baseline) > 5000:
            # Remove oldest 20%
            sorted_ips = sorted(
                self._ip_baseline.items(),
                key=lambda x: x[1]['last_seen']
            )
            for ip, _ in sorted_ips[:len(sorted_ips) // 5]:
                del self._ip_baseline[ip]

    def get_statistics(self) -> Dict:
        """Get verification statistics"""
        return {
            "total_verifications": self.total_verifications,
            "verified_count": self.verified_count,
            "flagged_count": self.flagged_count,
            "unknown_count": self.unknown_count,
            "verified_rate": self.verified_count / max(self.total_verifications, 1),
            "flagged_rate": self.flagged_count / max(self.total_verifications, 1),
            "baseline_ips": len(self._ip_baseline),
        }


# Singleton instance for global access
_verification_engine: Optional[VerificationEngine] = None


def get_verification_engine() -> VerificationEngine:
    """Get or create the global verification engine instance"""
    global _verification_engine
    if _verification_engine is None:
        _verification_engine = VerificationEngine()
    return _verification_engine
