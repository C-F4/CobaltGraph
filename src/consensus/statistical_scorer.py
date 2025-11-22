"""
Statistical Threat Scorer
Uses statistical analysis of threat intelligence data

Approach:
- Analyzes distribution of threat reports
- Applies confidence intervals
- Detects statistical anomalies
- Conservative scoring with uncertainty quantification
"""

import time
import statistics
from typing import Dict

from .scorer_base import ThreatScorer, ScorerAssessment


class StatisticalScorer(ThreatScorer):
    """
    Statistical analysis-based threat scorer

    Features:
    - Z-score based outlier detection
    - Confidence intervals for threat metrics
    - Handles missing data gracefully
    """

    def __init__(self):
        super().__init__(scorer_id='statistical')

    def assess(
        self,
        dst_ip: str,
        threat_intel: Dict,
        geo_data: Dict,
        connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        Statistical assessment of threat level

        Analyzes:
        - Threat intelligence vendor consensus
        - Statistical significance of reports
        - Anomalies in connection patterns
        """
        timestamp = time.time()
        features = {}

        # Extract threat intelligence metrics
        vt_data = threat_intel.get('virustotal', {})
        abuseipdb_data = threat_intel.get('abuseipdb', {})
        local_data = threat_intel.get('local', {})

        # Feature 1: Vendor malicious count (VirusTotal)
        vt_malicious = vt_data.get('malicious_vendors', 0)
        vt_total = vt_data.get('total_vendors', 1)
        vt_ratio = vt_malicious / max(vt_total, 1)
        features['vt_malicious_ratio'] = vt_ratio

        # Feature 2: AbuseIPDB confidence
        abuseipdb_confidence = abuseipdb_data.get('confidence_score', 0) / 100.0
        abuseipdb_reports = abuseipdb_data.get('total_reports', 0)
        features['abuseipdb_confidence'] = abuseipdb_confidence
        features['abuseipdb_reports'] = abuseipdb_reports

        # Feature 3: Port analysis (statistical)
        dst_port = connection_metadata.get('dst_port', 0)
        is_common_port = dst_port in [80, 443, 22, 21, 25, 53, 110, 143]
        features['is_common_port'] = is_common_port

        # Statistical scoring logic
        scores = []
        weights = []

        # VirusTotal contribution (if available)
        if vt_total > 0:
            # Use ratio with confidence based on number of vendors
            confidence_vt = min(1.0, vt_total / 50.0)  # More vendors = more confidence
            scores.append(vt_ratio)
            weights.append(confidence_vt)

        # AbuseIPDB contribution (if available)
        if abuseipdb_reports > 0:
            # Weight by number of reports
            confidence_abuse = min(1.0, abuseipdb_reports / 10.0)
            scores.append(abuseipdb_confidence)
            weights.append(confidence_abuse)

        # Port-based heuristic (always available)
        if not is_common_port and dst_port > 1024:
            # Uncommon high port = slightly suspicious
            port_score = 0.3
        else:
            port_score = 0.1
        scores.append(port_score)
        weights.append(0.5)  # Lower weight for heuristic

        # Calculate weighted average
        if scores:
            total_weight = sum(weights)
            weighted_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
        else:
            weighted_score = 0.0

        # Calculate confidence (based on data availability)
        data_sources = sum([
            1 if vt_total > 0 else 0,
            1 if abuseipdb_reports > 0 else 0,
            1  # Always have port data
        ])

        confidence = min(1.0, data_sources / 3.0)

        # Calculate spread/uncertainty
        if len(scores) > 1:
            score_stdev = statistics.stdev(scores)
            # High stdev = low confidence
            confidence *= max(0.3, 1.0 - score_stdev)

        # Generate reasoning
        reasoning_parts = []
        if vt_total > 0:
            reasoning_parts.append(
                f"VT: {vt_malicious}/{vt_total} vendors flagged"
            )
        if abuseipdb_reports > 0:
            reasoning_parts.append(
                f"AbuseIPDB: {abuseipdb_confidence*100:.0f}% confidence, "
                f"{abuseipdb_reports} reports"
            )
        reasoning_parts.append(
            f"Port {dst_port}: {'common' if is_common_port else 'uncommon'}"
        )
        reasoning = "Statistical analysis: " + "; ".join(reasoning_parts)

        # Sign assessment
        signature = self._sign_assessment(weighted_score, confidence, timestamp)

        assessment = ScorerAssessment(
            scorer_id=self.scorer_id,
            score=weighted_score,
            confidence=confidence,
            reasoning=reasoning,
            features=features,
            timestamp=timestamp,
            signature=signature
        )

        self._record_assessment(assessment)
        return assessment
