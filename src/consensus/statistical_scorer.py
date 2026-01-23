"""
Statistical Threat Scorer
Uses statistical analysis of threat intelligence data

Approach:
- Analyzes distribution of threat reports
- Applies confidence intervals
- Detects statistical anomalies
- TCP connection state baseline tracking
- Domain diversity analysis
- Conservative scoring with uncertainty quantification
"""

import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .scorer_base import ScorerAssessment, ThreatScorer


@dataclass
class ConnectionBaseline:
    """Baseline statistics for a destination IP"""
    total_connections: int = 0
    completed_connections: int = 0  # SYN-ACK or established
    failed_connections: int = 0  # RST or no response
    unique_domains: Set[str] = field(default_factory=set)
    recent_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    last_seen: float = 0.0


class StatisticalScorer(ThreatScorer):
    """
    Statistical analysis-based threat scorer

    Features:
    - Z-score based outlier detection
    - Confidence intervals for threat metrics
    - TCP connection completion rate tracking
    - Domain diversity per IP analysis
    - Handles missing data gracefully
    """

    # Baseline configuration
    BASELINE_CACHE_SIZE = 5000
    BASELINE_CACHE_TTL = 3600  # 1 hour

    def __init__(self):
        super().__init__(scorer_id="statistical")

        # Connection baseline tracking per destination IP
        self._baselines: Dict[str, ConnectionBaseline] = {}
        self._baseline_last_cleanup = time.time()

    def _get_or_create_baseline(self, dst_ip: str) -> ConnectionBaseline:
        """Get or create baseline statistics for a destination IP"""
        if dst_ip not in self._baselines:
            self._baselines[dst_ip] = ConnectionBaseline()

        # Periodic cleanup of old baselines
        now = time.time()
        if now - self._baseline_last_cleanup > 300:  # Every 5 minutes
            self._cleanup_baselines(now)
            self._baseline_last_cleanup = now

        return self._baselines[dst_ip]

    def _cleanup_baselines(self, now: float):
        """Remove stale baseline entries"""
        if len(self._baselines) <= self.BASELINE_CACHE_SIZE:
            return

        # Remove entries older than TTL
        cutoff = now - self.BASELINE_CACHE_TTL
        stale_keys = [k for k, v in self._baselines.items() if v.last_seen < cutoff]

        for key in stale_keys:
            del self._baselines[key]

        # If still too large, remove oldest entries
        if len(self._baselines) > self.BASELINE_CACHE_SIZE:
            sorted_keys = sorted(
                self._baselines.keys(),
                key=lambda k: self._baselines[k].last_seen
            )
            for key in sorted_keys[:len(self._baselines) - self.BASELINE_CACHE_SIZE]:
                del self._baselines[key]

    def _update_baseline(
        self,
        dst_ip: str,
        tcp_state: Optional[str],
        domain: Optional[str],
        timestamp: float,
    ) -> ConnectionBaseline:
        """Update baseline statistics with new connection data"""
        baseline = self._get_or_create_baseline(dst_ip)

        baseline.total_connections += 1
        baseline.last_seen = timestamp
        baseline.recent_timestamps.append(timestamp)

        # Track TCP state
        if tcp_state:
            if tcp_state in ("SYN-ACK", "DATA", "ACK"):
                baseline.completed_connections += 1
            elif tcp_state in ("RST", "SYN"):
                # SYN-only or RST indicates failed/incomplete
                baseline.failed_connections += 1

        # Track domain diversity
        if domain:
            baseline.unique_domains.add(domain.lower())

        return baseline

    def _calculate_completion_rate_score(self, baseline: ConnectionBaseline) -> tuple[float, float]:
        """
        Calculate threat score based on connection completion rate

        Low completion rate (many failures) is suspicious.
        Returns (score_adjustment, confidence)
        """
        if baseline.total_connections < 5:
            # Not enough data
            return 0.0, 0.3

        completed = baseline.completed_connections
        failed = baseline.failed_connections
        total = completed + failed

        if total == 0:
            return 0.0, 0.3

        completion_rate = completed / total

        # Score adjustment based on completion rate
        if completion_rate < 0.2:
            # Very low completion - highly suspicious
            return 0.3, 0.8
        elif completion_rate < 0.4:
            # Low completion - moderately suspicious
            return 0.15, 0.7
        elif completion_rate < 0.6:
            # Moderate completion - slightly elevated
            return 0.05, 0.6
        else:
            # Good completion rate - slight trust boost
            return -0.05, 0.7

    def _calculate_domain_diversity_score(self, baseline: ConnectionBaseline) -> tuple[float, float]:
        """
        Calculate threat score based on domain diversity

        An IP serving many unrelated domains is suspicious (except CDNs).
        Returns (score_adjustment, confidence)
        """
        domain_count = len(baseline.unique_domains)
        conn_count = baseline.total_connections

        if conn_count < 3 or domain_count < 2:
            return 0.0, 0.3

        # Diversity ratio: unique domains per connection
        diversity_ratio = domain_count / conn_count

        # High diversity (many domains, few connections each) is suspicious
        if diversity_ratio > 0.8 and domain_count > 5:
            # Very high diversity - suspicious
            return 0.2, 0.7
        elif diversity_ratio > 0.5 and domain_count > 3:
            # Moderate diversity - slightly elevated
            return 0.1, 0.6
        else:
            return 0.0, 0.5

    def _calculate_connection_frequency_score(self, baseline: ConnectionBaseline) -> tuple[float, float]:
        """
        Analyze connection frequency patterns

        Highly regular intervals can indicate beaconing.
        Returns (score_adjustment, confidence)
        """
        timestamps = list(baseline.recent_timestamps)
        if len(timestamps) < 5:
            return 0.0, 0.3

        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            if 0.1 < interval < 3600:  # Between 100ms and 1 hour
                intervals.append(interval)

        if len(intervals) < 4:
            return 0.0, 0.3

        try:
            mean_interval = statistics.mean(intervals)
            stdev_interval = statistics.stdev(intervals)

            # Calculate coefficient of variation (CV)
            if mean_interval > 0:
                cv = stdev_interval / mean_interval
            else:
                return 0.0, 0.3

            # Very low CV = very regular = potential beaconing
            if cv < 0.1 and mean_interval < 300:  # <10% variation, <5 min interval
                return 0.25, 0.8  # Highly suspicious
            elif cv < 0.2 and mean_interval < 600:
                return 0.15, 0.7  # Moderately suspicious
            elif cv < 0.3:
                return 0.05, 0.6  # Slightly elevated
            else:
                return 0.0, 0.5  # Normal variation

        except statistics.StatisticsError:
            return 0.0, 0.3

    def assess(
        self, dst_ip: str, threat_intel: Dict, geo_data: Dict, connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        Statistical assessment of threat level

        Analyzes:
        - Threat intelligence vendor consensus
        - Statistical significance of reports
        - Connection completion rate baselines
        - Domain diversity per IP
        - Connection frequency patterns
        - Anomalies in connection patterns
        """
        timestamp = connection_metadata.get("timestamp", time.time())
        features = {}

        # Extract threat intelligence metrics
        vt_data = threat_intel.get("virustotal", {})
        abuseipdb_data = threat_intel.get("abuseipdb", {})

        # Feature 1: Vendor malicious count (VirusTotal)
        vt_malicious = vt_data.get("malicious_vendors", 0)
        vt_total = vt_data.get("total_vendors", 1)
        vt_ratio = vt_malicious / max(vt_total, 1)
        features["vt_malicious_ratio"] = vt_ratio

        # Feature 2: AbuseIPDB confidence
        abuseipdb_confidence = abuseipdb_data.get("confidence_score", 0) / 100.0
        abuseipdb_reports = abuseipdb_data.get("total_reports", 0)
        features["abuseipdb_confidence"] = abuseipdb_confidence
        features["abuseipdb_reports"] = abuseipdb_reports

        # Feature 3: Port analysis (statistical)
        dst_port = connection_metadata.get("dst_port", 0)
        is_common_port = dst_port in [80, 443, 22, 21, 25, 53, 110, 143]
        features["is_common_port"] = is_common_port

        # Feature 4: Extract protocol enrichment data
        tcp_state = connection_metadata.get("tcp_state")
        domain = connection_metadata.get("tls_sni") or connection_metadata.get("dns_query")

        # Update connection baseline for this destination
        baseline = self._update_baseline(dst_ip, tcp_state, domain, timestamp)
        features["baseline_total_connections"] = baseline.total_connections
        features["baseline_unique_domains"] = len(baseline.unique_domains)

        # Statistical scoring logic
        scores = []
        weights = []
        reasoning_parts = []

        # VirusTotal contribution (if available)
        if vt_total > 0:
            # Use ratio with confidence based on number of vendors
            confidence_vt = min(1.0, vt_total / 50.0)  # More vendors = more confidence
            scores.append(vt_ratio)
            weights.append(confidence_vt)
            reasoning_parts.append(f"VT: {vt_malicious}/{vt_total} vendors flagged")

        # AbuseIPDB contribution (if available)
        if abuseipdb_reports > 0:
            # Weight by number of reports
            confidence_abuse = min(1.0, abuseipdb_reports / 10.0)
            scores.append(abuseipdb_confidence)
            weights.append(confidence_abuse)
            reasoning_parts.append(
                f"AbuseIPDB: {abuseipdb_confidence*100:.0f}% confidence, "
                f"{abuseipdb_reports} reports"
            )

        # Port-based heuristic (always available)
        if not is_common_port and dst_port > 1024:
            # Uncommon high port = slightly suspicious
            port_score = 0.3
        else:
            port_score = 0.1
        scores.append(port_score)
        weights.append(0.5)  # Lower weight for heuristic
        reasoning_parts.append(f"Port {dst_port}: {'common' if is_common_port else 'uncommon'}")

        # Connection completion rate analysis
        completion_adj, completion_conf = self._calculate_completion_rate_score(baseline)
        if completion_adj != 0:
            if baseline.total_connections >= 5:
                completed = baseline.completed_connections
                failed = baseline.failed_connections
                total = completed + failed
                if total > 0:
                    rate = completed / total
                    features["completion_rate"] = rate
                    if completion_adj > 0:
                        scores.append(completion_adj)
                        weights.append(completion_conf * 0.7)
                        reasoning_parts.append(f"Completion rate: {rate:.0%}")

        # Domain diversity analysis
        diversity_adj, diversity_conf = self._calculate_domain_diversity_score(baseline)
        if diversity_adj > 0:
            features["domain_diversity_risk"] = diversity_adj
            scores.append(diversity_adj)
            weights.append(diversity_conf * 0.6)
            reasoning_parts.append(f"Domain diversity: {len(baseline.unique_domains)} domains")

        # Connection frequency analysis (beaconing detection)
        frequency_adj, frequency_conf = self._calculate_connection_frequency_score(baseline)
        if frequency_adj > 0:
            features["frequency_pattern_risk"] = frequency_adj
            features["potential_beaconing"] = True
            scores.append(frequency_adj)
            weights.append(frequency_conf * 0.8)
            reasoning_parts.append("Potential beaconing pattern detected")

        # Calculate weighted average
        if scores:
            total_weight = sum(weights)
            weighted_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
        else:
            weighted_score = 0.0

        # Calculate confidence (based on data availability)
        data_sources = sum(
            [
                1 if vt_total > 0 else 0,
                1 if abuseipdb_reports > 0 else 0,
                1,  # Always have port data
                0.5 if baseline.total_connections >= 5 else 0,  # Baseline data
            ]
        )

        confidence = min(1.0, data_sources / 3.5)

        # Calculate spread/uncertainty
        if len(scores) > 1:
            try:
                score_stdev = statistics.stdev(scores)
                # High stdev = low confidence
                confidence *= max(0.3, 1.0 - score_stdev)
            except statistics.StatisticsError:
                pass

        # Generate reasoning
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
            signature=signature,
        )

        self._record_assessment(assessment)
        return assessment
