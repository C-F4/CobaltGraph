"""
Rule-Based Threat Scorer
Uses expert-defined heuristics and rules

Approach:
- Pattern matching on known threat indicators
- Port-based classification
- Geographic risk assessment
- Deterministic rule evaluation
"""

import time
from typing import Dict

from .scorer_base import ThreatScorer, ScorerAssessment


class RuleScorer(ThreatScorer):
    """
    Expert rule-based threat scorer

    Features:
    - Known malicious port detection
    - Geographic risk zones
    - Threat intelligence thresholds
    - Explicit rule-based reasoning
    """

    # Known high-risk ports (commonly exploited)
    HIGH_RISK_PORTS = {
        3389,  # RDP
        445,   # SMB
        135,   # RPC
        139,   # NetBIOS
        1433,  # MSSQL
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017, # MongoDB
    }

    # Medium risk ports
    MEDIUM_RISK_PORTS = {
        21,    # FTP
        23,    # Telnet
        25,    # SMTP
        110,   # POP3
        143,   # IMAP
        8080,  # HTTP alt
        8443,  # HTTPS alt
    }

    # High-risk countries (for demonstration - adjust based on your threat model)
    HIGH_RISK_COUNTRIES = {
        'CN',  # China
        'RU',  # Russia
        'KP',  # North Korea
    }

    def __init__(self):
        super().__init__(scorer_id='rule_based')

    def assess(
        self,
        dst_ip: str,
        threat_intel: Dict,
        geo_data: Dict,
        connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        Rule-based assessment of threat level

        Applies explicit rules:
        1. Threat intelligence thresholds
        2. Port-based risk classification
        3. Geographic risk assessment
        4. Combined heuristic scoring
        """
        timestamp = time.time()
        features = {}
        rules_triggered = []
        base_score = 0.0

        # Rule 1: VirusTotal threshold
        vt_data = threat_intel.get('virustotal', {})
        vt_malicious = vt_data.get('malicious_vendors', 0)

        if vt_malicious >= 5:
            base_score += 0.6
            rules_triggered.append(f"VT_HIGH_THREAT({vt_malicious} vendors)")
            features['vt_rule'] = 'high_threat'
        elif vt_malicious >= 2:
            base_score += 0.3
            rules_triggered.append(f"VT_MED_THREAT({vt_malicious} vendors)")
            features['vt_rule'] = 'medium_threat'

        # Rule 2: AbuseIPDB threshold
        abuseipdb_data = threat_intel.get('abuseipdb', {})
        abuse_confidence = abuseipdb_data.get('confidence_score', 0)

        if abuse_confidence >= 75:
            base_score += 0.5
            rules_triggered.append(f"ABUSEIPDB_HIGH({abuse_confidence}%)")
            features['abuseipdb_rule'] = 'high_confidence'
        elif abuse_confidence >= 50:
            base_score += 0.25
            rules_triggered.append(f"ABUSEIPDB_MED({abuse_confidence}%)")
            features['abuseipdb_rule'] = 'medium_confidence'

        # Rule 3: Port-based risk
        dst_port = connection_metadata.get('dst_port', 0)

        if dst_port in self.HIGH_RISK_PORTS:
            base_score += 0.3
            rules_triggered.append(f"HIGH_RISK_PORT({dst_port})")
            features['port_risk'] = 'high'
        elif dst_port in self.MEDIUM_RISK_PORTS:
            base_score += 0.15
            rules_triggered.append(f"MED_RISK_PORT({dst_port})")
            features['port_risk'] = 'medium'
        else:
            features['port_risk'] = 'low'

        # Rule 4: Geographic risk
        country_code = geo_data.get('country_code', '')

        if country_code in self.HIGH_RISK_COUNTRIES:
            base_score += 0.2
            rules_triggered.append(f"HIGH_RISK_GEO({country_code})")
            features['geo_risk'] = 'high'
        else:
            features['geo_risk'] = 'low'

        # Rule 5: Whitelisted IPs (trusted services)
        if abuseipdb_data.get('is_whitelisted', False):
            base_score = max(0.0, base_score - 0.5)
            rules_triggered.append("WHITELISTED")
            features['whitelisted'] = True

        # Cap score at 1.0
        final_score = min(1.0, base_score)

        # Confidence calculation
        # Rule-based is deterministic, so confidence is based on data availability
        confidence = 0.7  # Base confidence for rules

        if vt_malicious > 0 or abuse_confidence > 0:
            confidence = 0.9  # Higher confidence with threat intel
        elif dst_port in (self.HIGH_RISK_PORTS | self.MEDIUM_RISK_PORTS):
            confidence = 0.8  # Moderate confidence with port heuristics

        # Generate reasoning
        if rules_triggered:
            reasoning = "Rules triggered: " + ", ".join(rules_triggered)
        else:
            reasoning = "No threat rules triggered (clean)"

        # Sign assessment
        signature = self._sign_assessment(final_score, confidence, timestamp)

        assessment = ScorerAssessment(
            scorer_id=self.scorer_id,
            score=final_score,
            confidence=confidence,
            reasoning=reasoning,
            features=features,
            timestamp=timestamp,
            signature=signature
        )

        self._record_assessment(assessment)
        return assessment
