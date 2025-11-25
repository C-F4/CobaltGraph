#!/usr/bin/env python3
"""
Unit Tests: Rule-Based Scorer
Tests expert heuristic-based threat scoring
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.consensus.rule_scorer import RuleScorer


class TestRuleScorer(unittest.TestCase):
    """Test cases for RuleScorer"""

    def setUp(self):
        """Set up test fixtures"""
        self.scorer = RuleScorer()

    def test_initialization(self):
        """Test scorer initializes with rules"""
        self.assertEqual(self.scorer.scorer_id, 'rule_based')
        self.assertGreater(len(self.scorer.HIGH_RISK_PORTS), 0)
        self.assertGreater(len(self.scorer.MEDIUM_RISK_PORTS), 0)

    def test_high_risk_port_detection(self):
        """Test high-risk port rules (RDP, SMB, etc.)"""
        high_risk_ports = [3389, 445, 135, 1433]

        for port in high_risk_ports:
            assessment = self.scorer.assess(
                dst_ip="1.2.3.4",
                threat_intel={},
                geo_data={},
                connection_metadata={'dst_port': port}
            )

            # Should trigger high risk rule
            self.assertGreater(assessment.score, 0.2,
                             f"Port {port} should be flagged as risky")
            self.assertIn('HIGH_RISK_PORT', assessment.reasoning)
            self.assertEqual(assessment.features['port_risk'], 'high')

    def test_medium_risk_port_detection(self):
        """Test medium-risk port rules (FTP, Telnet, etc.)"""
        medium_risk_ports = [21, 23, 25, 8080]

        for port in medium_risk_ports:
            assessment = self.scorer.assess(
                dst_ip="1.2.3.4",
                threat_intel={},
                geo_data={},
                connection_metadata={'dst_port': port}
            )

            # Should trigger medium risk rule
            self.assertGreater(assessment.score, 0.0)
            self.assertEqual(assessment.features['port_risk'], 'medium')

    def test_virustotal_threshold_rules(self):
        """Test VirusTotal threshold rules"""
        # High threshold (>= 5 vendors)
        assessment_high = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={
                'virustotal': {'malicious_vendors': 10, 'total_vendors': 84}
            },
            geo_data={},
            connection_metadata={'dst_port': 443}
        )

        self.assertGreater(assessment_high.score, 0.5)
        self.assertIn('VT_HIGH_THREAT', assessment_high.reasoning)

        # Medium threshold (2-4 vendors)
        assessment_med = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={
                'virustotal': {'malicious_vendors': 3, 'total_vendors': 84}
            },
            geo_data={},
            connection_metadata={'dst_port': 443}
        )

        self.assertIn('VT_MED_THREAT', assessment_med.reasoning)

    def test_abuseipdb_threshold_rules(self):
        """Test AbuseIPDB confidence threshold rules"""
        # High confidence (>= 75%)
        assessment_high = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={
                'abuseipdb': {'confidence_score': 90, 'total_reports': 20}
            },
            geo_data={},
            connection_metadata={'dst_port': 443}
        )

        self.assertGreater(assessment_high.score, 0.4)
        self.assertIn('ABUSEIPDB_HIGH', assessment_high.reasoning)

        # Medium confidence (50-74%)
        assessment_med = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={
                'abuseipdb': {'confidence_score': 60, 'total_reports': 10}
            },
            geo_data={},
            connection_metadata={'dst_port': 443}
        )

        self.assertIn('ABUSEIPDB_MED', assessment_med.reasoning)

    def test_geographic_risk_rules(self):
        """Test geographic risk assessment rules"""
        high_risk_countries = ['CN', 'RU', 'KP']

        for country_code in high_risk_countries:
            assessment = self.scorer.assess(
                dst_ip="1.2.3.4",
                threat_intel={},
                geo_data={'country_code': country_code},
                connection_metadata={'dst_port': 443}
            )

            self.assertGreater(assessment.score, 0.0)
            self.assertIn('HIGH_RISK_GEO', assessment.reasoning)
            self.assertEqual(assessment.features['geo_risk'], 'high')

    def test_whitelist_override(self):
        """Test whitelisted IPs reduce score"""
        # Malicious signals but whitelisted
        assessment = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={
                'virustotal': {'malicious_vendors': 10, 'total_vendors': 84},
                'abuseipdb': {'confidence_score': 90, 'is_whitelisted': True}
            },
            geo_data={},
            connection_metadata={'dst_port': 3389}
        )

        # Whitelist should reduce score significantly
        self.assertIn('WHITELISTED', assessment.reasoning)
        self.assertTrue(assessment.features.get('whitelisted', False))

    def test_combined_rules_scoring(self):
        """Test combination of multiple rules"""
        # Multiple threat indicators
        assessment = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={
                'virustotal': {'malicious_vendors': 8, 'total_vendors': 84},
                'abuseipdb': {'confidence_score': 85, 'total_reports': 30}
            },
            geo_data={'country_code': 'RU'},
            connection_metadata={'dst_port': 3389}
        )

        # Should trigger multiple rules
        self.assertGreater(assessment.score, 0.7,
                          "Multiple threat indicators should produce high score")
        self.assertGreater(assessment.confidence, 0.8)

    def test_clean_ip_minimal_score(self):
        """Test clean IP produces minimal score"""
        assessment = self.scorer.assess(
            dst_ip="8.8.8.8",
            threat_intel={
                'virustotal': {'malicious_vendors': 0, 'total_vendors': 84},
                'abuseipdb': {'confidence_score': 0, 'total_reports': 0}
            },
            geo_data={'country_code': 'US'},
            connection_metadata={'dst_port': 443}
        )

        self.assertEqual(assessment.score, 0.0, "Clean IP should have zero score")
        self.assertIn('No threat rules triggered', assessment.reasoning)

    def test_score_capped_at_one(self):
        """Test score never exceeds 1.0"""
        # Extreme threat signals
        assessment = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={
                'virustotal': {'malicious_vendors': 50, 'total_vendors': 84},
                'abuseipdb': {'confidence_score': 100, 'total_reports': 1000}
            },
            geo_data={'country_code': 'KP'},
            connection_metadata={'dst_port': 3389}
        )

        self.assertLessEqual(assessment.score, 1.0, "Score must not exceed 1.0")


if __name__ == '__main__':
    unittest.main(verbosity=2)
