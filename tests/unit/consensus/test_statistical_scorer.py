#!/usr/bin/env python3
"""
Unit Tests: Statistical Scorer
Tests statistical analysis-based threat scoring
"""

import sys
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.consensus.statistical_scorer import StatisticalScorer


class TestStatisticalScorer(unittest.TestCase):
    """Test cases for StatisticalScorer"""

    def setUp(self):
        """Set up test fixtures"""
        self.scorer = StatisticalScorer()

    def test_initialization(self):
        """Test scorer initializes correctly"""
        self.assertEqual(self.scorer.scorer_id, 'statistical')
        self.assertIsNotNone(self.scorer.secret_key)
        self.assertEqual(self.scorer.assessments_made, 0)

    def test_clean_ip_scoring(self):
        """Test scoring of known clean IP (Google DNS)"""
        threat_intel = {
            'virustotal': {
                'malicious_vendors': 0,
                'total_vendors': 84,
            },
            'abuseipdb': {
                'confidence_score': 0,
                'total_reports': 0,
            }
        }

        assessment = self.scorer.assess(
            dst_ip="8.8.8.8",
            threat_intel=threat_intel,
            geo_data={'country': 'United States'},
            connection_metadata={'dst_port': 443}
        )

        # Should be low score (clean IP)
        self.assertLess(assessment.score, 0.3, "Clean IP should have low score")
        self.assertGreater(assessment.confidence, 0.5, "Should have reasonable confidence")
        self.assertEqual(assessment.scorer_id, 'statistical')
        self.assertIsNotNone(assessment.signature)

    def test_malicious_ip_scoring(self):
        """Test scoring of malicious IP"""
        threat_intel = {
            'virustotal': {
                'malicious_vendors': 15,
                'total_vendors': 84,
            },
            'abuseipdb': {
                'confidence_score': 95,
                'total_reports': 50,
            }
        }

        assessment = self.scorer.assess(
            dst_ip="198.51.100.1",
            threat_intel=threat_intel,
            geo_data={'country': 'Russia'},
            connection_metadata={'dst_port': 3389}
        )

        # Should be high score (malicious IP)
        self.assertGreater(assessment.score, 0.5, "Malicious IP should have high score")
        self.assertIn('VT:', assessment.reasoning)
        self.assertIn('AbuseIPDB:', assessment.reasoning)

    def test_missing_data_handling(self):
        """Test handling of missing threat intel data"""
        assessment = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel={},  # No data
            geo_data={},
            connection_metadata={'dst_port': 80}
        )

        # Should still produce valid assessment
        self.assertIsNotNone(assessment.score)
        self.assertGreaterEqual(assessment.score, 0.0)
        self.assertLessEqual(assessment.score, 1.0)
        self.assertGreater(assessment.confidence, 0.0)

    def test_signature_verification(self):
        """Test cryptographic signature verification"""
        assessment = self.scorer.assess(
            dst_ip="8.8.8.8",
            threat_intel={},
            geo_data={},
            connection_metadata={'dst_port': 443}
        )

        # Signature should verify
        is_valid = assessment.verify_signature(self.scorer.secret_key)
        self.assertTrue(is_valid, "Signature verification should succeed")

    def test_signature_tampering_detection(self):
        """Test detection of tampered signatures"""
        assessment = self.scorer.assess(
            dst_ip="8.8.8.8",
            threat_intel={},
            geo_data={},
            connection_metadata={'dst_port': 443}
        )

        # Tamper with score
        assessment.score = 0.99

        # Signature should NOT verify
        is_valid = assessment.verify_signature(self.scorer.secret_key)
        self.assertFalse(is_valid, "Tampered signature should be detected")

    def test_common_port_detection(self):
        """Test common port identification"""
        common_ports = [80, 443, 22, 53]

        for port in common_ports:
            assessment = self.scorer.assess(
                dst_ip="1.1.1.1",
                threat_intel={},
                geo_data={},
                connection_metadata={'dst_port': port}
            )

            self.assertIn('is_common_port', assessment.features)
            self.assertTrue(assessment.features['is_common_port'])

    def test_uncommon_port_detection(self):
        """Test uncommon port identification"""
        uncommon_ports = [8888, 31337, 54321]

        for port in uncommon_ports:
            assessment = self.scorer.assess(
                dst_ip="1.1.1.1",
                threat_intel={},
                geo_data={},
                connection_metadata={'dst_port': port}
            )

            self.assertIn('is_common_port', assessment.features)
            self.assertFalse(assessment.features['is_common_port'])

    def test_accuracy_tracking(self):
        """Test accuracy tracking with ground truth"""
        # Initial accuracy should be 0 (no data)
        self.assertEqual(self.scorer.get_accuracy(), 0.0)

        # Add correct predictions
        self.scorer.update_accuracy(predicted_score=0.8, actual_outcome=True)
        self.scorer.update_accuracy(predicted_score=0.2, actual_outcome=False)

        # Accuracy should be 100% (2/2 correct)
        self.assertEqual(self.scorer.get_accuracy(), 1.0)

        # Add incorrect prediction
        self.scorer.update_accuracy(predicted_score=0.8, actual_outcome=False)

        # Accuracy should be 66% (2/3 correct)
        self.assertAlmostEqual(self.scorer.get_accuracy(), 0.666, places=2)

    def test_feature_extraction(self):
        """Test that all expected features are extracted"""
        threat_intel = {
            'virustotal': {
                'malicious_vendors': 5,
                'total_vendors': 84,
            },
            'abuseipdb': {
                'confidence_score': 50,
                'total_reports': 10,
            }
        }

        assessment = self.scorer.assess(
            dst_ip="1.2.3.4",
            threat_intel=threat_intel,
            geo_data={},
            connection_metadata={'dst_port': 8080}
        )

        # Check all expected features exist
        expected_features = ['vt_malicious_ratio', 'abuseipdb_confidence',
                            'abuseipdb_reports', 'is_common_port']
        for feature in expected_features:
            self.assertIn(feature, assessment.features)


if __name__ == '__main__':
    unittest.main(verbosity=2)
