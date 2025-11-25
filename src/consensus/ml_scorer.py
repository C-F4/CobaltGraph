"""
Machine Learning Threat Scorer
Uses simple ML classifier for threat assessment

Approach:
- Feature engineering from threat intel + metadata
- Simple logistic regression (no external ML deps for now)
- Probabilistic scoring
- Can be upgraded to more sophisticated models later
"""

import math
import time
from typing import Dict

from .scorer_base import ScorerAssessment, ThreatScorer


class MLScorer(ThreatScorer):
    """
    Machine learning-based threat scorer

    Current implementation: Simple feature-based scoring
    Future: Can integrate sklearn, pytorch, etc.

    Features used:
    - Threat intelligence metrics
    - Port patterns
    - Geographic indicators
    - Connection frequency
    """

    def __init__(self):
        super().__init__(scorer_id="ml_based")

        # Simple learned weights (would come from training in production)
        # These are placeholder values for demonstration
        self.weights = {
            "vt_ratio": 0.4,
            "abuseipdb_conf": 0.35,
            "port_entropy": 0.15,
            "geo_risk": 0.1,
        }
        self.bias = -0.2

    def _sigmoid(self, x: float) -> float:
        """Sigmoid activation function"""
        return 1.0 / (1.0 + math.exp(-x))

    def _extract_features(
        self, dst_ip: str, threat_intel: Dict, geo_data: Dict, connection_metadata: Dict
    ) -> Dict[str, float]:
        """
        Extract numerical features for ML model

        Returns:
            Dictionary of feature_name -> normalized_value (0.0-1.0)
        """
        features = {}

        # Feature 1: VirusTotal ratio
        vt_data = threat_intel.get("virustotal", {})
        vt_malicious = vt_data.get("malicious_vendors", 0)
        vt_total = vt_data.get("total_vendors", 1)
        features["vt_ratio"] = vt_malicious / max(vt_total, 1)

        # Feature 2: AbuseIPDB confidence
        abuseipdb_data = threat_intel.get("abuseipdb", {})
        features["abuseipdb_conf"] = abuseipdb_data.get("confidence_score", 0) / 100.0

        # Feature 3: Port entropy (measure of port "unusualness")
        dst_port = connection_metadata.get("dst_port", 0)
        common_ports = [80, 443, 22, 21, 25, 53, 110, 143]

        if dst_port in common_ports:
            port_entropy = 0.1  # Low entropy = common port
        elif dst_port < 1024:
            port_entropy = 0.3  # Well-known ports
        elif dst_port < 49152:
            port_entropy = 0.6  # Registered ports
        else:
            port_entropy = 0.8  # Dynamic/private ports

        features["port_entropy"] = port_entropy

        # Feature 4: Geographic risk (simplified)
        country_code = geo_data.get("country_code", "")
        high_risk_countries = {"CN", "RU", "KP", "IR"}

        if country_code in high_risk_countries:
            features["geo_risk"] = 0.8
        elif country_code in {"US", "GB", "DE", "FR", "CA"}:
            features["geo_risk"] = 0.2  # Lower risk
        else:
            features["geo_risk"] = 0.5  # Neutral

        return features

    def _predict_score(self, features: Dict[str, float]) -> float:
        """
        Simple linear model prediction

        score = sigmoid(w1*f1 + w2*f2 + ... + bias)

        In production, this would load a trained model
        """
        # Linear combination
        linear_sum = self.bias

        for feature_name, weight in self.weights.items():
            feature_value = features.get(feature_name, 0.0)
            linear_sum += weight * feature_value

        # Apply sigmoid to get probability (0.0 - 1.0)
        probability = self._sigmoid(linear_sum)

        return probability

    def assess(
        self, dst_ip: str, threat_intel: Dict, geo_data: Dict, connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        ML-based assessment of threat level

        Process:
        1. Extract numerical features
        2. Run through model (simple linear for now)
        3. Output probability score
        """
        timestamp = time.time()

        # Extract features
        features = self._extract_features(dst_ip, threat_intel, geo_data, connection_metadata)

        # Predict threat score
        predicted_score = self._predict_score(features)

        # Confidence calculation
        # Based on feature completeness and model certainty
        feature_completeness = sum(1 for v in features.values() if v > 0) / len(features)

        # Model certainty: closer to 0.5 = less certain
        model_certainty = abs(predicted_score - 0.5) * 2.0

        confidence = (feature_completeness + model_certainty) / 2.0

        # Generate reasoning
        top_features = sorted(
            features.items(), key=lambda x: abs(x[1] * self.weights.get(x[0], 0)), reverse=True
        )[:3]

        reasoning_parts = [f"{name}={value:.2f}" for name, value in top_features]
        reasoning = (
            f"ML prediction: {predicted_score:.3f} (key features: {', '.join(reasoning_parts)})"
        )

        # Sign assessment
        signature = self._sign_assessment(predicted_score, confidence, timestamp)

        assessment = ScorerAssessment(
            scorer_id=self.scorer_id,
            score=predicted_score,
            confidence=confidence,
            reasoning=reasoning,
            features=features,
            timestamp=timestamp,
            signature=signature,
        )

        self._record_assessment(assessment)
        return assessment
