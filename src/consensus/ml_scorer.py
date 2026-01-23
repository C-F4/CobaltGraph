"""
Machine Learning Threat Scorer
Uses simple ML classifier for threat assessment

Approach:
- Feature engineering from threat intel + metadata
- Simple logistic regression (no external ML deps for now)
- Probabilistic scoring
- Hostname/domain analysis features (DGA detection, entropy)
- Can be upgraded to more sophisticated models later
"""

import math
import re
import time
from typing import Dict, Optional

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
    - Hostname/domain characteristics
    - TCP connection patterns
    - Connection frequency
    """

    # Character frequency for English language (approximate)
    # Used for detecting non-English/random domain names
    ENGLISH_CHAR_FREQ = {
        'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
        'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
        'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
        'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
        'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001,
        'z': 0.001,
    }

    def __init__(self):
        super().__init__(scorer_id="ml_based")

        # Expanded weights including hostname features
        # These are placeholder values for demonstration
        # Positive weights increase threat score, negative weights decrease it
        self.weights = {
            # Primary threat indicators
            "vt_ratio": 0.35,
            "abuseipdb_conf": 0.30,
            "port_entropy": 0.08,
            "geo_risk": 0.06,
            # Hostname/domain features (DGA detection)
            "hostname_entropy": 0.08,
            "hostname_length_risk": 0.04,
            "hostname_digit_ratio": 0.03,
            "hostname_consonant_ratio": 0.02,
            # TCP pattern indicator
            "tcp_scan_indicator": 0.10,
            # Local IOC match
            "local_ioc_indicator": 0.15,
            # GreyNoise benign indicator (NEGATIVE - reduces score)
            "greynoise_benign": -0.25,
        }
        self.bias = -0.2

    def _sigmoid(self, x: float) -> float:
        """Sigmoid activation function"""
        return 1.0 / (1.0 + math.exp(-x))

    def _calculate_hostname_entropy(self, hostname: str) -> float:
        """
        Calculate Shannon entropy of hostname for DGA detection

        Higher entropy suggests randomly generated domain names.
        Returns value normalized to 0-1 range.
        """
        if not hostname:
            return 0.0

        # Extract main part (remove TLD)
        parts = hostname.lower().split(".")
        if len(parts) > 1:
            main_part = ".".join(parts[:-1])  # Everything except TLD
        else:
            main_part = hostname

        if len(main_part) < 3:
            return 0.0

        # Calculate character frequency
        freq = {}
        for char in main_part:
            if char.isalnum():
                freq[char] = freq.get(char, 0) + 1

        if not freq:
            return 0.0

        # Calculate entropy
        length = sum(freq.values())
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        # Normalize: max entropy for random alphanumeric is ~log2(36) ≈ 5.17
        # Return as 0-1 where higher = more suspicious
        normalized = min(1.0, entropy / 5.17)
        return normalized

    def _calculate_hostname_length_risk(self, hostname: str) -> float:
        """
        Calculate risk based on hostname length

        Very short or very long hostnames can be suspicious.
        Returns 0-1 where higher = more suspicious.
        """
        if not hostname:
            return 0.0

        # Extract main part
        parts = hostname.lower().split(".")
        main_part = parts[0] if parts else hostname
        length = len(main_part)

        # Normal domain names are typically 4-15 characters
        if length < 4:
            return 0.3  # Suspiciously short
        elif length > 20:
            return min(1.0, (length - 20) / 30 + 0.4)  # Long domains are suspicious
        elif length > 15:
            return (length - 15) / 20  # Moderately elevated
        else:
            return 0.0  # Normal length

    def _calculate_digit_ratio(self, hostname: str) -> float:
        """
        Calculate ratio of digits to total alphanumeric characters

        High digit ratio can indicate DGA or randomized domains.
        Returns 0-1 where higher = more suspicious.
        """
        if not hostname:
            return 0.0

        parts = hostname.lower().split(".")
        main_part = parts[0] if parts else hostname

        if not main_part:
            return 0.0

        alnum_count = sum(1 for c in main_part if c.isalnum())
        digit_count = sum(1 for c in main_part if c.isdigit())

        if alnum_count == 0:
            return 0.0

        ratio = digit_count / alnum_count

        # Normal domains have few or no digits
        # Return normalized risk score
        if ratio > 0.5:
            return min(1.0, ratio)
        elif ratio > 0.3:
            return ratio * 0.8
        else:
            return ratio * 0.3

    def _calculate_consonant_ratio(self, hostname: str) -> float:
        """
        Calculate consonant to vowel ratio

        Unpronounceable domains (high consonant ratio) can indicate DGA.
        Returns 0-1 where higher = more suspicious.
        """
        if not hostname:
            return 0.0

        parts = hostname.lower().split(".")
        main_part = parts[0] if parts else hostname

        vowels = set("aeiou")
        vowel_count = 0
        consonant_count = 0

        for char in main_part:
            if char.isalpha():
                if char in vowels:
                    vowel_count += 1
                else:
                    consonant_count += 1

        total_letters = vowel_count + consonant_count
        if total_letters < 4:
            return 0.0

        # Normal English has roughly 40% vowels
        vowel_ratio = vowel_count / total_letters

        # Very low or very high vowel ratio is suspicious
        if vowel_ratio < 0.15:  # Almost all consonants
            return 0.8
        elif vowel_ratio < 0.25:
            return 0.5
        elif vowel_ratio > 0.7:  # Almost all vowels (unusual)
            return 0.4
        else:
            return 0.0

    def _extract_hostname_features(self, connection_metadata: Dict) -> Dict[str, float]:
        """
        Extract all hostname-related features

        Uses TLS SNI or DNS query as hostname source.
        Returns dictionary of feature_name -> normalized_value
        """
        features = {}

        # Get hostname from metadata
        hostname = connection_metadata.get("tls_sni") or connection_metadata.get("dns_query")

        if not hostname:
            # No hostname data - return zeros
            features["hostname_entropy"] = 0.0
            features["hostname_length_risk"] = 0.0
            features["hostname_digit_ratio"] = 0.0
            features["hostname_consonant_ratio"] = 0.0
            return features

        # Calculate hostname features
        features["hostname_entropy"] = self._calculate_hostname_entropy(hostname)
        features["hostname_length_risk"] = self._calculate_hostname_length_risk(hostname)
        features["hostname_digit_ratio"] = self._calculate_digit_ratio(hostname)
        features["hostname_consonant_ratio"] = self._calculate_consonant_ratio(hostname)

        return features

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
        country_code = geo_data.get("country", "")
        high_risk_countries = {"CN", "RU", "KP", "IR"}

        if country_code in high_risk_countries:
            features["geo_risk"] = 0.8
        elif country_code in {"US", "GB", "DE", "FR", "CA"}:
            features["geo_risk"] = 0.2  # Lower risk
        elif country_code in ("Unknown", ""):
            features["geo_risk"] = 0.6  # Elevated for unknown
        else:
            features["geo_risk"] = 0.5  # Neutral for other countries

        # Feature 5-8: Hostname/domain features (for DGA detection)
        hostname_features = self._extract_hostname_features(connection_metadata)
        features.update(hostname_features)

        # Feature 9: TCP scan pattern indicator
        if connection_metadata.get("tcp_is_scan", False):
            features["tcp_scan_indicator"] = 0.9
        elif connection_metadata.get("tcp_syn", False) and not connection_metadata.get("tcp_ack", False):
            features["tcp_scan_indicator"] = 0.6
        else:
            features["tcp_scan_indicator"] = 0.0

        # Feature 10: Local IOC match indicator
        if threat_intel.get("local_ioc_match"):
            features["local_ioc_indicator"] = 0.9
        else:
            features["local_ioc_indicator"] = 0.0

        # Feature 11: GreyNoise benign indicator (reduces score)
        if threat_intel.get("greynoise_riot") or threat_intel.get("greynoise_benign_scanner"):
            features["greynoise_benign"] = 0.8  # High = more likely benign
        else:
            features["greynoise_benign"] = 0.0

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
