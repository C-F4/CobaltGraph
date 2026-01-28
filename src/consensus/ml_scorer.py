"""
Feature-Weighted Heuristic Threat Scorer (Legacy ML Scorer)

This scorer uses expert-tuned feature weights with logistic regression
for deterministic, explainable threat scoring. It does NOT use actual
machine learning - the weights are manually defined based on domain knowledge.

For actual neural network-based ML scoring with learned weights, see:
- neural_scorer.py: NeuralScorer with GRU temporal learning
- neural_network.py: Pure Python neural network implementation

This heuristic scorer remains valuable as:
- Deterministic baseline (reproducible results)
- No training data required
- Explainable feature contributions
- Fast inference with no model loading

Approach:
- Feature engineering from threat intel + metadata
- Logistic regression with hand-tuned weights (sigmoid activation)
- Probabilistic scoring (0.0 - 1.0)
- Hostname/domain analysis features (DGA detection, entropy)
- Enhanced n-gram analysis for DGA detection
- OTX pulse intelligence integration
- PortServiceResolver high-risk port detection
"""

import math
import re
import time
from typing import Dict, Optional, Set

from .scorer_base import ScorerAssessment, ThreatScorer

# Import port service for high-risk detection
try:
    from src.services.port_service import PortServiceResolver
    PORT_SERVICE_AVAILABLE = True
except ImportError:
    PORT_SERVICE_AVAILABLE = False


class HeuristicScorer(ThreatScorer):
    """
    Heuristic feature-weighted threat scorer

    Uses expert-tuned weights with logistic regression for deterministic,
    explainable scoring. Provides a stable baseline that doesn't require
    training data.

    Features used:
    - Threat intelligence metrics (VirusTotal, AbuseIPDB)
    - Port patterns
    - Geographic indicators
    - Hostname/domain characteristics (DGA detection)
    - TCP connection patterns
    - GreyNoise benign indicators
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

    # Common English bigrams (character pairs) for n-gram DGA detection
    # Higher frequency = more likely legitimate English word
    ENGLISH_BIGRAMS = {
        'th': 0.0356, 'he': 0.0307, 'in': 0.0243, 'er': 0.0205, 'an': 0.0199,
        'on': 0.0176, 're': 0.0173, 'ed': 0.0168, 'nd': 0.0157, 'ha': 0.0156,
        'at': 0.0149, 'en': 0.0145, 'es': 0.0134, 'of': 0.0132, 'or': 0.0128,
        'nt': 0.0117, 'ea': 0.0113, 'ti': 0.0111, 'to': 0.0109, 'it': 0.0108,
        'st': 0.0105, 'io': 0.0102, 'le': 0.0102, 'is': 0.0098, 'ou': 0.0096,
        'ar': 0.0094, 'as': 0.0087, 'de': 0.0087, 'rt': 0.0086, 'co': 0.0079,
        'te': 0.0078, 'se': 0.0073, 'ng': 0.0069, 've': 0.0069, 'me': 0.0068,
        'ne': 0.0068, 'al': 0.0065, 'li': 0.0064, 'ra': 0.0063, 'ce': 0.0062,
    }

    # 3-tier geographic risk model based on threat intelligence
    # HIGH_RISK: Countries with significant state-sponsored APT activity
    HIGH_RISK_COUNTRIES: Set[str] = {
        "CN",  # China - APT1, APT10, APT41, etc.
        "RU",  # Russia - APT28, APT29, Sandworm, etc.
        "KP",  # North Korea - Lazarus, Kimsuky, etc.
        "IR",  # Iran - APT33, APT34, APT35, etc.
        "BY",  # Belarus - GhostWriter, UNC1151
        "VE",  # Venezuela - APT-C-36 activity
        "SY",  # Syria - Syrian Electronic Army
    }

    # ELEVATED_RISK: High cybercrime, weak regulations, or proxy states
    ELEVATED_RISK_COUNTRIES: Set[str] = {
        "UA",  # Ukraine - Both victim and crime origin
        "VN",  # Vietnam - OceanLotus/APT32
        "PK",  # Pakistan - APT36
        "BD",  # Bangladesh - Cyber crime origin
        "NG",  # Nigeria - Significant fraud/BEC origin
        "RO",  # Romania - Cybercrime hub
        "MD",  # Moldova - Cybercrime operations
        "BG",  # Bulgaria - Cybercrime operations
        "IN",  # India - Mixed threat landscape
        "PH",  # Philippines - BEC/fraud origin
        "ID",  # Indonesia - Growing threat actor presence
        "TH",  # Thailand - Proxy servers, mixed
        "MY",  # Malaysia - Cyber operations
        "BR",  # Brazil - Banking trojans, ransomware
        "MX",  # Mexico - Cartel-affiliated cyber operations
        "RS",  # Serbia - Cybercrime operations
        "LB",  # Lebanon - Volatile Cedars, Dark Caracal
    }

    # LOW_RISK: Established cyber defense, strong regulations
    LOW_RISK_COUNTRIES: Set[str] = {
        "US", "CA",  # North America
        "GB", "DE", "FR", "NL", "SE", "NO", "FI", "DK",  # Western Europe
        "CH", "AT", "BE", "IE", "LU",  # Central Europe
        "AU", "NZ",  # Oceania
        "JP", "KR", "SG",  # Asia Pacific (allied)
        "IL",  # Israel - strong cyber capability
        "EE",  # Estonia - NATO cyber center
    }

    # OTX critical tags indicating severe threats
    OTX_CRITICAL_TAGS: Set[str] = {
        "apt", "apt1", "apt10", "apt28", "apt29", "apt32", "apt33", "apt34",
        "apt35", "apt38", "apt41", "lazarus", "kimsuky", "sandworm", "cozy bear",
        "fancy bear", "turla", "equation group", "ransomware", "ryuk", "conti",
        "lockbit", "revil", "sodinokibi", "darkside", "blackcat", "alphv",
        "c2", "c&c", "command and control", "cobalt strike", "beacon",
        "emotet", "trickbot", "qakbot", "qbot", "dridex", "icedid",
        "botnet", "rat", "remote access trojan", "backdoor", "implant",
        "zero-day", "0day", "exploit", "cve-", "critical",
    }

    def __init__(self):
        super().__init__(scorer_id="heuristic")

        # Expert-tuned weights based on threat intelligence value
        # Positive weights increase threat score, negative weights decrease it
        self.weights = {
            # Primary threat indicators (high value intel)
            "vt_ratio": 0.40,           # VirusTotal is authoritative
            "abuseipdb_conf": 0.30,     # AbuseIPDB confidence
            "otx_pulse_risk": 0.25,     # OTX pulse count/tags (NEW)
            # Port-based risk (integrated with PortServiceResolver)
            "port_risk": 0.12,          # Replaces port_entropy (NEW)
            # Geographic risk (3-tier model)
            "geo_risk": 0.10,           # Expanded geo model
            # Hostname/domain features (enhanced DGA detection)
            "hostname_entropy": 0.08,
            "hostname_ngram_score": 0.10,  # N-gram based DGA (NEW)
            "hostname_length_risk": 0.04,
            "hostname_digit_ratio": 0.05,
            "hostname_consonant_ratio": 0.03,
            "hostname_hex_pattern": 0.08,  # Hex-like DGA detection (NEW)
            # TCP pattern indicator
            "tcp_scan_indicator": 0.12,
            # Local IOC match
            "local_ioc_indicator": 0.18,
            # GreyNoise benign indicator (NEGATIVE - reduces score)
            "greynoise_benign": -0.30,
            # Trust indicators (NEGATIVE)
            "trusted_geo": -0.10,       # Low-risk country (NEW)
        }
        self.bias = -0.15  # Slight reduction to avoid over-scoring

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

    def _calculate_ngram_score(self, hostname: str) -> float:
        """
        Calculate n-gram based DGA detection score

        Uses English bigram frequency analysis. Legitimate domain names
        tend to have common English bigrams; DGA domains have random
        character combinations with low bigram frequencies.

        Returns 0-1 where higher = more suspicious (likely DGA)
        """
        if not hostname:
            return 0.0

        # Extract main part
        parts = hostname.lower().split(".")
        main_part = parts[0] if parts else hostname

        if len(main_part) < 4:
            return 0.0

        # Only analyze alphabetic characters
        alpha_only = ''.join(c for c in main_part if c.isalpha())
        if len(alpha_only) < 4:
            return 0.0

        # Calculate bigram score
        bigram_count = 0
        total_freq = 0.0

        for i in range(len(alpha_only) - 1):
            bigram = alpha_only[i:i+2]
            bigram_count += 1
            # Get frequency (0 if not in common bigrams)
            freq = self.ENGLISH_BIGRAMS.get(bigram, 0.0)
            total_freq += freq

        if bigram_count == 0:
            return 0.0

        # Average bigram frequency (expected ~0.01 for English text)
        avg_freq = total_freq / bigram_count

        # Low average = suspicious (DGA-like)
        # Normal English has avg ~0.008-0.012
        if avg_freq < 0.002:
            return 0.9  # Very suspicious - almost no common bigrams
        elif avg_freq < 0.004:
            return 0.7  # Suspicious
        elif avg_freq < 0.006:
            return 0.4  # Moderately suspicious
        elif avg_freq < 0.008:
            return 0.2  # Slightly elevated
        else:
            return 0.0  # Normal English-like

    def _detect_hex_pattern(self, hostname: str) -> float:
        """
        Detect hexadecimal-like patterns common in DGA output

        Many DGA families (Necurs, Bamital, Ramnit) generate
        hex-like domain names (e.g., "1a2b3c4d.com")

        Returns 0-1 where higher = more suspicious
        """
        if not hostname:
            return 0.0

        parts = hostname.lower().split(".")
        main_part = parts[0] if parts else hostname

        if len(main_part) < 6:
            return 0.0

        # Count hex-valid characters (0-9, a-f)
        hex_chars = set("0123456789abcdef")
        hex_count = sum(1 for c in main_part if c in hex_chars)
        total_alnum = sum(1 for c in main_part if c.isalnum())

        if total_alnum == 0:
            return 0.0

        hex_ratio = hex_count / total_alnum

        # Check for pure hex pattern
        if hex_ratio >= 0.95 and len(main_part) >= 8:
            # Strong indicator of hex-encoded DGA
            return 0.9

        # Check for alternating digit-letter pattern (common in DGA)
        alternating_count = 0
        for i in range(len(main_part) - 1):
            c1, c2 = main_part[i], main_part[i+1]
            if (c1.isdigit() and c2.isalpha()) or (c1.isalpha() and c2.isdigit()):
                alternating_count += 1

        alternating_ratio = alternating_count / max(len(main_part) - 1, 1)

        if alternating_ratio > 0.6 and len(main_part) >= 10:
            return 0.7

        # High hex ratio but not pure hex
        if hex_ratio > 0.8 and len(main_part) >= 8:
            return 0.5

        return 0.0

    def _extract_otx_features(self, threat_intel: Dict) -> float:
        """
        Extract risk score from OTX (AlienVault Open Threat Exchange) data

        Scoring based on:
        - Pulse count (more pulses = more reported)
        - Critical tags (apt, ransomware, c2, etc.)

        Returns 0-1 risk score
        """
        otx_data = threat_intel.get("otx", {})
        if not otx_data:
            return 0.0

        pulse_count = otx_data.get("pulse_count", 0)
        tags = otx_data.get("tags", [])

        # Base score from pulse count
        if pulse_count == 0:
            base_score = 0.0
        elif pulse_count == 1:
            base_score = 0.2
        elif pulse_count <= 3:
            base_score = 0.4
        elif pulse_count <= 7:
            base_score = 0.6
        elif pulse_count <= 15:
            base_score = 0.75
        else:
            base_score = 0.85

        # Check for critical tags
        tags_lower = {t.lower() for t in tags}
        for critical_tag in self.OTX_CRITICAL_TAGS:
            if critical_tag in tags_lower:
                # Critical tag found - significant boost
                base_score = min(1.0, base_score + 0.25)
                break

            # Partial match for compound tags
            for tag in tags_lower:
                if critical_tag in tag:
                    base_score = min(1.0, base_score + 0.15)
                    break

        return base_score

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
            features["hostname_ngram_score"] = 0.0
            features["hostname_hex_pattern"] = 0.0
            return features

        # Calculate hostname features
        features["hostname_entropy"] = self._calculate_hostname_entropy(hostname)
        features["hostname_length_risk"] = self._calculate_hostname_length_risk(hostname)
        features["hostname_digit_ratio"] = self._calculate_digit_ratio(hostname)
        features["hostname_consonant_ratio"] = self._calculate_consonant_ratio(hostname)
        # Enhanced DGA detection features
        features["hostname_ngram_score"] = self._calculate_ngram_score(hostname)
        features["hostname_hex_pattern"] = self._detect_hex_pattern(hostname)

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

        # Feature 3: OTX pulse risk (NEW)
        features["otx_pulse_risk"] = self._extract_otx_features(threat_intel)

        # Feature 4: Port risk (using PortServiceResolver when available)
        dst_port = connection_metadata.get("dst_port", 0)
        if PORT_SERVICE_AVAILABLE and dst_port > 0:
            # Use the comprehensive port service
            if PortServiceResolver.is_high_risk(dst_port):
                features["port_risk"] = 0.85
            elif PortServiceResolver.is_ephemeral(dst_port):
                features["port_risk"] = 0.7  # Unusual as destination
            elif PortServiceResolver.is_dynamic(dst_port):
                features["port_risk"] = 0.5
            elif PortServiceResolver.is_well_known(dst_port):
                # Check if it's a known service
                service_info = PortServiceResolver.resolve(dst_port)
                if service_info:
                    features["port_risk"] = 0.1  # Known service
                else:
                    features["port_risk"] = 0.3  # Well-known range but unknown
            else:
                features["port_risk"] = 0.4  # Registered port range
        else:
            # Fallback to basic classification
            common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 587}
            high_risk_ports = {3389, 445, 135, 139, 1433, 3306, 5432, 6379, 27017}

            if dst_port in high_risk_ports:
                features["port_risk"] = 0.85
            elif dst_port in common_ports:
                features["port_risk"] = 0.1
            elif dst_port < 1024:
                features["port_risk"] = 0.3
            elif dst_port < 49152:
                features["port_risk"] = 0.5
            else:
                features["port_risk"] = 0.7

        # Feature 5: Geographic risk (3-tier model)
        country_code = geo_data.get("country", "")
        features["trusted_geo"] = 0.0  # Default no trust bonus

        if country_code in self.HIGH_RISK_COUNTRIES:
            features["geo_risk"] = 0.85
        elif country_code in self.ELEVATED_RISK_COUNTRIES:
            features["geo_risk"] = 0.55
        elif country_code in self.LOW_RISK_COUNTRIES:
            features["geo_risk"] = 0.15
            features["trusted_geo"] = 0.7  # Trust bonus for low-risk geo
        elif country_code in ("Unknown", ""):
            features["geo_risk"] = 0.6  # Elevated for unknown
        else:
            features["geo_risk"] = 0.35  # Neutral for unlisted countries

        # Feature 6-11: Hostname/domain features (enhanced DGA detection)
        hostname_features = self._extract_hostname_features(connection_metadata)
        features.update(hostname_features)

        # Feature 12: TCP scan pattern indicator
        if connection_metadata.get("tcp_is_scan", False):
            features["tcp_scan_indicator"] = 0.9
        elif connection_metadata.get("tcp_syn", False) and not connection_metadata.get("tcp_ack", False):
            features["tcp_scan_indicator"] = 0.6
        else:
            features["tcp_scan_indicator"] = 0.0

        # Feature 13: Local IOC match indicator
        if threat_intel.get("local_ioc_match"):
            features["local_ioc_indicator"] = 0.95
        else:
            features["local_ioc_indicator"] = 0.0

        # Feature 14: GreyNoise benign indicator (reduces score)
        if threat_intel.get("greynoise_riot"):
            features["greynoise_benign"] = 0.9  # High trust - RIOT verified
        elif threat_intel.get("greynoise_benign_scanner"):
            features["greynoise_benign"] = 0.7  # Benign scanner
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
            f"Heuristic score: {predicted_score:.3f} (key features: {', '.join(reasoning_parts)})"
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
