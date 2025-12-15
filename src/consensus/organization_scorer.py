"""
Organization-Based Threat Scorer
Scores connections based on ASN, organization type, and network path analysis

Approach:
- Organization reputation scoring (cloud providers vs. bullet-proof hosting)
- ASN-based threat profiling
- Network distance weighting (hops)
- Trust inheritance from organization classification
- Multi-hop path anomaly detection
"""

import time
from typing import Dict, Optional

from .scorer_base import ScorerAssessment, ThreatScorer

# Import ASN service types
try:
    from src.services.asn_lookup import ASNInfo, ASNLookup, OrgType, TTLAnalyzer
    ASN_AVAILABLE = True
except ImportError:
    ASN_AVAILABLE = False
    ASNInfo = None
    OrgType = None


class OrganizationScorer(ThreatScorer):
    """
    Organization and ASN-based threat scorer

    Features:
    - ASN reputation scoring
    - Organization type classification
    - TTL-based hop analysis
    - Network infrastructure profiling
    - Known bad actor ASN detection
    """

    # Known high-risk ASNs (bullet-proof hosting, malware infrastructure)
    # These ASNs have historically been associated with malicious activity
    HIGH_RISK_ASNS = {
        # Bullet-proof hosting
        44477,   # STARK-INDUSTRIES
        213371,  # EVOCATIVE
        202425,  # IP VOLUME INC
        14061,   # DigitalOcean (abused but not malicious)
        # Note: Add more based on your threat intel feeds
    }

    # Highly trusted ASNs (major tech infrastructure)
    TRUSTED_ASNS = {
        15169,   # GOOGLE
        8075,    # MICROSOFT-CORP-MSN-AS-BLOCK
        16509,   # AMAZON-02 (AWS)
        13335,   # CLOUDFLARE
        32934,   # FACEBOOK (Meta)
        20940,   # AKAMAI
        6185,    # APPLE
        14618,   # AMAZON-AES (AWS US East)
        16591,   # GOOGLE-FIBER
        36459,   # GITHUB
    }

    # Organization type risk multipliers
    ORG_TYPE_RISK = {
        "cloud": 0.0,           # Cloud providers - neutral (legitimate + abuse)
        "cdn": -0.15,           # CDNs - slightly lower risk
        "hosting": 0.15,        # Hosting - slightly elevated (abuse potential)
        "isp_residential": -0.1,  # Residential ISP - normal traffic
        "isp_business": -0.1,   # Business ISP - normal traffic
        "enterprise": -0.2,     # Major enterprises - lower risk
        "education": -0.15,     # Education - lower risk
        "government": -0.1,     # Government - context dependent
        "tor_proxy": 0.35,      # Tor/VPN - elevated risk (anonymization)
        "unknown": 0.1,         # Unknown - slight risk elevation
    }

    # Hop-based risk adjustments
    # More hops = more potential for suspicious routing
    HOP_RISK_THRESHOLDS = [
        (5, -0.05),    # Very close - slightly lower risk
        (10, 0.0),     # Normal range - no adjustment
        (15, 0.05),    # Moderately far - slight elevation
        (20, 0.1),     # Far - elevated
        (25, 0.15),    # Very far - suspicious
        (30, 0.25),    # Extremely far - highly suspicious routing
    ]

    def __init__(self, asn_service: Optional['ASNLookup'] = None):
        """
        Initialize organization scorer

        Args:
            asn_service: Optional ASNLookup service instance (creates one if None)
        """
        super().__init__(scorer_id="organization")

        # Initialize ASN lookup service
        if ASN_AVAILABLE:
            self.asn_service = asn_service or ASNLookup()
            self.ttl_analyzer = TTLAnalyzer()
        else:
            self.asn_service = None
            self.ttl_analyzer = None

        # Cache for repeated lookups in same session
        self._session_cache: Dict[str, ASNInfo] = {}

    def assess(
        self, dst_ip: str, threat_intel: Dict, geo_data: Dict, connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        Organization-based threat assessment

        Analyzes:
        1. ASN reputation (known good/bad ASNs)
        2. Organization type (cloud, CDN, hosting, ISP)
        3. Trust score from classification
        4. TTL-based hop count
        5. Network path anomalies
        """
        timestamp = time.time()
        features = {}
        factors = []
        base_score = 0.5  # Start neutral

        # Get TTL from metadata if available
        ttl = connection_metadata.get("ttl", 0)

        # Perform ASN lookup
        asn_info = self._get_asn_info(dst_ip, ttl)
        features["asn"] = asn_info.asn if asn_info else 0
        features["asn_name"] = asn_info.asn_name if asn_info else "Unknown"
        features["organization"] = asn_info.organization if asn_info else "Unknown"
        features["org_type"] = asn_info.org_type.value if asn_info else "unknown"

        # Factor 1: ASN reputation
        if asn_info and asn_info.asn > 0:
            if asn_info.asn in self.HIGH_RISK_ASNS:
                base_score += 0.4
                factors.append(f"HIGH_RISK_ASN(AS{asn_info.asn})")
                features["asn_reputation"] = "high_risk"
            elif asn_info.asn in self.TRUSTED_ASNS:
                base_score -= 0.25
                factors.append(f"TRUSTED_ASN(AS{asn_info.asn})")
                features["asn_reputation"] = "trusted"
            else:
                features["asn_reputation"] = "neutral"

        # Factor 2: Organization type risk
        if asn_info:
            org_type_str = asn_info.org_type.value if hasattr(asn_info.org_type, 'value') else str(asn_info.org_type)
            risk_modifier = self.ORG_TYPE_RISK.get(org_type_str, 0.1)
            base_score += risk_modifier

            if risk_modifier > 0.1:
                factors.append(f"ORG_TYPE_ELEVATED({org_type_str})")
            elif risk_modifier < -0.1:
                factors.append(f"ORG_TYPE_TRUSTED({org_type_str})")

            features["org_type_risk"] = risk_modifier

        # Factor 3: Trust score from ASN classification
        if asn_info:
            trust_factor = (0.5 - asn_info.trust_score) * 0.3  # Convert trust to risk
            base_score += trust_factor
            features["trust_score"] = asn_info.trust_score
            features["trust_factor"] = trust_factor

        # Factor 4: Hop-based risk assessment
        if asn_info and asn_info.estimated_hops > 0:
            hops = asn_info.estimated_hops
            hop_risk = 0.0

            for threshold, risk in self.HOP_RISK_THRESHOLDS:
                if hops <= threshold:
                    hop_risk = risk
                    break
            else:
                hop_risk = 0.3  # > 30 hops is very suspicious

            base_score += hop_risk
            features["estimated_hops"] = hops
            features["initial_ttl"] = asn_info.initial_ttl
            features["hop_risk"] = hop_risk

            if hop_risk > 0.1:
                factors.append(f"HIGH_HOP_COUNT({hops})")

        # Factor 5: TTL anomaly detection
        if self.ttl_analyzer and ttl > 0:
            ttl_result = self.ttl_analyzer.analyze(dst_ip, ttl, timestamp)
            if ttl_result.get("anomaly"):
                base_score += 0.2
                factors.append(f"TTL_ANOMALY({ttl_result['anomaly']})")
                features["ttl_anomaly"] = ttl_result["anomaly"]

            features["os_guess"] = ttl_result.get("os_guess", "Unknown")

        # Factor 6: CIDR block intelligence
        if asn_info and asn_info.cidr:
            features["cidr"] = asn_info.cidr
            # Could add CIDR-specific reputation here

        # Factor 7: Cross-reference with geo risk
        country = geo_data.get("country_code", "") or (asn_info.country if asn_info else "")
        if country and asn_info:
            # Mismatch between ASN country and geo country is suspicious
            if asn_info.country and country != asn_info.country:
                base_score += 0.1
                factors.append(f"GEO_ASN_MISMATCH({country} vs {asn_info.country})")
                features["geo_asn_mismatch"] = True

        # Clamp score
        final_score = max(0.0, min(1.0, base_score))

        # Calculate confidence
        confidence = self._calculate_confidence(asn_info, ttl)

        # Generate reasoning
        if factors:
            reasoning = "Org analysis: " + ", ".join(factors)
        else:
            reasoning = f"Organization: {features.get('organization', 'Unknown')} (AS{features.get('asn', 0)})"

        # Sign assessment
        signature = self._sign_assessment(final_score, confidence, timestamp)

        assessment = ScorerAssessment(
            scorer_id=self.scorer_id,
            score=final_score,
            confidence=confidence,
            reasoning=reasoning,
            features=features,
            timestamp=timestamp,
            signature=signature,
        )

        self._record_assessment(assessment)
        return assessment

    def _get_asn_info(self, ip: str, ttl: int = 0) -> Optional[ASNInfo]:
        """Get ASN info with session caching"""
        if not self.asn_service:
            return None

        # Check session cache
        if ip in self._session_cache:
            cached = self._session_cache[ip]
            # Update TTL info if new observation
            if ttl > 0:
                cached.ttl_observed = ttl
                from src.services.asn_lookup import ASNLookup
                temp = ASNLookup()
                cached.initial_ttl, cached.estimated_hops = temp._estimate_hops(ttl)
            return cached

        # Perform lookup
        try:
            info = self.asn_service.lookup(ip, ttl)
            self._session_cache[ip] = info
            return info
        except Exception as e:
            # Log but don't fail scoring
            return None

    def _calculate_confidence(self, asn_info: Optional[ASNInfo], ttl: int) -> float:
        """
        Calculate confidence based on data availability

        Higher confidence when:
        - ASN lookup succeeded
        - Organization classified
        - TTL available for hop analysis
        """
        confidence = 0.5  # Base confidence

        if asn_info:
            if asn_info.asn > 0:
                confidence += 0.15  # Have ASN data
            if asn_info.organization:
                confidence += 0.1  # Have org name
            if asn_info.org_type and asn_info.org_type.value != "unknown":
                confidence += 0.1  # Successfully classified
            if asn_info.estimated_hops > 0:
                confidence += 0.1  # Have hop data
        else:
            confidence -= 0.2  # No ASN data at all

        if ttl > 0:
            confidence += 0.05  # Have TTL for analysis

        return min(0.95, max(0.3, confidence))

    def get_asn_stats(self) -> Dict:
        """Get ASN service statistics"""
        if self.asn_service:
            return self.asn_service.get_stats()
        return {}

    def clear_session_cache(self):
        """Clear the session cache"""
        self._session_cache.clear()


# Factory function
def create_organization_scorer(asn_service=None) -> OrganizationScorer:
    """Create an OrganizationScorer instance"""
    return OrganizationScorer(asn_service=asn_service)
