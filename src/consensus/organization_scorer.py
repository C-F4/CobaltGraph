"""
Organization-Based Threat Scorer
Scores connections based on ASN, organization type, and network path analysis

Approach:
- Organization reputation scoring (cloud providers vs. bullet-proof hosting)
- ASN-based threat profiling (30+ high-risk, 15+ elevated-risk, 40+ trusted)
- Network distance weighting (hops)
- Trust inheritance from organization classification
- Multi-hop path anomaly detection
- Domain-ASN correlation (SNI verification) with 60+ domain mappings
- CDN organization detection (20+ CDN patterns)
- ASN abuse pattern detection in org names
"""

import re
import time
from typing import Dict, List, Optional, Set

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
    - ASN reputation scoring (expanded databases)
    - Organization type classification (including budget VPS, bulletproof)
    - TTL-based hop analysis
    - Network infrastructure profiling
    - Known bad actor ASN detection (30+ high-risk ASNs)
    - CDN detection for legitimate multi-tenant hosting
    - ASN abuse pattern matching
    """

    # Known high-risk ASNs (bullet-proof hosting, malware infrastructure)
    # Expanded from 4 to 30+ ASNs
    HIGH_RISK_ASNS = {
        # Bullet-proof hosting providers
        44477,   # STARK-INDUSTRIES - notorious bulletproof
        213371,  # EVOCATIVE - abuse reports
        202425,  # IP VOLUME INC - bulletproof
        49981,   # WORLDSTREAM - bulletproof hosting NL
        209711,  # MUV BILISIM - Turkish bulletproof
        208323,  # STARK-INDUSTRIES
        62904,   # EONIX - bulletproof
        60117,   # HOST SAILOR - bulletproof
        50613,   # Micfo LLC - bulletproof
        57043,   # HOSTKEY B.V. - bulletproof
        # Russian/CIS bulletproof infrastructure
        197414,  # RETN
        48666,   # SELECTEL - Russian hosting (abuse)
        44050,   # PIN-AS - bulletproof
        29119,   # SERVIHOSTING
        35913,   # DEDIPATH-LLC
        36351,   # SOFTLAYER (IBM) - high abuse
        # Asian bulletproof
        45899,   # VNPT - Vietnam (high abuse)
        4134,    # CHINANET-BACKBONE
        17623,   # CNCGROUP-SZ - China (high abuse)
        # Known malware C2 infrastructure
        136987,  # QUICKPACKET
        46844,   # SHARKTECH
        53667,   # FRANTECH/PONYNET - bulletproof
        16276,   # OVH - high abuse volume
        # Offshore bulletproof
        56630,   # MELBIKOMAS-AS - bulletproof
        200019,  # ALEXHOST - Moldova bulletproof
        39572,   # DATACAMP LIMITED
        42473,   # ANEXIA-AS
        61317,   # ASDETUK - bulletproof
        # Crypto/darknet associated
        53264,   # FERAL - known abuse
        25369,   # HYDRA Communications
    }

    # Elevated risk ASNs - budget VPS, residential proxies, frequent abuse
    ELEVATED_RISK_ASNS = {
        14061,   # DigitalOcean - legitimate but heavily abused
        63949,   # Linode/Akamai - legitimate but abused
        20473,   # AS-CHOOPA/Vultr - legitimate but abused
        46664,   # VolumeDrive - budget VPS
        29802,   # HVC-AS HIVELOCITY - budget
        19551,   # INCAPSULA - mixed traffic
        206264,  # Amarutu Technology - residential proxy
        9009,    # M247 - VPN/proxy services
        21859,   # ZEN-ECN - budget hosting
        51167,   # CONTABO - budget VPS DE
        24940,   # HETZNER-AS - budget hosting
        12876,   # SCALEWAY - budget cloud
        132203,  # TENCENT-NET-AP-CN - Chinese cloud
        37963,   # CNNIC-ALIBABA-CN - Alibaba Cloud
    }

    # Highly trusted ASNs (major tech infrastructure)
    # Expanded from 10 to 40+ ASNs
    TRUSTED_ASNS = {
        # Google ecosystem
        15169,   # GOOGLE
        16591,   # GOOGLE-FIBER
        19527,   # GOOGLE-2
        36040,   # GOOGLE-GGLS2
        # Microsoft ecosystem
        8075,    # MICROSOFT-CORP-MSN-AS-BLOCK
        8068,    # MICROSOFT-CORP-AS
        8069,    # MICROSOFT-CORP-AS
        3598,    # MICROSOFT-CORP-AS
        8070,    # MICROSOFT-CORP-AS
        # Amazon ecosystem
        16509,   # AMAZON-02 (AWS)
        14618,   # AMAZON-AES (AWS US East)
        7224,    # AMAZON-02
        38895,   # AMAZON-02-AP
        # Cloudflare
        13335,   # CLOUDFLARE
        209242,  # CLOUDFLARE
        # Meta/Facebook
        32934,   # FACEBOOK (Meta)
        63293,   # FB-CORP
        # Apple
        6185,    # APPLE-AUSTIN
        714,     # APPLE-ENGINEERING
        # CDN providers
        20940,   # AKAMAI
        16625,   # AKAMAI-AS
        21342,   # AKAMAI-AS2
        54113,   # FASTLY
        26008,   # FASTLY
        # GitHub/Dev platforms
        36459,   # GITHUB
        25291,   # SYSNETWORKS-AS/Gandi
        # Major ISPs/Telecoms (US)
        7018,    # ATT-INTERNET4
        7922,    # COMCAST-7922
        20001,   # TWC-20001-PACWEST
        209,     # CENTURYLINK
        # Major ISPs (EU)
        3320,    # DTAG - Deutsche Telekom
        5400,    # BT-UK
        3215,    # ORANGE - France
        # DNS providers
        19281,   # QUAD9
        393234,  # QUAD9-SECONDARY
        # Financial infrastructure
        26415,   # VERISIGN
        # Other major services
        2906,    # NETFLIX
        22822,   # LLNW/Limelight
        46489,   # TWITCH
        19679,   # DROPBOX
        6939,    # HURRICANE (HE.net) - infrastructure
    }

    # Infrastructure ASNs - DNS providers, NTP, CAs (should not be penalized)
    INFRASTRUCTURE_ASNS = {
        # DNS root/authoritative
        19281,   # QUAD9
        393234,  # QUAD9-SECONDARY
        13335,   # CLOUDFLARE (DNS)
        15169,   # GOOGLE (DNS)
        # NTP providers
        6939,    # HURRICANE-AS
        # Certificate authorities
        26415,   # VERISIGN
        1273,    # COMODO/SECTIGO
    }

    # Organization type risk multipliers (expanded with new categories)
    ORG_TYPE_RISK = {
        "cloud": 0.0,             # Cloud providers - neutral (legitimate + abuse)
        "cdn": -0.15,             # CDNs - slightly lower risk
        "hosting": 0.15,          # Standard hosting - slightly elevated
        "budget_vps": 0.25,       # Budget VPS providers - higher abuse (NEW)
        "bulletproof": 0.50,      # Bulletproof hosting - very high risk (NEW)
        "isp_residential": -0.1,  # Residential ISP - normal traffic
        "isp_business": -0.1,     # Business ISP - normal traffic
        "enterprise": -0.2,       # Major enterprises - lower risk
        "education": -0.15,       # Education - lower risk
        "government": -0.1,       # Government - context dependent
        "tor_proxy": 0.40,        # Tor exit/VPN - elevated risk (anonymization)
        "vpn": 0.30,              # Commercial VPN - elevated (NEW)
        "proxy": 0.35,            # Proxy services - elevated (NEW)
        "residential_proxy": 0.45, # Residential proxies - high risk (NEW)
        "unknown": 0.15,          # Unknown - slight risk elevation
        "infrastructure": -0.20,  # DNS/NTP/CA infrastructure (NEW)
    }

    # Bulletproof hosting indicators in org names
    BULLETPROOF_INDICATORS = {
        "bulletproof", "offshore", "anonymous", "untraceable", "abuse-proof",
        "privacy", "dmca ignore", "no logs", "anonymous hosting",
    }

    # Budget VPS indicators in org names
    BUDGET_VPS_INDICATORS = {
        "vps", "cheap", "budget", "discount", "low cost",
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

    # Domain to expected organization mapping for SNI-ASN correlation
    # Expanded from 20 to 60+ domains
    DOMAIN_ASN_MAP = {
        # Google ecosystem
        "google.com": {"Google", "GOOGLE"},
        "googleapis.com": {"Google", "GOOGLE"},
        "gstatic.com": {"Google", "GOOGLE"},
        "youtube.com": {"Google", "GOOGLE"},
        "googlevideo.com": {"Google", "GOOGLE"},
        "gmail.com": {"Google", "GOOGLE"},
        "googlemail.com": {"Google", "GOOGLE"},
        "android.com": {"Google", "GOOGLE"},
        "googleusercontent.com": {"Google", "GOOGLE"},
        "firebaseio.com": {"Google", "GOOGLE"},
        "gvt1.com": {"Google", "GOOGLE"},
        "gvt2.com": {"Google", "GOOGLE"},
        # Microsoft ecosystem
        "microsoft.com": {"Microsoft", "MICROSOFT"},
        "windows.com": {"Microsoft", "MICROSOFT"},
        "azure.com": {"Microsoft", "MICROSOFT"},
        "live.com": {"Microsoft", "MICROSOFT"},
        "office.com": {"Microsoft", "MICROSOFT"},
        "outlook.com": {"Microsoft", "MICROSOFT"},
        "office365.com": {"Microsoft", "MICROSOFT"},
        "microsoftonline.com": {"Microsoft", "MICROSOFT"},
        "msn.com": {"Microsoft", "MICROSOFT"},
        "bing.com": {"Microsoft", "MICROSOFT"},
        "msedge.net": {"Microsoft", "MICROSOFT"},
        "windowsupdate.com": {"Microsoft", "MICROSOFT"},
        "sharepoint.com": {"Microsoft", "MICROSOFT"},
        "onedrive.com": {"Microsoft", "MICROSOFT"},
        "visualstudio.com": {"Microsoft", "MICROSOFT"},
        "xbox.com": {"Microsoft", "MICROSOFT"},
        "skype.com": {"Microsoft", "MICROSOFT"},
        "linkedin.com": {"LinkedIn", "LINKEDIN", "Microsoft", "MICROSOFT"},
        "github.com": {"GitHub", "GITHUB", "Microsoft", "MICROSOFT"},
        # Amazon/AWS ecosystem
        "amazon.com": {"Amazon", "AMAZON"},
        "amazonaws.com": {"Amazon", "AMAZON"},
        "cloudfront.net": {"Amazon", "AMAZON", "Cloudflare", "CLOUDFLARE"},
        "awsstatic.com": {"Amazon", "AMAZON"},
        "elasticbeanstalk.com": {"Amazon", "AMAZON"},
        # Cloudflare (CDN - expected to host many domains)
        "cloudflare.com": {"Cloudflare", "CLOUDFLARE"},
        "cloudflare-dns.com": {"Cloudflare", "CLOUDFLARE"},
        # Apple ecosystem
        "apple.com": {"Apple", "APPLE"},
        "icloud.com": {"Apple", "APPLE"},
        "icloud-content.com": {"Apple", "APPLE"},
        "mzstatic.com": {"Apple", "APPLE"},
        "itunes.com": {"Apple", "APPLE"},
        # Meta/Facebook ecosystem
        "facebook.com": {"Facebook", "META", "FACEBOOK"},
        "fb.com": {"Facebook", "META", "FACEBOOK"},
        "fbcdn.net": {"Facebook", "META", "FACEBOOK"},
        "instagram.com": {"Facebook", "META", "FACEBOOK"},
        "whatsapp.com": {"Facebook", "META", "FACEBOOK"},
        "whatsapp.net": {"Facebook", "META", "FACEBOOK"},
        "messenger.com": {"Facebook", "META", "FACEBOOK"},
        # Twitter/X
        "twitter.com": {"Twitter", "TWITTER", "X Corp", "X CORP"},
        "x.com": {"Twitter", "TWITTER", "X Corp", "X CORP"},
        "twimg.com": {"Twitter", "TWITTER", "X Corp", "X CORP"},
        # Other major tech
        "netflix.com": {"Netflix", "NETFLIX"},
        "nflxvideo.net": {"Netflix", "NETFLIX"},
        "spotify.com": {"Spotify", "SPOTIFY"},
        "twitch.tv": {"Twitch", "TWITCH", "Amazon", "AMAZON"},
        "discord.com": {"Discord", "DISCORD", "Cloudflare", "CLOUDFLARE"},
        "discordapp.com": {"Discord", "DISCORD", "Cloudflare", "CLOUDFLARE"},
        "reddit.com": {"Reddit", "REDDIT", "Fastly", "FASTLY"},
        "wikipedia.org": {"Wikimedia", "WIKIMEDIA"},
        "dropbox.com": {"Dropbox", "DROPBOX"},
        # Enterprise software
        "salesforce.com": {"Salesforce", "SALESFORCE"},
        "slack.com": {"Slack", "SLACK", "Salesforce", "SALESFORCE"},
        "zoom.us": {"Zoom", "ZOOM"},
        "atlassian.com": {"Atlassian", "ATLASSIAN"},
        "atlassian.net": {"Atlassian", "ATLASSIAN"},
        "okta.com": {"Okta", "OKTA"},
        "auth0.com": {"Auth0", "AUTH0", "Okta", "OKTA"},
        "zendesk.com": {"Zendesk", "ZENDESK"},
        "servicenow.com": {"ServiceNow", "SERVICENOW"},
        # Payment processors
        "paypal.com": {"PayPal", "PAYPAL"},
        "stripe.com": {"Stripe", "STRIPE"},
        # Security vendors
        "virustotal.com": {"Google", "GOOGLE"},
        "crowdstrike.com": {"CrowdStrike", "CROWDSTRIKE"},
    }

    # CDN organizations that legitimately host many domains
    # Expanded from 10 to 20+ CDN patterns
    CDN_ORGANIZATIONS = {
        # Major CDNs
        "Cloudflare", "CLOUDFLARE", "CF-",
        "Akamai", "AKAMAI", "AKAMAI-AS",
        "Fastly", "FASTLY",
        "Amazon CloudFront", "AMAZON", "AWS", "AMAZON-02",
        "Google Cloud CDN", "GOOGLE", "GCP",
        "Microsoft Azure CDN", "MICROSOFT", "AZURE",
        # Specialized CDNs
        "StackPath", "STACKPATH", "HIGHWINDS",
        "KeyCDN", "KEYCDN",
        "Limelight", "LIMELIGHT", "LLNW",
        "Verizon Digital Media", "EDGECAST",
        "Bunny CDN", "BUNNY",
        "jsDelivr", "JSDELIVR",
        "unpkg", "UNPKG",
        # Security/WAF CDNs
        "Imperva", "IMPERVA", "INCAPSULA",
        "Sucuri", "SUCURI",
        "Cloudflare Magic Transit",
        # Streaming CDNs
        "Netflix Open Connect", "NFLX",
        "Twitch", "TWITCH",
    }

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

    def _get_expected_orgs_for_domain(self, domain: str) -> Optional[Set[str]]:
        """
        Get expected organizations for a domain based on known mappings

        Returns:
            Set of expected organization names, or None if domain not mapped
        """
        if not domain:
            return None

        domain_lower = domain.lower()

        # Direct lookup
        for mapped_domain, orgs in self.DOMAIN_ASN_MAP.items():
            if domain_lower == mapped_domain or domain_lower.endswith("." + mapped_domain):
                return orgs

        return None

    def _is_cdn_organization(self, org_name: str) -> bool:
        """Check if organization is a known CDN (legitimately hosts many domains)"""
        if not org_name:
            return False

        org_upper = org_name.upper()
        for cdn in self.CDN_ORGANIZATIONS:
            if cdn.upper() in org_upper or org_upper in cdn.upper():
                return True
        return False

    def _detect_abuse_patterns(self, org_name: str, asn_name: str) -> tuple[Optional[str], float]:
        """
        Detect abuse patterns in organization/ASN names

        Looks for bulletproof hosting indicators, budget VPS patterns,
        and other suspicious naming conventions.

        Args:
            org_name: Organization name from ASN lookup
            asn_name: ASN name from lookup

        Returns:
            Tuple of (detected_pattern, score_adjustment)
        """
        if not org_name and not asn_name:
            return None, 0.0

        combined = f"{org_name or ''} {asn_name or ''}".lower()

        # Check for bulletproof hosting indicators
        for indicator in self.BULLETPROOF_INDICATORS:
            if indicator in combined:
                return f"bulletproof_indicator({indicator})", 0.35

        # Check for budget VPS indicators
        for indicator in self.BUDGET_VPS_INDICATORS:
            if indicator in combined:
                return f"budget_vps_indicator({indicator})", 0.10

        # Check for suspicious country indicators in org names
        suspicious_country_terms = {"offshore", "panama", "seychelles", "belize"}
        for term in suspicious_country_terms:
            if term in combined:
                return f"offshore_indicator({term})", 0.20

        return None, 0.0

    def _classify_org_type_enhanced(
        self, asn: int, org_name: str, asn_name: str, base_org_type: str
    ) -> tuple[str, float]:
        """
        Enhanced organization type classification

        Uses ASN databases and name pattern matching to refine
        the organization type classification.

        Args:
            asn: ASN number
            org_name: Organization name
            asn_name: ASN name
            base_org_type: Base org type from ASN lookup

        Returns:
            Tuple of (refined_org_type, risk_modifier)
        """
        # Check ASN databases first (most reliable)
        if asn in self.INFRASTRUCTURE_ASNS:
            return "infrastructure", self.ORG_TYPE_RISK.get("infrastructure", -0.20)

        if asn in self.HIGH_RISK_ASNS:
            # Determine if bulletproof or just high abuse
            abuse_pattern, _ = self._detect_abuse_patterns(org_name, asn_name)
            if abuse_pattern and "bulletproof" in abuse_pattern:
                return "bulletproof", self.ORG_TYPE_RISK.get("bulletproof", 0.50)
            return "hosting", self.ORG_TYPE_RISK.get("hosting", 0.15) + 0.20

        if asn in self.ELEVATED_RISK_ASNS:
            return "budget_vps", self.ORG_TYPE_RISK.get("budget_vps", 0.25)

        if asn in self.TRUSTED_ASNS:
            # Could be CDN, cloud, or enterprise - keep base classification
            return base_org_type, self.ORG_TYPE_RISK.get(base_org_type, -0.15)

        # Check name patterns for VPN/proxy indicators
        combined = f"{org_name or ''} {asn_name or ''}".lower()
        vpn_indicators = {"vpn", "virtual private", "tunneling", "hide", "private internet"}
        for indicator in vpn_indicators:
            if indicator in combined:
                return "vpn", self.ORG_TYPE_RISK.get("vpn", 0.30)

        proxy_indicators = {"proxy", "residential", "mobile ip", "isp proxy"}
        for indicator in proxy_indicators:
            if indicator in combined:
                if "residential" in combined:
                    return "residential_proxy", self.ORG_TYPE_RISK.get("residential_proxy", 0.45)
                return "proxy", self.ORG_TYPE_RISK.get("proxy", 0.35)

        # Fall back to base classification
        return base_org_type, self.ORG_TYPE_RISK.get(base_org_type, 0.1)

    def _check_domain_asn_correlation(
        self,
        domain: str,
        asn_org: str,
        asn_name: str,
    ) -> tuple[bool, Optional[str], float]:
        """
        Check if domain matches expected ASN ownership

        This helps detect:
        - Potential MITM attacks (domain resolving to unexpected network)
        - CDN/proxy usage (legitimate but noteworthy)
        - Domain fronting or suspicious hosting

        Args:
            domain: TLS SNI or DNS query domain
            asn_org: Organization name from ASN lookup
            asn_name: ASN name from lookup

        Returns:
            Tuple of (is_mismatch, reason, score_adjustment)
            - is_mismatch: True if domain doesn't match expected owner
            - reason: Human-readable reason for mismatch
            - score_adjustment: Score adjustment (-0.1 to +0.2)
        """
        if not domain:
            return False, None, 0.0

        # Get expected organizations for this domain
        expected_orgs = self._get_expected_orgs_for_domain(domain)

        if expected_orgs is None:
            # Domain not in our mapping - can't verify
            return False, None, 0.0

        # Check if current ASN org matches any expected
        org_match = False
        if asn_org:
            asn_org_upper = asn_org.upper()
            for expected in expected_orgs:
                if expected.upper() in asn_org_upper or asn_org_upper in expected.upper():
                    org_match = True
                    break

        if not org_match and asn_name:
            asn_name_upper = asn_name.upper()
            for expected in expected_orgs:
                if expected.upper() in asn_name_upper or asn_name_upper in expected.upper():
                    org_match = True
                    break

        if org_match:
            # Domain matches expected ASN - good sign
            return False, None, -0.05  # Slight trust boost

        # Mismatch detected - check if it's a CDN (legitimate)
        if self._is_cdn_organization(asn_org) or self._is_cdn_organization(asn_name):
            # CDN hosting - legitimate but noteworthy
            return True, f"cdn_hosted({asn_org or asn_name})", 0.0  # No score change

        # Genuine mismatch - potentially suspicious
        expected_list = ", ".join(list(expected_orgs)[:3])
        return True, f"expected({expected_list}),got({asn_org or asn_name})", 0.15

    def assess(
        self, dst_ip: str, threat_intel: Dict, geo_data: Dict, connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        Organization-based threat assessment

        Analyzes:
        1. ASN reputation (known good/bad/elevated ASNs)
        2. Organization type (cloud, CDN, hosting, ISP, bulletproof, VPN, proxy)
        3. Trust score from classification
        4. TTL-based hop count
        5. Network path anomalies
        6. ASN abuse pattern detection
        7. Domain-ASN correlation
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

        # Factor 1: ASN reputation (expanded with elevated risk)
        if asn_info and asn_info.asn > 0:
            if asn_info.asn in self.HIGH_RISK_ASNS:
                base_score += 0.45
                factors.append(f"HIGH_RISK_ASN(AS{asn_info.asn})")
                features["asn_reputation"] = "high_risk"
            elif asn_info.asn in self.ELEVATED_RISK_ASNS:
                base_score += 0.18
                factors.append(f"ELEVATED_RISK_ASN(AS{asn_info.asn})")
                features["asn_reputation"] = "elevated_risk"
            elif asn_info.asn in self.INFRASTRUCTURE_ASNS:
                base_score -= 0.15
                factors.append(f"INFRASTRUCTURE_ASN(AS{asn_info.asn})")
                features["asn_reputation"] = "infrastructure"
            elif asn_info.asn in self.TRUSTED_ASNS:
                base_score -= 0.28
                factors.append(f"TRUSTED_ASN(AS{asn_info.asn})")
                features["asn_reputation"] = "trusted"
            else:
                features["asn_reputation"] = "neutral"

        # Factor 2: Enhanced organization type classification
        if asn_info:
            base_org_type = asn_info.org_type.value if hasattr(asn_info.org_type, 'value') else str(asn_info.org_type)

            # Use enhanced classification
            refined_org_type, risk_modifier = self._classify_org_type_enhanced(
                asn=asn_info.asn,
                org_name=asn_info.organization,
                asn_name=asn_info.asn_name,
                base_org_type=base_org_type,
            )

            features["org_type_refined"] = refined_org_type
            base_score += risk_modifier

            if risk_modifier > 0.1:
                factors.append(f"ORG_TYPE_ELEVATED({refined_org_type})")
            elif risk_modifier < -0.1:
                factors.append(f"ORG_TYPE_TRUSTED({refined_org_type})")

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
        country = geo_data.get("country", "") or (asn_info.country if asn_info else "")
        if country and asn_info:
            # Mismatch between ASN country and geo country is suspicious
            if asn_info.country and country != asn_info.country:
                base_score += 0.1
                factors.append(f"GEO_ASN_MISMATCH({country} vs {asn_info.country})")
                features["geo_asn_mismatch"] = True

        # Factor 8: Domain-ASN correlation (SNI/DNS verification)
        tls_sni = connection_metadata.get("tls_sni")
        dns_query = connection_metadata.get("dns_query")
        domain = tls_sni or dns_query

        if domain and asn_info:
            is_mismatch, mismatch_reason, score_adj = self._check_domain_asn_correlation(
                domain=domain,
                asn_org=asn_info.organization,
                asn_name=asn_info.asn_name,
            )

            features["domain"] = domain
            features["domain_source"] = "tls_sni" if tls_sni else "dns"

            if is_mismatch:
                features["domain_asn_mismatch"] = True
                features["domain_asn_mismatch_reason"] = mismatch_reason

                if score_adj > 0:
                    # Suspicious mismatch
                    base_score += score_adj
                    factors.append(f"DOMAIN_ASN_MISMATCH({mismatch_reason})")
                elif score_adj == 0 and "cdn_hosted" in (mismatch_reason or ""):
                    # CDN hosting - note but don't penalize
                    factors.append(f"CDN_HOSTED({domain})")
                    features["cdn_hosted"] = True
            elif score_adj < 0:
                # Domain matches expected owner - trust boost
                base_score += score_adj
                features["domain_asn_verified"] = True

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
