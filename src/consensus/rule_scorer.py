"""
Rule-Based Threat Scorer
Uses expert-defined heuristics and rules

Approach:
- Pattern matching on known threat indicators
- Port-based classification
- Geographic risk assessment
- Domain/hostname intelligence
- TCP connection state analysis
- Deterministic rule evaluation
"""

import math
import re
import time
from typing import Dict, Optional, Set

from .scorer_base import ScorerAssessment, ThreatScorer


class RuleScorer(ThreatScorer):
    """
    Expert rule-based threat scorer

    Features:
    - Known malicious port detection
    - Geographic risk zones
    - Threat intelligence thresholds
    - Domain intelligence (DNS queries, TLS SNI)
    - DGA detection (Domain Generation Algorithm)
    - TCP connection state analysis
    - Explicit rule-based reasoning
    """

    # Known high-risk ports (commonly exploited)
    HIGH_RISK_PORTS = {
        3389,  # RDP
        445,  # SMB
        135,  # RPC
        139,  # NetBIOS
        1433,  # MSSQL
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017,  # MongoDB
    }

    # Medium risk ports
    MEDIUM_RISK_PORTS = {
        21,  # FTP
        23,  # Telnet
        25,  # SMTP
        110,  # POP3
        143,  # IMAP
        8080,  # HTTP alt
        8443,  # HTTPS alt
    }

    # High-risk countries (for demonstration - adjust based on your threat model)
    HIGH_RISK_COUNTRIES = {
        "CN",  # China
        "RU",  # Russia
        "KP",  # North Korea
    }

    # High-risk domain patterns (TLDs and dynamic DNS services)
    HIGH_RISK_DOMAIN_PATTERNS = {
        ".onion",           # Tor hidden services
        ".bit",             # Namecoin (often malware)
        ".bazar",           # Malware TLD
        ".coin",            # Alternative currency TLD
        "duckdns.org",      # Dynamic DNS (C2 common)
        "no-ip.com",        # Dynamic DNS
        "no-ip.org",        # Dynamic DNS
        "no-ip.biz",        # Dynamic DNS
        "ddns.net",         # Dynamic DNS
        "hopto.org",        # Dynamic DNS
        "zapto.org",        # Dynamic DNS
        "sytes.net",        # Dynamic DNS
        "redirectme.net",   # Dynamic DNS
        "bounceme.net",     # Dynamic DNS
        "myftp.org",        # Dynamic DNS
        "myftp.biz",        # Dynamic DNS
        "serveblog.net",    # Dynamic DNS
        "servegame.com",    # Dynamic DNS
    }

    # Suspicious TLDs often used by malware
    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",  # Free/cheap TLDs
        ".work", ".click", ".link", ".loan", ".date",        # Spammy TLDs
        ".win", ".bid", ".download", ".review", ".stream",   # Spammy TLDs
    }

    # Known legitimate domains that should reduce suspicion (partial list)
    TRUSTED_DOMAINS = {
        "google.com", "googleapis.com", "gstatic.com",
        "microsoft.com", "windows.com", "azure.com", "live.com",
        "apple.com", "icloud.com",
        "amazon.com", "amazonaws.com", "cloudfront.net",
        "cloudflare.com", "cloudflare-dns.com",
        "facebook.com", "fbcdn.net",
        "twitter.com", "twimg.com",
        "github.com", "githubusercontent.com",
        "linkedin.com",
        "akamai.com", "akamaiedge.net",
        "fastly.net",
    }

    def __init__(self):
        super().__init__(scorer_id="rule_based")

    def _is_suspicious_domain(self, domain: str) -> tuple[bool, Optional[str]]:
        """
        Check if domain matches known suspicious patterns

        Returns:
            Tuple of (is_suspicious, reason)
        """
        if not domain:
            return False, None

        domain_lower = domain.lower()

        # Check high-risk patterns
        for pattern in self.HIGH_RISK_DOMAIN_PATTERNS:
            if domain_lower.endswith(pattern) or pattern in domain_lower:
                return True, f"dynamic_dns({pattern})"

        # Check suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                return True, f"suspicious_tld({tld})"

        return False, None

    def _is_trusted_domain(self, domain: str) -> bool:
        """Check if domain is from a known trusted source"""
        if not domain:
            return False

        domain_lower = domain.lower()

        for trusted in self.TRUSTED_DOMAINS:
            if domain_lower == trusted or domain_lower.endswith("." + trusted):
                return True

        return False

    def _calculate_domain_entropy(self, domain: str) -> float:
        """
        Calculate Shannon entropy of domain name (for DGA detection)

        High entropy domains are often generated algorithmically
        """
        if not domain:
            return 0.0

        # Extract the main domain part (remove TLD)
        parts = domain.lower().split(".")
        if len(parts) > 1:
            main_part = parts[0]  # First subdomain/domain
        else:
            main_part = domain

        if not main_part:
            return 0.0

        # Calculate character frequency
        freq = {}
        for char in main_part:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        length = len(main_part)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _detect_dga_pattern(self, domain: str) -> tuple[bool, Optional[str]]:
        """
        Detect potential Domain Generation Algorithm (DGA) patterns

        DGA indicators:
        - High entropy (random-looking characters)
        - Unusual consonant/vowel ratio
        - Long subdomain with mixed numbers/letters
        - No recognizable words

        Returns:
            Tuple of (is_dga, reason)
        """
        if not domain:
            return False, None

        # Extract main domain part
        parts = domain.lower().split(".")
        if len(parts) < 2:
            return False, None

        main_part = parts[0]

        # Skip very short domains
        if len(main_part) < 8:
            return False, None

        # Check entropy (typical DGAs have entropy > 3.5)
        entropy = self._calculate_domain_entropy(domain)
        if entropy > 4.0:
            return True, f"high_entropy({entropy:.2f})"

        # Check for excessive numbers mixed with letters
        num_count = sum(1 for c in main_part if c.isdigit())
        letter_count = sum(1 for c in main_part if c.isalpha())

        if num_count > 3 and letter_count > 3:
            ratio = num_count / max(letter_count, 1)
            if 0.3 < ratio < 3.0 and len(main_part) > 12:
                return True, f"mixed_alphanum({num_count}d/{letter_count}a)"

        # Check consonant/vowel ratio (English words have ~0.6 vowel ratio)
        vowels = set("aeiou")
        vowel_count = sum(1 for c in main_part if c in vowels)
        consonant_count = letter_count - vowel_count

        if letter_count > 10:
            vowel_ratio = vowel_count / letter_count
            if vowel_ratio < 0.15 or vowel_ratio > 0.7:
                return True, f"unusual_vowel_ratio({vowel_ratio:.2f})"

        # Check for long strings of consonants (unpronounceable)
        consonant_run = re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', main_part)
        if consonant_run:
            return True, f"consonant_run({consonant_run.group()})"

        return False, None

    def _analyze_tcp_state(self, connection_metadata: Dict) -> tuple[float, list]:
        """
        Analyze TCP connection state for suspicious patterns

        Returns:
            Tuple of (score_adjustment, rules_triggered)
        """
        score_adj = 0.0
        rules = []

        tcp_is_scan = connection_metadata.get("tcp_is_scan", False)
        tcp_syn = connection_metadata.get("tcp_syn", False)
        tcp_ack = connection_metadata.get("tcp_ack", False)
        tcp_rst = connection_metadata.get("tcp_rst", False)

        # SYN-only packets are classic port scan indicators
        if tcp_is_scan:
            score_adj += 0.2
            rules.append("TCP_SCAN_PATTERN")

        # RST without prior connection could indicate blocked/filtered
        if tcp_rst and not tcp_ack:
            score_adj += 0.1
            rules.append("TCP_RST_ONLY")

        return score_adj, rules

    def assess(
        self, dst_ip: str, threat_intel: Dict, geo_data: Dict, connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        Rule-based assessment of threat level

        Applies explicit rules:
        1. Threat intelligence thresholds
        2. Port-based risk classification
        3. Geographic risk assessment
        4. Domain intelligence (DNS queries, TLS SNI)
        5. TCP connection state analysis
        6. Local IOC matches
        7. Combined heuristic scoring
        """
        timestamp = time.time()
        features = {}
        rules_triggered = []
        base_score = 0.0

        # Rule 1: VirusTotal threshold
        vt_data = threat_intel.get("virustotal", {})
        vt_malicious = vt_data.get("malicious_vendors", 0)

        if vt_malicious >= 5:
            base_score += 0.6
            rules_triggered.append(f"VT_HIGH_THREAT({vt_malicious} vendors)")
            features["vt_rule"] = "high_threat"
        elif vt_malicious >= 2:
            base_score += 0.3
            rules_triggered.append(f"VT_MED_THREAT({vt_malicious} vendors)")
            features["vt_rule"] = "medium_threat"

        # Rule 2: AbuseIPDB threshold
        abuseipdb_data = threat_intel.get("abuseipdb", {})
        abuse_confidence = abuseipdb_data.get("confidence_score", 0)

        if abuse_confidence >= 75:
            base_score += 0.5
            rules_triggered.append(f"ABUSEIPDB_HIGH({abuse_confidence}%)")
            features["abuseipdb_rule"] = "high_confidence"
        elif abuse_confidence >= 50:
            base_score += 0.25
            rules_triggered.append(f"ABUSEIPDB_MED({abuse_confidence}%)")
            features["abuseipdb_rule"] = "medium_confidence"

        # Rule 3: Port-based risk
        dst_port = connection_metadata.get("dst_port", 0)

        if dst_port in self.HIGH_RISK_PORTS:
            base_score += 0.3
            rules_triggered.append(f"HIGH_RISK_PORT({dst_port})")
            features["port_risk"] = "high"
        elif dst_port in self.MEDIUM_RISK_PORTS:
            base_score += 0.15
            rules_triggered.append(f"MED_RISK_PORT({dst_port})")
            features["port_risk"] = "medium"
        else:
            features["port_risk"] = "low"

        # Rule 4: Geographic risk
        country_code = geo_data.get("country", "")

        if country_code in self.HIGH_RISK_COUNTRIES:
            base_score += 0.2
            rules_triggered.append(f"HIGH_RISK_GEO({country_code})")
            features["geo_risk"] = "high"
        elif country_code in ("Unknown", ""):
            base_score += 0.1
            rules_triggered.append("UNKNOWN_GEO")
            features["geo_risk"] = "unknown"
        else:
            features["geo_risk"] = "low"

        # Rule 5: Whitelisted IPs (trusted services)
        if abuseipdb_data.get("is_whitelisted", False):
            base_score = max(0.0, base_score - 0.5)
            rules_triggered.append("WHITELISTED")
            features["whitelisted"] = True

        # Rule 6: Domain Intelligence (DNS queries and TLS SNI)
        dns_query = connection_metadata.get("dns_query")
        tls_sni = connection_metadata.get("tls_sni")
        domain = dns_query or tls_sni  # Use whichever is available

        if domain:
            features["domain"] = domain
            features["domain_source"] = "dns" if dns_query else "tls_sni"

            # Check for trusted domain (reduces score)
            if self._is_trusted_domain(domain):
                base_score = max(0.0, base_score - 0.2)
                rules_triggered.append(f"TRUSTED_DOMAIN({domain})")
                features["domain_trust"] = "trusted"
            else:
                # Check for suspicious domain patterns
                is_suspicious, reason = self._is_suspicious_domain(domain)
                if is_suspicious:
                    base_score += 0.25
                    rules_triggered.append(f"SUSPICIOUS_DOMAIN({reason})")
                    features["domain_trust"] = "suspicious"
                    features["domain_suspicious_reason"] = reason

                # Check for DGA patterns
                is_dga, dga_reason = self._detect_dga_pattern(domain)
                if is_dga:
                    base_score += 0.35
                    rules_triggered.append(f"DGA_PATTERN({dga_reason})")
                    features["dga_detected"] = True
                    features["dga_reason"] = dga_reason

                if not is_suspicious and not is_dga:
                    features["domain_trust"] = "neutral"

            # Store domain entropy for analysis
            features["domain_entropy"] = self._calculate_domain_entropy(domain)

        # Rule 7: TCP Connection State Analysis
        tcp_score_adj, tcp_rules = self._analyze_tcp_state(connection_metadata)
        if tcp_score_adj > 0:
            base_score += tcp_score_adj
            rules_triggered.extend(tcp_rules)
            features["tcp_suspicious"] = True

        # Store TCP state for visibility
        tcp_state = connection_metadata.get("tcp_state")
        if tcp_state:
            features["tcp_state"] = tcp_state

        # Rule 8: Local IOC matches (from threat_intel)
        if threat_intel.get("local_ioc_match"):
            base_score += 0.4
            ioc_type = threat_intel.get("local_ioc_type", "unknown")
            rules_triggered.append(f"LOCAL_IOC({ioc_type})")
            features["local_ioc_match"] = True
            features["local_ioc_type"] = ioc_type

        # Rule 9: GreyNoise benign scanner reduction
        if threat_intel.get("greynoise_riot"):
            # Known business service - reduce score
            base_score = max(0.0, base_score - 0.3)
            rules_triggered.append(f"GREYNOISE_RIOT({threat_intel.get('greynoise_name', '')})")
            features["greynoise_verified"] = True
        elif threat_intel.get("greynoise_benign_scanner"):
            # Known benign scanner (Shodan, Censys, etc.)
            base_score = max(0.0, base_score - 0.2)
            rules_triggered.append(f"GREYNOISE_BENIGN({threat_intel.get('greynoise_name', '')})")
            features["benign_scanner"] = True

        # Cap score at 1.0
        final_score = min(1.0, base_score)

        # Confidence calculation
        # Rule-based is deterministic, so confidence is based on data availability
        confidence = 0.7  # Base confidence for rules

        if vt_malicious > 0 or abuse_confidence > 0:
            confidence = 0.9  # Higher confidence with threat intel
        elif domain and (features.get("dga_detected") or features.get("domain_trust") == "suspicious"):
            confidence = 0.85  # Good confidence with domain intelligence
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
            signature=signature,
        )

        self._record_assessment(assessment)
        return assessment
