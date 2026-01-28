"""
Rule-Based Threat Scorer
Uses expert-defined heuristics and rules

Approach:
- Pattern matching on known threat indicators
- Port-based classification (expanded high/medium/malware port lists)
- Geographic risk assessment (3-tier model)
- Domain/hostname intelligence (80+ DDNS patterns, 40+ suspicious TLDs)
- TCP connection state analysis
- GreyNoise RIOT/NOISE integration
- OTX pulse intelligence integration
- Enhanced DGA detection (consonant clustering, hex patterns)
- Deterministic rule evaluation
"""

import math
import re
import time
from typing import Dict, List, Optional, Set, Tuple

from .scorer_base import ScorerAssessment, ThreatScorer


class RuleScorer(ThreatScorer):
    """
    Expert rule-based threat scorer

    Features:
    - Known malicious port detection (45+ high-risk, 25+ medium-risk)
    - Geographic risk zones (3-tier model)
    - Threat intelligence thresholds
    - Domain intelligence (DNS queries, TLS SNI)
    - DGA detection (Domain Generation Algorithm) - enhanced
    - TCP connection state analysis
    - GreyNoise RIOT/NOISE classification
    - OTX pulse intelligence
    - Explicit rule-based reasoning
    """

    # Known high-risk ports (commonly exploited services)
    # Expanded from 9 to 45+ ports
    HIGH_RISK_PORTS = {
        # Remote Access - Primary targets
        3389,   # RDP - most attacked service
        22,     # SSH - brute force target
        23,     # Telnet - unencrypted legacy
        5900,   # VNC - remote desktop
        5901,   # VNC :1
        5902,   # VNC :2
        # SMB/Windows Networking - Ransomware vectors
        445,    # SMB - WannaCry, NotPetya
        135,    # MSRPC - DCE endpoint mapper
        139,    # NetBIOS Session
        137,    # NetBIOS Name Service
        138,    # NetBIOS Datagram
        # Databases - Data exfiltration targets
        1433,   # MSSQL
        1434,   # MSSQL Browser
        3306,   # MySQL
        5432,   # PostgreSQL
        6379,   # Redis - often unauth
        27017,  # MongoDB - often unauth
        27018,  # MongoDB secondary
        9042,   # Cassandra CQL
        5984,   # CouchDB
        11211,  # Memcached - amplification attacks
        # Container/Orchestration - Supply chain
        2375,   # Docker API unencrypted
        2376,   # Docker API TLS
        2377,   # Docker Swarm
        6443,   # Kubernetes API
        10250,  # Kubelet API
        10255,  # Kubelet read-only
        2379,   # etcd client
        2380,   # etcd peer
        # Management interfaces
        161,    # SNMP - info disclosure
        162,    # SNMP Trap
        623,    # IPMI - BMC access
        5986,   # WinRM HTTPS
        5985,   # WinRM HTTP
        # Legacy exploitable services
        512,    # rexec
        513,    # rlogin
        514,    # rsh/syslog
        1099,   # Java RMI
        1524,   # ingreslock (backdoor)
        111,    # RPC portmapper
        2049,   # NFS
        # Web management
        10000,  # Webmin
        2082,   # cPanel
        2083,   # cPanel SSL
        8291,   # Mikrotik Winbox
    }

    # Medium risk ports - elevated monitoring
    # Expanded from 7 to 25+ ports
    MEDIUM_RISK_PORTS = {
        # Email - Spam/phishing vectors
        25,     # SMTP
        110,    # POP3
        143,    # IMAP
        465,    # SMTPS
        587,    # Submission
        993,    # IMAPS
        995,    # POP3S
        # Web alternates - potential C2
        8080,   # HTTP alt
        8443,   # HTTPS alt
        8000,   # HTTP alt
        8888,   # HTTP proxy
        9000,   # Various services
        9443,   # HTTPS alt
        # VPN/Tunneling
        1194,   # OpenVPN
        1723,   # PPTP
        500,    # ISAKMP/IKE
        4500,   # NAT-T
        # Messaging/Queue
        5672,   # AMQP
        1883,   # MQTT
        9092,   # Kafka
        # Proxy
        1080,   # SOCKS
        3128,   # Squid
        8118,   # Privoxy
        # Directory
        389,    # LDAP
        636,    # LDAPS
        88,     # Kerberos
    }

    # Malware-specific ports - commonly used by malware families
    MALWARE_PORTS = {
        4444,   # Metasploit default
        5555,   # Android ADB
        6666,   # IRC botnets
        6667,   # IRC
        6668,   # IRC alt
        6669,   # IRC alt
        31337,  # Back Orifice
        12345,  # NetBus
        54321,  # Back Orifice 2000
        20000,  # Millenium
        1234,   # Sub7
        27374,  # Sub7
        7777,   # Trin00
        65535,  # RC1 trojan
        9999,   # RAT common
        1337,   # Elite/leet
        1338,   # Wanna Cry
        9001,   # Tor (suspicious as dest)
        9050,   # Tor SOCKS
    }

    # High-risk countries - State-sponsored APT activity
    # Expanded from 3 to 7 countries
    HIGH_RISK_COUNTRIES = {
        "CN",  # China - APT1, APT10, APT41
        "RU",  # Russia - APT28, APT29, Sandworm
        "KP",  # North Korea - Lazarus, Kimsuky
        "IR",  # Iran - APT33, APT34, APT35
        "BY",  # Belarus - GhostWriter
        "SY",  # Syria - SEA
        "VE",  # Venezuela - APT-C-36
    }

    # Elevated risk countries - High cybercrime, weak regulations
    ELEVATED_RISK_COUNTRIES = {
        "UA",  # Ukraine
        "VN",  # Vietnam - OceanLotus
        "PK",  # Pakistan - APT36
        "NG",  # Nigeria - BEC
        "RO",  # Romania - cybercrime
        "MD",  # Moldova
        "BG",  # Bulgaria
        "BR",  # Brazil - banking trojans
        "ID",  # Indonesia
        "PH",  # Philippines - BEC
    }

    # High-risk domain patterns (DDNS, anonymizers, suspicious TLDs)
    # Expanded from 17 to 80+ patterns
    HIGH_RISK_DOMAIN_PATTERNS = {
        # Tor/Anonymizer TLDs
        ".onion",           # Tor hidden services
        ".i2p",             # I2P network
        ".bit",             # Namecoin (malware common)
        ".bazar",           # Malware TLD
        ".coin",            # Alternative currency TLD
        ".lib",             # Namecoin
        # Dynamic DNS - Heavily abused for C2
        "duckdns.org",
        "no-ip.com", "no-ip.org", "no-ip.biz", "no-ip.info",
        "noip.com",
        "ddns.net", "ddns.org",
        "hopto.org",
        "zapto.org",
        "sytes.net",
        "redirectme.net",
        "bounceme.net",
        "myftp.org", "myftp.biz",
        "serveblog.net",
        "servegame.com",
        "servehttp.com",
        "serveftp.com",
        "servequake.com",
        "servebeer.com",
        "servemp3.com",
        "servepics.com",
        "webhop.me",
        "freedns.afraid.org",
        "changeip.com", "changeip.net", "changeip.org",
        "dns.army", "dns.navy",
        "dnsalias.com", "dnsalias.net", "dnsalias.org",
        "dnsdynamic.org",
        "dyndns.org", "dyndns.com", "dyndns.info", "dyndns.tv",
        "dynalias.com", "dynalias.net", "dynalias.org",
        "dynu.com", "dynu.net",
        "afraid.org",
        "3utilities.com",
        "4mydomain.com",
        "ddnsfree.com",
        "dlinkddns.com",
        "freeddns.com", "freeddns.org",
        "dns2go.com",
        "now-dns.com", "now-dns.net", "now-dns.org",
        "publicvm.com",
        "gotdns.ch", "gotdns.com", "gotdns.org",
        "redirectme.net",
        "pointto.us",
        "trickip.net", "trickip.org",
        "yi.org",
        "selfip.com", "selfip.net", "selfip.org",
        "mooo.com",
        "homelinux.com", "homelinux.org",
        # URL Shorteners - phishing/redirect
        "bit.ly", "bitly.com",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "j.mp",
        "rebrand.ly",
        "cutt.ly",
        # Pastebin/Code sharing - malware delivery
        "pastebin.com",
        "paste.ee",
        "ghostbin.co",
        "hastebin.com",
        "dpaste.org",
        "codepad.org",
        "ideone.com",
        "controlc.com",
        "pasteio.com",
        # File sharing - malware distribution
        "mega.nz", "mega.co.nz",
        "mediafire.com",
        "zippyshare.com",
        "sendspace.com",
        "4shared.com",
        "rapidshare.com",
        "uploaded.net",
        "uploadfiles.io",
        "file.io",
        "transfer.sh",
        "gofile.io",
        "anonfiles.com",
        "bayfiles.com",
        # VPN/Proxy services (indicator of evasion)
        "hide.me",
        "nordvpn.com",
        "expressvpn.com",
        "privateinternetaccess.com",
        "protonvpn.com",
    }

    # Suspicious TLDs - cheap/free, high abuse rate
    # Expanded from 12 to 40+ TLDs
    SUSPICIOUS_TLDS = {
        # Free TLDs - extremely high abuse
        ".tk", ".ml", ".ga", ".cf", ".gq",
        # Cheap gTLDs - high spam/malware
        ".xyz", ".top", ".club", ".online", ".site", ".website",
        ".work", ".click", ".link", ".loan", ".date",
        ".win", ".bid", ".download", ".review", ".stream",
        ".racing", ".science", ".party", ".trade", ".accountant",
        ".cricket", ".faith", ".men", ".gdn", ".icu",
        ".buzz", ".monster", ".quest", ".cam",
        # High-abuse ccTLDs
        ".cc", ".ws", ".to", ".su", ".pw",
        ".cx", ".nu", ".la", ".me.uk",
        # Uncommon/suspicious
        ".kim", ".wang", ".vip", ".ren", ".xin",
        ".pro", ".biz", ".info",  # Often abused
    }

    # Known legitimate domains - expanded from 30 to 100+
    TRUSTED_DOMAINS = {
        # Google ecosystem
        "google.com", "googleapis.com", "gstatic.com",
        "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
        "gmail.com", "googlemail.com",
        "android.com", "google.co.uk", "google.de", "google.fr",
        "google.ca", "google.com.au", "google.co.jp",
        "googleusercontent.com", "googleadservices.com",
        "googlesyndication.com", "doubleclick.net",
        "firebase.google.com", "firebaseio.com",
        "gvt1.com", "gvt2.com", "gvt3.com",
        # Microsoft ecosystem
        "microsoft.com", "windows.com", "azure.com", "live.com",
        "office.com", "office365.com", "outlook.com", "hotmail.com",
        "msn.com", "bing.com", "msedge.net",
        "microsoftonline.com", "microsoftazure.com",
        "windowsupdate.com", "windows.net",
        "sharepoint.com", "onedrive.com", "onenote.com",
        "visualstudio.com", "vsassets.io",
        "xbox.com", "xboxlive.com",
        "skype.com", "teams.microsoft.com",
        "linkedin.com", "licdn.com",
        "github.com", "githubusercontent.com", "githubassets.com",
        "npmjs.com", "npmjs.org",
        # Apple ecosystem
        "apple.com", "icloud.com", "icloud-content.com",
        "apple-dns.net", "mzstatic.com",
        "itunes.com", "itunes.apple.com",
        # Amazon/AWS ecosystem
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
        "amazonaws.com", "aws.amazon.com", "awsstatic.com",
        "cloudfront.net", "elasticbeanstalk.com",
        "s3.amazonaws.com",
        # Cloudflare
        "cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com",
        "cdnjs.cloudflare.com",
        # Meta/Facebook
        "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com",
        "instagram.com", "cdninstagram.com",
        "whatsapp.com", "whatsapp.net",
        "messenger.com",
        # Twitter/X
        "twitter.com", "x.com", "twimg.com", "t.co", "twitpic.com",
        # CDNs and infrastructure
        "akamai.com", "akamaiedge.net", "akamaihd.net",
        "edgekey.net", "edgesuite.net",
        "fastly.net", "fastlylb.net",
        "edgecastcdn.net", "llnwd.net",
        "stackpathdns.com", "stackpathcdn.com",
        "jsdelivr.net", "unpkg.com",
        # Security vendors
        "virustotal.com", "crowdstrike.com", "sentinelone.net",
        "paloaltonetworks.com", "checkpoint.com",
        "mcafee.com", "symantec.com", "norton.com",
        "kaspersky.com", "avast.com", "avg.com",
        "malwarebytes.com", "bitdefender.com",
        # Enterprise software
        "salesforce.com", "force.com", "lightning.force.com",
        "slack.com", "slack-edge.com",
        "zoom.us", "zoomgov.com",
        "dropbox.com", "dropboxapi.com",
        "box.com", "boxcdn.net",
        "atlassian.com", "atlassian.net", "jira.com",
        "confluence.com", "bitbucket.org",
        "zendesk.com",
        "servicenow.com",
        "workday.com",
        "okta.com", "oktapreview.com",
        "auth0.com",
        # Payment processors
        "paypal.com", "paypalobjects.com",
        "stripe.com", "stripe.network",
        "braintreegateway.com", "braintree-api.com",
        "squareup.com", "square.com",
        "adyen.com",
        # Other major services
        "netflix.com", "nflxvideo.net",
        "spotify.com", "scdn.co",
        "reddit.com", "redd.it", "redditmedia.com",
        "wikipedia.org", "wikimedia.org",
        "twitch.tv", "twitchcdn.net",
        "discord.com", "discordapp.com", "discord.gg",
        "adobe.com", "adobelogin.com", "typekit.net",
        "oracle.com", "oraclecloud.com",
        "ibm.com", "ibmcloud.com",
        "sap.com", "hana.ondemand.com",
        "docker.com", "docker.io",
        "elastic.co", "elasticsearch.org",
        "datadog.com", "datadoghq.com",
        "splunk.com", "splunkcloud.com",
        "newrelic.com",
        "pagerduty.com",
    }

    # OTX critical tags indicating severe threats
    OTX_CRITICAL_TAGS = {
        "apt", "ransomware", "c2", "c&c", "command and control",
        "cobalt strike", "beacon", "emotet", "trickbot", "qakbot",
        "botnet", "rat", "backdoor", "zero-day", "exploit",
        "lazarus", "apt28", "apt29", "apt41", "sandworm",
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

        Enhanced DGA indicators:
        - High entropy (random-looking characters)
        - Unusual consonant/vowel ratio
        - Long subdomain with mixed numbers/letters
        - No recognizable words
        - Consonant clustering (consecutive consonants)
        - Hex-like patterns (0-9, a-f only)
        - Repeated character patterns

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

        # Track multiple DGA signals for combined scoring
        dga_signals = []

        # Check 1: High entropy (typical DGAs have entropy > 3.5)
        entropy = self._calculate_domain_entropy(domain)
        if entropy > 4.0:
            dga_signals.append(f"high_entropy({entropy:.2f})")
        elif entropy > 3.7:
            dga_signals.append(f"elevated_entropy({entropy:.2f})")

        # Check 2: Hex-like pattern detection (NEW)
        hex_chars = set("0123456789abcdef")
        hex_count = sum(1 for c in main_part if c in hex_chars)
        alnum_count = sum(1 for c in main_part if c.isalnum())

        if alnum_count > 0:
            hex_ratio = hex_count / alnum_count
            if hex_ratio >= 0.95 and len(main_part) >= 12:
                return True, "hex_pattern_strong"
            elif hex_ratio >= 0.90 and len(main_part) >= 8:
                dga_signals.append(f"hex_pattern({hex_ratio:.2f})")

        # Check 3: Excessive numbers mixed with letters
        num_count = sum(1 for c in main_part if c.isdigit())
        letter_count = sum(1 for c in main_part if c.isalpha())

        if num_count > 3 and letter_count > 3:
            ratio = num_count / max(letter_count, 1)
            if 0.3 < ratio < 3.0 and len(main_part) > 12:
                dga_signals.append(f"mixed_alphanum({num_count}d/{letter_count}a)")

        # Check 4: Consonant/vowel ratio
        vowels = set("aeiou")
        vowel_count = sum(1 for c in main_part if c in vowels)
        consonant_count = letter_count - vowel_count

        if letter_count > 10:
            vowel_ratio = vowel_count / letter_count
            if vowel_ratio < 0.15:
                dga_signals.append(f"consonant_heavy({vowel_ratio:.2f})")
            elif vowel_ratio > 0.7:
                dga_signals.append(f"vowel_heavy({vowel_ratio:.2f})")

        # Check 5: Consonant clustering (5+ consecutive consonants)
        consonant_run = re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', main_part)
        if consonant_run:
            run = consonant_run.group()
            if len(run) >= 6:
                return True, f"consonant_cluster({run})"
            dga_signals.append(f"consonant_run({run})")

        # Check 6: Repeated character patterns (NEW)
        # Detect patterns like "aaaa", "abab", "abcabc"
        if len(main_part) >= 8:
            # Check for same char repeated 4+ times
            repeat_match = re.search(r'(.)\1{3,}', main_part)
            if repeat_match:
                dga_signals.append(f"char_repeat({repeat_match.group()})")

            # Check for 2-char pattern repeated 3+ times
            pattern_match = re.search(r'(.{2,3})\1{2,}', main_part)
            if pattern_match:
                dga_signals.append(f"pattern_repeat({pattern_match.group()})")

        # Check 7: Alternating digit-letter pattern (common in DGA)
        if len(main_part) >= 10:
            alternating = 0
            for i in range(len(main_part) - 1):
                c1, c2 = main_part[i], main_part[i+1]
                if (c1.isdigit() and c2.isalpha()) or (c1.isalpha() and c2.isdigit()):
                    alternating += 1
            if alternating >= len(main_part) // 2:
                dga_signals.append("alternating_pattern")

        # Decision: Multiple weak signals or one strong signal
        if len(dga_signals) >= 2:
            return True, "+".join(dga_signals[:3])
        elif len(dga_signals) == 1 and any(
            s.startswith(("high_entropy", "hex_pattern", "consonant_cluster"))
            for s in dga_signals
        ):
            return True, dga_signals[0]

        return False, None

    def _check_greynoise(self, threat_intel: Dict) -> Tuple[float, List[str]]:
        """
        Check GreyNoise RIOT/NOISE classification

        Returns:
            Tuple of (score_adjustment, rules_triggered)
        """
        score_adj = 0.0
        rules = []

        # RIOT - Rule It Out - Known business services
        if threat_intel.get("greynoise_riot"):
            name = threat_intel.get("greynoise_name", "")
            category = threat_intel.get("greynoise_category", "")
            trust_level = threat_intel.get("greynoise_trust_level", "")

            if trust_level == "1":
                # High trust RIOT - significant reduction
                score_adj = -0.35
                rules.append(f"GREYNOISE_RIOT_HIGH({name or category})")
            else:
                # Standard RIOT
                score_adj = -0.25
                rules.append(f"GREYNOISE_RIOT({name or category})")
            return score_adj, rules

        # NOISE - Known scanner
        if threat_intel.get("greynoise_noise"):
            classification = threat_intel.get("greynoise_classification", "unknown")
            name = threat_intel.get("greynoise_name", "")

            if classification == "benign":
                # Benign scanner (Shodan, Censys, etc.)
                score_adj = -0.20
                rules.append(f"GREYNOISE_BENIGN({name})")
            elif classification == "malicious":
                # Known malicious scanner
                score_adj = 0.30
                rules.append(f"GREYNOISE_MALICIOUS({name})")
            else:
                # Unknown classification - neutral
                rules.append(f"GREYNOISE_NOISE({name})")

        return score_adj, rules

    def _check_otx(self, threat_intel: Dict) -> Tuple[float, List[str]]:
        """
        Check OTX (AlienVault Open Threat Exchange) pulse data

        Returns:
            Tuple of (score_adjustment, rules_triggered)
        """
        otx_data = threat_intel.get("otx", {})
        if not otx_data:
            return 0.0, []

        score_adj = 0.0
        rules = []

        pulse_count = otx_data.get("pulse_count", 0)
        tags = otx_data.get("tags", [])

        # Score based on pulse count
        if pulse_count >= 10:
            score_adj = 0.45
            rules.append(f"OTX_HIGH_PULSE({pulse_count})")
        elif pulse_count >= 5:
            score_adj = 0.30
            rules.append(f"OTX_MED_PULSE({pulse_count})")
        elif pulse_count >= 2:
            score_adj = 0.15
            rules.append(f"OTX_LOW_PULSE({pulse_count})")
        elif pulse_count == 1:
            score_adj = 0.05
            rules.append("OTX_SINGLE_PULSE")

        # Check for critical tags
        tags_lower = {t.lower() for t in tags}
        for critical_tag in self.OTX_CRITICAL_TAGS:
            if critical_tag in tags_lower:
                score_adj = min(1.0, score_adj + 0.20)
                rules.append(f"OTX_CRITICAL_TAG({critical_tag})")
                break  # Only add once

            # Partial match
            for tag in tags_lower:
                if critical_tag in tag and f"OTX_TAG({tag})" not in rules:
                    score_adj = min(1.0, score_adj + 0.10)
                    rules.append(f"OTX_TAG({tag})")
                    break

        return score_adj, rules

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
        1. Threat intelligence thresholds (VT, AbuseIPDB)
        2. Port-based risk classification (high/medium/malware)
        3. Geographic risk assessment (3-tier model)
        4. Domain intelligence (DNS queries, TLS SNI)
        5. TCP connection state analysis
        6. Local IOC matches
        7. GreyNoise RIOT/NOISE classification
        8. OTX pulse intelligence
        9. Combined heuristic scoring
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

        # Rule 3: Port-based risk (expanded with malware ports)
        dst_port = connection_metadata.get("dst_port", 0)

        if dst_port in self.MALWARE_PORTS:
            base_score += 0.45
            rules_triggered.append(f"MALWARE_PORT({dst_port})")
            features["port_risk"] = "malware"
        elif dst_port in self.HIGH_RISK_PORTS:
            base_score += 0.30
            rules_triggered.append(f"HIGH_RISK_PORT({dst_port})")
            features["port_risk"] = "high"
        elif dst_port in self.MEDIUM_RISK_PORTS:
            base_score += 0.15
            rules_triggered.append(f"MED_RISK_PORT({dst_port})")
            features["port_risk"] = "medium"
        else:
            features["port_risk"] = "low"

        # Rule 4: Geographic risk (3-tier model)
        country_code = geo_data.get("country", "")

        if country_code in self.HIGH_RISK_COUNTRIES:
            base_score += 0.25
            rules_triggered.append(f"HIGH_RISK_GEO({country_code})")
            features["geo_risk"] = "high"
        elif country_code in self.ELEVATED_RISK_COUNTRIES:
            base_score += 0.12
            rules_triggered.append(f"ELEVATED_RISK_GEO({country_code})")
            features["geo_risk"] = "elevated"
        elif country_code in ("Unknown", ""):
            base_score += 0.10
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
                base_score = max(0.0, base_score - 0.25)
                rules_triggered.append(f"TRUSTED_DOMAIN({domain})")
                features["domain_trust"] = "trusted"
            else:
                # Check for suspicious domain patterns
                is_suspicious, reason = self._is_suspicious_domain(domain)
                if is_suspicious:
                    base_score += 0.28
                    rules_triggered.append(f"SUSPICIOUS_DOMAIN({reason})")
                    features["domain_trust"] = "suspicious"
                    features["domain_suspicious_reason"] = reason

                # Check for DGA patterns (enhanced detection)
                is_dga, dga_reason = self._detect_dga_pattern(domain)
                if is_dga:
                    base_score += 0.38
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
            base_score += 0.45
            ioc_type = threat_intel.get("local_ioc_type", "unknown")
            rules_triggered.append(f"LOCAL_IOC({ioc_type})")
            features["local_ioc_match"] = True
            features["local_ioc_type"] = ioc_type

        # Rule 9: GreyNoise RIOT/NOISE classification (enhanced)
        gn_score_adj, gn_rules = self._check_greynoise(threat_intel)
        if gn_score_adj != 0:
            base_score = max(0.0, base_score + gn_score_adj)
            rules_triggered.extend(gn_rules)
            features["greynoise_checked"] = True
            if gn_score_adj < 0:
                features["greynoise_benign"] = True
            elif gn_score_adj > 0:
                features["greynoise_malicious"] = True

        # Rule 10: OTX pulse intelligence (NEW)
        otx_score_adj, otx_rules = self._check_otx(threat_intel)
        if otx_score_adj > 0:
            base_score += otx_score_adj
            rules_triggered.extend(otx_rules)
            features["otx_checked"] = True
            features["otx_pulse_count"] = threat_intel.get("otx", {}).get("pulse_count", 0)

        # Cap score at 1.0
        final_score = min(1.0, base_score)

        # Confidence calculation
        # Rule-based is deterministic, so confidence is based on data availability
        confidence = 0.7  # Base confidence for rules

        if vt_malicious > 0 or abuse_confidence > 0:
            confidence = 0.92  # High confidence with threat intel
        elif features.get("otx_pulse_count", 0) > 0:
            confidence = 0.88  # Good confidence with OTX data
        elif domain and (features.get("dga_detected") or features.get("domain_trust") == "suspicious"):
            confidence = 0.85  # Good confidence with domain intelligence
        elif dst_port in (self.HIGH_RISK_PORTS | self.MEDIUM_RISK_PORTS | self.MALWARE_PORTS):
            confidence = 0.80  # Moderate confidence with port heuristics
        elif features.get("greynoise_benign"):
            confidence = 0.85  # Good confidence from GreyNoise verification

        # Generate reasoning
        if rules_triggered:
            reasoning = "Rules triggered: " + ", ".join(rules_triggered[:8])  # Limit for readability
            if len(rules_triggered) > 8:
                reasoning += f" (+{len(rules_triggered) - 8} more)"
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
