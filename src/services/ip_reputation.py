#!/usr/bin/env python3
"""
IP Reputation Service - Clean Minimal Version
Queries VirusTotal and AbuseIPDB for threat intelligence
"""

import requests
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class IPReputation:
    """
    Minimal IP reputation checker
    Queries threat intelligence APIs and returns normalized scores
    """

    def __init__(self, config):
        """Initialize with API keys from config"""
        self.config = config
        self.vt_api_key = config.get('virustotal_api_key')
        self.abuseipdb_api_key = config.get('abuseipdb_api_key')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CobaltGraph/1.0'})

    def check_ip(self, ip_address: str) -> Dict:
        """
        Check IP reputation across multiple sources

        Returns dict with:
        - threat_score: 0.0-1.0 (normalized)
        - vt_positives: Number of VirusTotal detections
        - abuse_confidence_score: AbuseIPDB confidence (0-100)
        - sources_checked: List of sources queried
        """
        result = {
            'threat_score': 0.2,  # Default fallback
            'vt_positives': 0,
            'vt_total': 0,
            'abuse_confidence_score': 0,
            'sources_checked': []
        }

        # Query VirusTotal
        if self.vt_api_key:
            try:
                vt_data = self._query_virustotal(ip_address)
                if vt_data:
                    result['vt_positives'] = vt_data.get('positives', 0)
                    result['vt_total'] = vt_data.get('total', 0)
                    result['sources_checked'].append('virustotal')
            except Exception as e:
                logger.debug(f"VirusTotal query failed: {e}")

        # Query AbuseIPDB
        if self.abuseipdb_api_key:
            try:
                abuse_data = self._query_abuseipdb(ip_address)
                if abuse_data:
                    result['abuse_confidence_score'] = abuse_data.get('abuseConfidenceScore', 0)
                    result['sources_checked'].append('abuseipdb')
            except Exception as e:
                logger.debug(f"AbuseIPDB query failed: {e}")

        # Calculate normalized threat score
        result['threat_score'] = self._calculate_threat_score(result)

        return result

    def _query_virustotal(self, ip_address: str) -> Optional[Dict]:
        """Query VirusTotal API"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {'x-apikey': self.vt_api_key}

        response = self.session.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                'total': sum(stats.values())
            }
        return None

    def _query_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        """Query AbuseIPDB API"""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': self.abuseipdb_api_key}
        params = {'ipAddress': ip_address, 'maxAgeInDays': 90}

        response = self.session.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json().get('data', {})
        return None

    def _calculate_threat_score(self, data: Dict) -> float:
        """Calculate normalized threat score (0.0-1.0)"""
        score = 0.0

        # VirusTotal contribution (0-5 detections = 0.0-0.5)
        if data['vt_total'] > 0:
            vt_ratio = data['vt_positives'] / data['vt_total']
            score += min(vt_ratio * 0.5, 0.5)

        # AbuseIPDB contribution (0-100 confidence = 0.0-0.5)
        abuse_score = data['abuse_confidence_score'] / 200.0  # Normalize to 0-0.5
        score += abuse_score

        return min(score, 1.0)  # Cap at 1.0
