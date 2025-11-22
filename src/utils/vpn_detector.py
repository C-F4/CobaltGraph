"""
VPN Detection Utilities
Detect and classify VPN-related connections
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class VPNDetector:
    """
    Detect VPN connections and classify traffic

    Identifies:
    - VPN DNS leak prevention (loopback DNS)
    - VPN tunnel endpoints
    - Post-VPN decrypted traffic
    """

    def __init__(self):
        self.vpn_dns_servers = set()  # Track known VPN DNS servers
        self.detected_vpn = False

    def classify_connection(self, conn_data: Dict) -> Dict:
        """
        Classify connection and add VPN metadata

        Args:
            conn_data: Connection dictionary with src_ip, dst_ip, dst_port

        Returns:
            Updated conn_data with 'vpn_classification' field
        """
        src_ip = conn_data.get('src_ip', '')
        dst_ip = conn_data.get('dst_ip', '')
        dst_port = conn_data.get('dst_port', 0)

        classification = {
            'is_vpn_related': False,
            'vpn_type': None,
            'should_display': True,  # Whether to show in dashboard
            'note': None
        }

        # Pattern 1: VPN DNS Protection (src=dst, port 53, private IP)
        if src_ip == dst_ip and dst_port == 53:
            if self._is_private_ip(dst_ip):
                classification['is_vpn_related'] = True
                classification['vpn_type'] = 'dns_leak_prevention'
                classification['should_display'] = False  # Noise - hide from main view
                classification['note'] = f'VPN DNS protection via {dst_ip}'

                # Track VPN DNS server
                self.vpn_dns_servers.add(dst_ip)

                if not self.detected_vpn:
                    logger.info(f"🔒 VPN detected: DNS leak prevention active ({dst_ip})")
                    self.detected_vpn = True

        # Pattern 2: VPN tunnel endpoint (encrypted traffic to VPN server)
        # Note: Hard to detect with ss, would need to check for:
        # - High volume to single IP
        # - Specific ports (OpenVPN: 1194, WireGuard: 51820, etc.)
        elif dst_port in [1194, 1195, 1196, 1197,  # OpenVPN
                          51820,  # WireGuard
                          500, 4500,  # IKEv2/IPsec
                          443, 80] and self._high_connection_rate(dst_ip):
            classification['is_vpn_related'] = True
            classification['vpn_type'] = 'potential_vpn_tunnel'
            classification['note'] = f'Possible VPN tunnel to {dst_ip}:{dst_port}'

        # Pattern 3: Post-VPN decrypted traffic (everything else when VPN detected)
        elif self.detected_vpn and not self._is_private_ip(dst_ip):
            classification['is_vpn_related'] = True
            classification['vpn_type'] = 'via_vpn'
            classification['should_display'] = True
            classification['note'] = 'Connection through VPN (decrypted view)'

        conn_data['vpn_classification'] = classification
        return conn_data

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private (RFC 1918)"""
        if not ip:
            return False

        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True

            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True

            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

            # 127.0.0.0/8 (loopback)
            if first == 127:
                return True

            return False

        except ValueError:
            return False

    def _high_connection_rate(self, ip: str) -> bool:
        """Check if IP has high connection rate (potential VPN server)"""
        # TODO: Implement connection rate tracking
        # For now, return False (would need to track connection history)
        return False

    def get_vpn_info(self) -> Dict:
        """Get detected VPN information"""
        return {
            'vpn_detected': self.detected_vpn,
            'vpn_dns_servers': list(self.vpn_dns_servers),
            'note': 'VPN DNS leak prevention active' if self.detected_vpn else None
        }

    def should_suppress_connection(self, conn_data: Dict) -> bool:
        """
        Check if connection should be suppressed from display

        Useful for filtering dashboard views
        """
        if 'vpn_classification' not in conn_data:
            return False

        classification = conn_data['vpn_classification']
        return not classification.get('should_display', True)
