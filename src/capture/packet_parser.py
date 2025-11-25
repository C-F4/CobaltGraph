"""
CobaltGraph Packet Parser Utilities
Raw packet parsing and protocol handling

Utilities:
- Ethernet frame parsing
- IP header parsing
- TCP/UDP header parsing
- MAC address formatting
- Protocol identification
"""

import logging
import struct
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Protocol numbers
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


def parse_ethernet_frame(data: bytes) -> Tuple[str, str, int, bytes]:
    """
    Parse Ethernet frame

    Args:
        data: Raw packet data

    Returns:
        Tuple of (dst_mac, src_mac, eth_proto, payload)
    """
    # Ethernet header is 14 bytes
    dst_mac, src_mac, eth_proto = struct.unpack("! 6s 6s H", data[:14])

    return (format_mac(dst_mac), format_mac(src_mac), eth_proto, data[14:])  # Payload


def parse_ipv4_header(data: bytes) -> Tuple[str, str, int, bytes]:
    """
    Parse IPv4 header

    Args:
        data: IP packet data

    Returns:
        Tuple of (src_ip, dst_ip, protocol, payload)
    """
    # IPv4 header: Version + IHL (1 byte), then skip to addresses
    version_ihl = data[0]
    ihl = (version_ihl & 0xF) * 4  # Internet Header Length in bytes

    # Skip to source/dest IPs (bytes 12-19)
    src_ip = format_ipv4(data[12:16])
    dst_ip = format_ipv4(data[16:20])

    # Protocol is at byte 9
    protocol = data[9]

    return (src_ip, dst_ip, protocol, data[ihl:])


def parse_tcp_header(data: bytes) -> Tuple[int, int]:
    """
    Parse TCP header

    Args:
        data: TCP segment

    Returns:
        Tuple of (src_port, dst_port)
    """
    # TCP header starts with src port (2 bytes) and dst port (2 bytes)
    src_port, dst_port = struct.unpack("! H H", data[:4])
    return (src_port, dst_port)


def parse_udp_header(data: bytes) -> Tuple[int, int]:
    """
    Parse UDP header

    Args:
        data: UDP datagram

    Returns:
        Tuple of (src_port, dst_port)
    """
    # UDP header: src port (2 bytes), dst port (2 bytes)
    src_port, dst_port = struct.unpack("! H H", data[:4])
    return (src_port, dst_port)


def format_mac(mac_bytes: bytes) -> str:
    """
    Format MAC address bytes as string

    Args:
        mac_bytes: 6-byte MAC address

    Returns:
        String like "aa:bb:cc:dd:ee:ff"
    """
    return ":".join(f"{b:02x}" for b in mac_bytes)


def format_ipv4(ip_bytes: bytes) -> str:
    """
    Format IPv4 address bytes as string

    Args:
        ip_bytes: 4-byte IP address

    Returns:
        String like "192.168.1.1"
    """
    return ".".join(str(b) for b in ip_bytes)


def get_protocol_name(proto_num: int) -> str:
    """
    Get protocol name from number

    Args:
        proto_num: Protocol number

    Returns:
        Protocol name (TCP, UDP, ICMP, etc.)
    """
    protocols = {
        PROTO_ICMP: "ICMP",
        PROTO_TCP: "TCP",
        PROTO_UDP: "UDP",
    }
    return protocols.get(proto_num, f"PROTO_{proto_num}")


def parse_full_packet(data: bytes) -> Optional[Dict]:
    """
    Parse complete packet from Ethernet to Transport layer

    Args:
        data: Raw packet data

    Returns:
        Dict with parsed fields or None if parsing fails
    """
    try:
        # Parse Ethernet
        dst_mac, src_mac, eth_proto, ip_data = parse_ethernet_frame(data)

        # Check if IPv4 (0x0800)
        if eth_proto != 0x0800:
            return None

        # Parse IP
        src_ip, dst_ip, protocol, transport_data = parse_ipv4_header(ip_data)

        # Parse transport layer
        if protocol == PROTO_TCP:
            src_port, dst_port = parse_tcp_header(transport_data)
        elif protocol == PROTO_UDP:
            src_port, dst_port = parse_udp_header(transport_data)
        else:
            src_port, dst_port = 0, 0

        return {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": get_protocol_name(protocol),
        }

    except Exception as e:
        logger.debug("Packet parsing error: %s", e)
        return None
