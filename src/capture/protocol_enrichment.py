"""
Protocol Enrichment Module for CobaltGraph
Extracts application-layer intelligence from network packets

Capabilities:
- DNS query extraction (domain names from UDP/53 packets)
- TLS SNI extraction (hostname from ClientHello)
- TCP flags extraction (connection state indicators)

All parsers return Optional - graceful degradation on malformed data.
No external dependencies - pure Python packet parsing.
"""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class DNSQuery:
    """Extracted DNS query information"""
    domain: str
    query_type: str  # A, AAAA, CNAME, MX, etc.
    transaction_id: int = 0
    is_response: bool = False
    response_code: int = 0  # RCODE: 0=NOERROR, 3=NXDOMAIN, etc.


@dataclass
class TLSInfo:
    """Extracted TLS ClientHello information"""
    sni: str  # Server Name Indication (hostname)
    version: str  # TLS version string
    cipher_suites_count: int = 0
    extensions_count: int = 0
    ja3_components: Dict[str, str] = field(default_factory=dict)  # For JA3 fingerprinting


@dataclass
class TCPFlags:
    """TCP connection state flags"""
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False

    @property
    def connection_state(self) -> str:
        """Interpret flags as connection state"""
        if self.syn and not self.ack:
            return "SYN"  # Connection initiation
        elif self.syn and self.ack:
            return "SYN-ACK"  # Connection response
        elif self.fin:
            return "FIN"  # Connection termination
        elif self.rst:
            return "RST"  # Connection reset
        elif self.ack and self.psh:
            return "DATA"  # Data transfer
        elif self.ack:
            return "ACK"  # Acknowledgment
        return "UNKNOWN"

    @property
    def is_scan_pattern(self) -> bool:
        """Detect potential port scan patterns"""
        # SYN-only packets are classic port scan indicators
        return self.syn and not self.ack and not self.fin and not self.rst


@dataclass
class ProtocolEnrichment:
    """Combined protocol enrichment data for a connection"""
    dns_query: Optional[DNSQuery] = None
    tls_info: Optional[TLSInfo] = None
    tcp_flags: Optional[TCPFlags] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage/transmission"""
        result = {}

        if self.dns_query:
            result["dns_query"] = self.dns_query.domain
            result["dns_query_type"] = self.dns_query.query_type
            result["dns_is_response"] = self.dns_query.is_response
            result["dns_response_code"] = self.dns_query.response_code

        if self.tls_info:
            result["tls_sni"] = self.tls_info.sni
            result["tls_version"] = self.tls_info.version
            result["tls_cipher_count"] = self.tls_info.cipher_suites_count

        if self.tcp_flags:
            result["tcp_state"] = self.tcp_flags.connection_state
            result["tcp_syn"] = self.tcp_flags.syn
            result["tcp_ack"] = self.tcp_flags.ack
            result["tcp_fin"] = self.tcp_flags.fin
            result["tcp_rst"] = self.tcp_flags.rst
            result["tcp_is_scan"] = self.tcp_flags.is_scan_pattern

        return result


class DNSParser:
    """
    Parse DNS queries and responses from UDP payload

    DNS Packet Format:
    - Header: 12 bytes (ID, Flags, QDCount, ANCount, NSCount, ARCount)
    - Questions: Variable (QNAME, QTYPE, QCLASS)
    - Answers: Variable (for responses)
    """

    # DNS Query Types
    QUERY_TYPES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    @classmethod
    def parse(cls, udp_payload: bytes) -> Optional[DNSQuery]:
        """
        Parse DNS packet from UDP payload

        Args:
            udp_payload: Raw UDP payload bytes (after UDP header)

        Returns:
            DNSQuery if valid DNS packet, None otherwise
        """
        try:
            if len(udp_payload) < 12:
                return None

            # Parse DNS header
            transaction_id = struct.unpack("!H", udp_payload[0:2])[0]
            flags = struct.unpack("!H", udp_payload[2:4])[0]
            qd_count = struct.unpack("!H", udp_payload[4:6])[0]

            # Check if this is a query (QR=0) or response (QR=1)
            is_response = bool(flags & 0x8000)
            response_code = flags & 0x000F

            # Need at least one question
            if qd_count == 0:
                return None

            # Parse first question (domain name)
            domain, offset = cls._parse_domain_name(udp_payload, 12)
            if not domain:
                return None

            # Parse QTYPE and QCLASS
            if len(udp_payload) < offset + 4:
                return None

            qtype = struct.unpack("!H", udp_payload[offset:offset+2])[0]
            query_type = cls.QUERY_TYPES.get(qtype, f"TYPE{qtype}")

            return DNSQuery(
                domain=domain,
                query_type=query_type,
                transaction_id=transaction_id,
                is_response=is_response,
                response_code=response_code,
            )

        except Exception:
            return None

    @classmethod
    def _parse_domain_name(cls, data: bytes, offset: int) -> Tuple[Optional[str], int]:
        """
        Parse DNS domain name with compression support

        Returns:
            Tuple of (domain_string, next_offset)
        """
        labels = []
        original_offset = offset
        jumped = False
        max_jumps = 10  # Prevent infinite loops
        jump_count = 0

        try:
            while offset < len(data):
                length = data[offset]

                if length == 0:
                    # End of domain name
                    if not jumped:
                        offset += 1
                    break

                # Check for compression pointer
                if (length & 0xC0) == 0xC0:
                    if offset + 1 >= len(data):
                        return None, original_offset
                    pointer = ((length & 0x3F) << 8) | data[offset + 1]
                    if not jumped:
                        # First jump - remember where to continue
                        original_offset = offset + 2
                    offset = pointer
                    jumped = True
                    jump_count += 1
                    if jump_count > max_jumps:
                        return None, original_offset  # Too many jumps
                    continue

                # Regular label
                offset += 1
                if offset + length > len(data):
                    return None, original_offset
                label = data[offset:offset + length].decode('utf-8', errors='ignore')
                labels.append(label)
                offset += length

            if not labels:
                return None, original_offset

            domain = ".".join(labels)
            return domain, offset if not jumped else original_offset

        except Exception:
            return None, original_offset


class TLSParser:
    """
    Parse TLS ClientHello to extract SNI and other metadata

    TLS Record Format:
    - Content Type: 1 byte (22 = Handshake)
    - Version: 2 bytes
    - Length: 2 bytes
    - Handshake payload

    Handshake Format:
    - Handshake Type: 1 byte (1 = ClientHello)
    - Length: 3 bytes
    - ClientHello payload
    """

    # TLS Versions
    TLS_VERSIONS = {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }

    # Extension types we care about
    EXT_SERVER_NAME = 0x0000
    EXT_SUPPORTED_VERSIONS = 0x002B

    @classmethod
    def parse(cls, tcp_payload: bytes) -> Optional[TLSInfo]:
        """
        Parse TLS ClientHello from TCP payload

        Args:
            tcp_payload: Raw TCP payload bytes

        Returns:
            TLSInfo if valid ClientHello, None otherwise
        """
        try:
            if len(tcp_payload) < 5:
                return None

            # Check TLS record header
            content_type = tcp_payload[0]
            if content_type != 22:  # Handshake
                return None

            record_version = struct.unpack("!H", tcp_payload[1:3])[0]
            record_length = struct.unpack("!H", tcp_payload[3:5])[0]

            if len(tcp_payload) < 5 + record_length:
                return None

            # Parse handshake header
            handshake_data = tcp_payload[5:5 + record_length]
            if len(handshake_data) < 4:
                return None

            handshake_type = handshake_data[0]
            if handshake_type != 1:  # ClientHello
                return None

            # Handshake length (3 bytes big-endian)
            handshake_length = (handshake_data[1] << 16) | (handshake_data[2] << 8) | handshake_data[3]

            if len(handshake_data) < 4 + handshake_length:
                return None

            # Parse ClientHello
            return cls._parse_client_hello(handshake_data[4:4 + handshake_length], record_version)

        except Exception:
            return None

    @classmethod
    def _parse_client_hello(cls, data: bytes, record_version: int) -> Optional[TLSInfo]:
        """Parse ClientHello handshake message"""
        try:
            if len(data) < 38:  # Minimum ClientHello size
                return None

            offset = 0

            # Client version (2 bytes)
            client_version = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID (1 byte length + variable)
            session_id_length = data[offset]
            offset += 1 + session_id_length

            if offset + 2 > len(data):
                return None

            # Cipher suites (2 byte length + variable)
            cipher_suites_length = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            cipher_suites_count = cipher_suites_length // 2
            offset += cipher_suites_length

            if offset + 1 > len(data):
                return None

            # Compression methods (1 byte length + variable)
            compression_length = data[offset]
            offset += 1 + compression_length

            # Extensions (optional)
            sni = ""
            extensions_count = 0
            actual_version = cls.TLS_VERSIONS.get(client_version, f"Unknown (0x{client_version:04x})")

            if offset + 2 <= len(data):
                extensions_length = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2

                extensions_end = offset + extensions_length
                while offset + 4 <= extensions_end and offset + 4 <= len(data):
                    ext_type = struct.unpack("!H", data[offset:offset+2])[0]
                    ext_length = struct.unpack("!H", data[offset+2:offset+4])[0]
                    offset += 4

                    if offset + ext_length > len(data):
                        break

                    ext_data = data[offset:offset + ext_length]
                    extensions_count += 1

                    # Parse SNI extension
                    if ext_type == cls.EXT_SERVER_NAME and len(ext_data) >= 5:
                        sni = cls._parse_sni_extension(ext_data)

                    # Parse supported_versions extension (TLS 1.3)
                    elif ext_type == cls.EXT_SUPPORTED_VERSIONS and len(ext_data) >= 3:
                        # Check if TLS 1.3 is supported
                        versions_length = ext_data[0]
                        for i in range(1, min(1 + versions_length, len(ext_data)), 2):
                            if i + 1 < len(ext_data):
                                ver = struct.unpack("!H", ext_data[i:i+2])[0]
                                if ver == 0x0304:
                                    actual_version = "TLS 1.3"
                                    break

                    offset += ext_length

            return TLSInfo(
                sni=sni,
                version=actual_version,
                cipher_suites_count=cipher_suites_count,
                extensions_count=extensions_count,
            )

        except Exception:
            return None

    @classmethod
    def _parse_sni_extension(cls, ext_data: bytes) -> str:
        """Parse Server Name Indication extension"""
        try:
            if len(ext_data) < 5:
                return ""

            # SNI list length (2 bytes)
            offset = 2

            # Name type (1 byte, should be 0 for hostname)
            name_type = ext_data[offset]
            if name_type != 0:
                return ""
            offset += 1

            # Name length (2 bytes)
            name_length = struct.unpack("!H", ext_data[offset:offset+2])[0]
            offset += 2

            if offset + name_length > len(ext_data):
                return ""

            # Hostname
            hostname = ext_data[offset:offset + name_length].decode('utf-8', errors='ignore')
            return hostname

        except Exception:
            return ""


class TCPParser:
    """
    Parse TCP header to extract flags and connection state

    TCP Header Format:
    - Source Port: 2 bytes
    - Dest Port: 2 bytes
    - Sequence Number: 4 bytes
    - Ack Number: 4 bytes
    - Data Offset + Flags: 2 bytes
    - Window: 2 bytes
    - Checksum: 2 bytes
    - Urgent Pointer: 2 bytes
    """

    # TCP Flag masks
    FLAG_FIN = 0x01
    FLAG_SYN = 0x02
    FLAG_RST = 0x04
    FLAG_PSH = 0x08
    FLAG_ACK = 0x10
    FLAG_URG = 0x20

    @classmethod
    def parse_flags(cls, transport_data: bytes) -> Optional[TCPFlags]:
        """
        Parse TCP flags from transport layer data

        Args:
            transport_data: TCP segment data (including header)

        Returns:
            TCPFlags if valid TCP header, None otherwise
        """
        try:
            if len(transport_data) < 14:  # Minimum TCP header
                return None

            # Flags are at byte 13 (0-indexed)
            flags_byte = transport_data[13]

            return TCPFlags(
                fin=bool(flags_byte & cls.FLAG_FIN),
                syn=bool(flags_byte & cls.FLAG_SYN),
                rst=bool(flags_byte & cls.FLAG_RST),
                psh=bool(flags_byte & cls.FLAG_PSH),
                ack=bool(flags_byte & cls.FLAG_ACK),
                urg=bool(flags_byte & cls.FLAG_URG),
            )

        except Exception:
            return None

    @classmethod
    def get_payload(cls, transport_data: bytes) -> bytes:
        """
        Extract TCP payload (application data) from segment

        Returns:
            Payload bytes (empty if header-only)
        """
        try:
            if len(transport_data) < 13:
                return b""

            # Data offset is upper 4 bits of byte 12, in 32-bit words
            data_offset = (transport_data[12] >> 4) * 4

            if len(transport_data) <= data_offset:
                return b""

            return transport_data[data_offset:]

        except Exception:
            return b""


class ProtocolEnricher:
    """
    Main interface for protocol enrichment

    Analyzes raw packet data and extracts application-layer intelligence.
    Designed to be called from network_monitor.py during packet processing.
    """

    @classmethod
    def enrich(
        cls,
        protocol: int,  # IP protocol number (6=TCP, 17=UDP)
        src_port: int,
        dst_port: int,
        transport_data: bytes,
    ) -> ProtocolEnrichment:
        """
        Enrich connection with protocol-specific data

        Args:
            protocol: IP protocol number (6=TCP, 17=UDP)
            src_port: Source port
            dst_port: Destination port
            transport_data: Raw transport layer data

        Returns:
            ProtocolEnrichment with extracted data
        """
        enrichment = ProtocolEnrichment()

        try:
            if protocol == 17:  # UDP
                # Check for DNS (port 53)
                if dst_port == 53 or src_port == 53:
                    # UDP header is 8 bytes
                    if len(transport_data) > 8:
                        udp_payload = transport_data[8:]
                        enrichment.dns_query = DNSParser.parse(udp_payload)

            elif protocol == 6:  # TCP
                # Parse TCP flags
                enrichment.tcp_flags = TCPParser.parse_flags(transport_data)

                # Check for TLS (port 443 or other common TLS ports)
                tls_ports = {443, 8443, 993, 995, 465, 636}
                if dst_port in tls_ports or src_port in tls_ports:
                    # Only parse if we have payload (not just SYN)
                    tcp_payload = TCPParser.get_payload(transport_data)
                    if tcp_payload:
                        enrichment.tls_info = TLSParser.parse(tcp_payload)

                # Also check for DNS over TCP (rare but valid)
                if dst_port == 53 or src_port == 53:
                    tcp_payload = TCPParser.get_payload(transport_data)
                    if len(tcp_payload) > 2:
                        # TCP DNS has 2-byte length prefix
                        dns_payload = tcp_payload[2:]
                        enrichment.dns_query = DNSParser.parse(dns_payload)

        except Exception:
            pass

        return enrichment

    @classmethod
    def enrich_from_dict(cls, packet_info: Dict) -> ProtocolEnrichment:
        """
        Enrich from a packet info dictionary (for integration with network_monitor)

        Args:
            packet_info: Dictionary with protocol, src_port, dest_port, transport_data

        Returns:
            ProtocolEnrichment with extracted data
        """
        protocol = packet_info.get("protocol", 0)

        # Handle protocol name strings
        if isinstance(protocol, str):
            protocol_map = {"TCP": 6, "UDP": 17}
            protocol = protocol_map.get(protocol.upper(), 0)

        src_port = packet_info.get("src_port", 0)
        dst_port = packet_info.get("dest_port") or packet_info.get("dst_port", 0)
        transport_data = packet_info.get("transport_data", b"")

        return cls.enrich(protocol, src_port, dst_port, transport_data)
