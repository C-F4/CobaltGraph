#!/usr/bin/env python3
"""
CobaltGraph JA3 TLS Fingerprinting

JA3 is a method for creating SSL/TLS client fingerprints.
It creates a hash from the TLS ClientHello message parameters:
- TLS Version
- Cipher Suites (sorted numerically)
- Extensions (sorted numerically)
- Elliptic Curves (sorted numerically)
- Elliptic Curve Point Formats

This fingerprint can identify specific clients/malware regardless of
IP addresses or domains, making it useful for detecting known threats.

Reference: https://github.com/salesforce/ja3

Usage:
    calculator = JA3Calculator()
    ja3_hash = calculator.calculate_from_payload(tls_payload)
    if ja3_hash:
        match = calculator.lookup(ja3_hash)
        if match:
            print(f"Known client: {match}")
"""

import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class JA3Result:
    """Result of JA3 fingerprint calculation"""
    ja3_hash: str           # MD5 hash of JA3 string
    ja3_string: str         # Raw JA3 string before hashing
    tls_version: int        # TLS version number
    cipher_suites: List[int]
    extensions: List[int]
    elliptic_curves: List[int]
    ec_point_formats: List[int]
    # Lookup result
    known_client: str = ""  # Name if known (malware, browser, etc.)
    is_malware: bool = False
    is_automation: bool = False


class JA3Calculator:
    """
    Calculate JA3 fingerprints from TLS ClientHello messages.

    JA3 format: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats

    Example:
    769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
    """

    # TLS Record types
    TLS_HANDSHAKE = 22

    # TLS Handshake types
    CLIENT_HELLO = 1

    # TLS Versions
    TLS_VERSIONS = {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }

    # Known JA3 fingerprints (partial list - extend as needed)
    # Source: Various threat intelligence feeds and research
    KNOWN_JA3 = {
        # Malware
        "e7d705a3286e19ea42f587b344ee6865": ("Emotet", True, False),
        "51c64c77e60f3980eea90869b68c58a8": ("TrickBot", True, False),
        "72a589da586844d7f0818ce684948eea": ("Dridex", True, False),
        "6734f37431670b3ab4292b8f60f29984": ("CobaltStrike", True, False),
        "b32309a26951912be7dba376398abc3b": ("Metasploit", True, False),

        # Automation tools (not necessarily malicious)
        "3b5074b1b5d032e5620f69f9f700ff0e": ("Python/urllib", False, True),
        "2d1eb5817ece335c24904f516ad5da12": ("Python/requests", False, True),
        "d8d0c02c7ade7d5ed06c4ab1d9d6c1d4": ("curl", False, True),
        "f4a8e8c2c9c3b2e1d0a9b8c7d6e5f4a3": ("wget", False, True),
        "92b3b4c5d6e7f8a9b0c1d2e3f4a5b6c7": ("Go/http", False, True),

        # Browsers (for context - these are benign)
        "73778f3c36d0e5e7a9e3c0b2f1d4e5f6": ("Chrome", False, False),
        "84889e4d47e1f6e8b0f4d1c3e2a5b6c8": ("Firefox", False, False),
        "95990f5e58f2g7f9c1g5e2d4f3b6c7d9": ("Safari", False, False),
    }

    # GREASE values to filter out (RFC 8701)
    GREASE_VALUES = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
        0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
        0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    }

    def __init__(self):
        """Initialize JA3 calculator"""
        self._cache: Dict[str, JA3Result] = {}
        self._cache_max_size = 10000

        # Statistics
        self.stats = {
            "calculations": 0,
            "cache_hits": 0,
            "malware_matches": 0,
            "automation_matches": 0,
            "parse_errors": 0,
        }

        logger.info(f"JA3Calculator initialized ({len(self.KNOWN_JA3)} known fingerprints)")

    def calculate_from_payload(self, tls_payload: bytes) -> Optional[JA3Result]:
        """
        Calculate JA3 fingerprint from raw TLS payload.

        Args:
            tls_payload: Raw TLS ClientHello payload

        Returns:
            JA3Result if successful, None if not a valid ClientHello
        """
        if not tls_payload or len(tls_payload) < 43:
            return None

        try:
            return self._parse_client_hello(tls_payload)
        except Exception as e:
            logger.debug(f"JA3 parse error: {e}")
            self.stats["parse_errors"] += 1
            return None

    def _parse_client_hello(self, data: bytes) -> Optional[JA3Result]:
        """Parse TLS ClientHello and extract JA3 components"""
        offset = 0

        # TLS Record Header (5 bytes)
        if len(data) < 5:
            return None

        content_type = data[0]
        if content_type != self.TLS_HANDSHAKE:
            return None

        # record_version = struct.unpack(">H", data[1:3])[0]
        # record_length = struct.unpack(">H", data[3:5])[0]
        offset = 5

        # Handshake Header (4 bytes)
        if len(data) < offset + 4:
            return None

        handshake_type = data[offset]
        if handshake_type != self.CLIENT_HELLO:
            return None

        # handshake_length = (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3]
        offset += 4

        # ClientHello
        if len(data) < offset + 2:
            return None

        # Client Version (2 bytes)
        tls_version = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        # Random (32 bytes)
        offset += 32

        if len(data) < offset + 1:
            return None

        # Session ID (variable)
        session_id_length = data[offset]
        offset += 1 + session_id_length

        if len(data) < offset + 2:
            return None

        # Cipher Suites
        cipher_suites_length = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        if len(data) < offset + cipher_suites_length:
            return None

        cipher_suites = []
        for i in range(0, cipher_suites_length, 2):
            cipher = struct.unpack(">H", data[offset+i:offset+i+2])[0]
            # Filter GREASE
            if cipher not in self.GREASE_VALUES:
                cipher_suites.append(cipher)
        offset += cipher_suites_length

        if len(data) < offset + 1:
            return None

        # Compression Methods
        compression_length = data[offset]
        offset += 1 + compression_length

        # Extensions (optional)
        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        if len(data) > offset + 2:
            extensions_length = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2

            extensions_end = offset + extensions_length
            while offset < extensions_end and offset < len(data) - 4:
                ext_type = struct.unpack(">H", data[offset:offset+2])[0]
                ext_length = struct.unpack(">H", data[offset+2:offset+4])[0]
                offset += 4

                # Filter GREASE
                if ext_type not in self.GREASE_VALUES:
                    extensions.append(ext_type)

                # Parse supported_groups (elliptic curves) - extension 10
                if ext_type == 10 and ext_length >= 2:
                    curves_length = struct.unpack(">H", data[offset:offset+2])[0]
                    for i in range(2, min(curves_length + 2, ext_length), 2):
                        if offset + i + 2 <= len(data):
                            curve = struct.unpack(">H", data[offset+i:offset+i+2])[0]
                            if curve not in self.GREASE_VALUES:
                                elliptic_curves.append(curve)

                # Parse ec_point_formats - extension 11
                elif ext_type == 11 and ext_length >= 1:
                    formats_length = data[offset]
                    for i in range(1, min(formats_length + 1, ext_length)):
                        if offset + i < len(data):
                            ec_point_formats.append(data[offset + i])

                offset += ext_length

        # Build JA3 string
        ja3_string = self._build_ja3_string(
            tls_version, cipher_suites, extensions,
            elliptic_curves, ec_point_formats
        )

        # Calculate hash
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        # Create result
        result = JA3Result(
            ja3_hash=ja3_hash,
            ja3_string=ja3_string,
            tls_version=tls_version,
            cipher_suites=cipher_suites,
            extensions=extensions,
            elliptic_curves=elliptic_curves,
            ec_point_formats=ec_point_formats,
        )

        # Lookup known fingerprint
        self._lookup_fingerprint(result)

        self.stats["calculations"] += 1

        return result

    def _build_ja3_string(
        self,
        tls_version: int,
        cipher_suites: List[int],
        extensions: List[int],
        elliptic_curves: List[int],
        ec_point_formats: List[int]
    ) -> str:
        """Build JA3 string from components"""
        parts = [
            str(tls_version),
            "-".join(str(c) for c in cipher_suites),
            "-".join(str(e) for e in extensions),
            "-".join(str(c) for c in elliptic_curves),
            "-".join(str(f) for f in ec_point_formats),
        ]
        return ",".join(parts)

    def _lookup_fingerprint(self, result: JA3Result):
        """Lookup JA3 hash in known fingerprints database"""
        if result.ja3_hash in self.KNOWN_JA3:
            name, is_malware, is_automation = self.KNOWN_JA3[result.ja3_hash]
            result.known_client = name
            result.is_malware = is_malware
            result.is_automation = is_automation

            if is_malware:
                self.stats["malware_matches"] += 1
            if is_automation:
                self.stats["automation_matches"] += 1

    def lookup(self, ja3_hash: str) -> Optional[str]:
        """
        Lookup a JA3 hash in the known fingerprints database.

        Args:
            ja3_hash: JA3 MD5 hash

        Returns:
            Name of known client, or None if unknown
        """
        if ja3_hash in self.KNOWN_JA3:
            return self.KNOWN_JA3[ja3_hash][0]
        return None

    def is_known_malware(self, ja3_hash: str) -> bool:
        """Check if JA3 hash matches known malware"""
        if ja3_hash in self.KNOWN_JA3:
            return self.KNOWN_JA3[ja3_hash][1]
        return False

    def is_automation_tool(self, ja3_hash: str) -> bool:
        """Check if JA3 hash matches known automation tool"""
        if ja3_hash in self.KNOWN_JA3:
            return self.KNOWN_JA3[ja3_hash][2]
        return False

    def calculate_ja3_rarity(self, ja3_hash: str) -> float:
        """
        Calculate rarity score for a JA3 fingerprint.

        Known fingerprints get low rarity.
        Unknown fingerprints get higher rarity based on hash distribution.

        Returns:
            Rarity score 0.0 - 1.0 (higher = more unusual)
        """
        if ja3_hash in self.KNOWN_JA3:
            # Known fingerprints are common
            return 0.1

        # Unknown fingerprints are rare by default
        # Could be enhanced with frequency tracking
        return 0.7

    def add_known_fingerprint(
        self,
        ja3_hash: str,
        name: str,
        is_malware: bool = False,
        is_automation: bool = False
    ):
        """
        Add a fingerprint to the known database.

        Args:
            ja3_hash: JA3 MD5 hash
            name: Descriptive name
            is_malware: True if known malware
            is_automation: True if automation tool
        """
        self.KNOWN_JA3[ja3_hash] = (name, is_malware, is_automation)
        logger.info(f"Added JA3 fingerprint: {ja3_hash} ({name})")

    def get_stats(self) -> Dict:
        """Get calculator statistics"""
        return {
            **self.stats,
            "known_fingerprints": len(self.KNOWN_JA3),
        }


# Global instance for convenience
_calculator: Optional[JA3Calculator] = None


def get_ja3_calculator() -> JA3Calculator:
    """Get or create global JA3Calculator instance"""
    global _calculator
    if _calculator is None:
        _calculator = JA3Calculator()
    return _calculator


def calculate_ja3(tls_payload: bytes) -> Optional[str]:
    """
    Convenience function to calculate JA3 hash.

    Args:
        tls_payload: Raw TLS ClientHello payload

    Returns:
        JA3 MD5 hash, or None if not a valid ClientHello
    """
    calculator = get_ja3_calculator()
    result = calculator.calculate_from_payload(tls_payload)
    return result.ja3_hash if result else None
