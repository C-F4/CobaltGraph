"""
Connection Correlator Stage

Correlates bidirectional packet events into unified connection records.
Enables accurate TTL-based hop estimation by capturing response packet TTLs.

Architecture:
    NetworkMonitor emits bidirectional packet events:
    - Outbound: local_ip -> remote_ip (our initial request)
    - Inbound:  remote_ip -> local_ip (server's response)

    This stage maintains a connection state table and:
    1. Creates connection records on outbound packets
    2. Updates records with response TTL on inbound packets
    3. Emits ConnectionEvents with hop estimation data
    4. Handles connection timeouts and cleanup
"""

import logging
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any

from .base import PipelineStage, StageContext
from ..config import PipelineConfig
from ..events import ConnectionEvent, HopData, StageResult

logger = logging.getLogger(__name__)


# Common initial TTL values used by operating systems
COMMON_INITIAL_TTLS = [64, 128, 255, 32]


@dataclass
class ConnectionState:
    """State for a single connection being correlated"""
    # Connection identifiers (4-tuple)
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

    # Packet data
    protocol: str = "TCP"
    src_mac: str = ""
    device_vendor: str = ""

    # TTL data
    outbound_ttl: int = 0          # TTL from our outgoing packet
    response_ttl: Optional[int] = None  # TTL from server's response

    # Hop estimation (calculated when response is received)
    estimated_initial_ttl: int = 0
    estimated_hops: int = 0

    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    response_received: bool = False

    # Event tracking
    emitted: bool = False          # Has this connection been emitted as an event?
    packets_out: int = 0
    packets_in: int = 0

    def get_key(self) -> Tuple[str, int, str, int]:
        """Get the 4-tuple key for this connection"""
        return (self.local_ip, self.local_port, self.remote_ip, self.remote_port)

    def update_response_ttl(self, ttl: int) -> None:
        """Update with response packet TTL and calculate hops"""
        if ttl > 0:
            self.response_ttl = ttl
            self.response_received = True
            self.estimated_initial_ttl, self.estimated_hops = self._estimate_hops(ttl)
            logger.debug(
                f"Hop estimation for {self.remote_ip}: "
                f"response_ttl={ttl}, initial={self.estimated_initial_ttl}, hops={self.estimated_hops}"
            )

    def _estimate_hops(self, observed_ttl: int) -> Tuple[int, int]:
        """
        Estimate network hops from observed TTL in response packet.

        Common initial TTL values:
        - Linux/Unix: 64
        - Windows: 128
        - Cisco/Network: 255
        - Some older systems: 32

        Returns:
            Tuple of (estimated_initial_ttl, estimated_hops)
        """
        if observed_ttl <= 0:
            return (0, 0)

        # Find the most likely initial TTL
        best_initial = 64
        min_hops = 999

        for initial in COMMON_INITIAL_TTLS:
            if initial >= observed_ttl:
                hops = initial - observed_ttl
                if hops < min_hops:
                    min_hops = hops
                    best_initial = initial

        # Sanity check - more than 30 hops is unusual
        if min_hops > 30:
            # Try finding a closer match
            for check in [64, 128, 255]:
                if check > observed_ttl:
                    hops = check - observed_ttl
                    if hops <= 30:
                        return (check, hops)

        return (best_initial, max(0, min_hops))

    def to_hop_data(self) -> HopData:
        """Convert to HopData for ConnectionEvent"""
        return HopData(
            hop_count=self.estimated_hops if self.response_received else 0,
            ttl_observed=self.response_ttl,
            ttl_initial=self.estimated_initial_ttl if self.response_received else None,
            os_fingerprint=self._guess_os() if self.response_received else None,
        )

    def _guess_os(self) -> Optional[str]:
        """Guess remote OS from initial TTL"""
        if not self.response_received or self.estimated_initial_ttl == 0:
            return None

        ttl = self.estimated_initial_ttl
        if ttl == 64:
            return "Linux/Unix"
        elif ttl == 128:
            return "Windows"
        elif ttl == 255:
            return "Network/Cisco"
        elif ttl == 32:
            return "Legacy"
        return None


class ConnectionCorrelator(PipelineStage[Dict]):
    """
    Correlates bidirectional packet events into unified connections.

    This stage sits at the beginning of the pipeline and:
    1. Receives raw packet events from NetworkMonitor
    2. Maintains connection state for correlation
    3. Emits ConnectionEvents with hop estimation data

    Configuration:
        - connection_timeout: How long to keep connections without activity (default: 300s)
        - cleanup_interval: How often to run cleanup (default: 60s)
        - emit_on_outbound: Emit event immediately on outbound (default: True)
        - emit_on_response: Update/re-emit when response received (default: True)
    """

    # Default configuration
    DEFAULT_CONNECTION_TIMEOUT = 300  # 5 minutes
    DEFAULT_CLEANUP_INTERVAL = 60     # 1 minute

    def __init__(self, config: Optional[PipelineConfig] = None):
        super().__init__("ConnectionCorrelator")
        self.config = config

        # Connection state table: (local_ip, local_port, remote_ip, remote_port) -> ConnectionState
        self._connections: Dict[Tuple[str, int, str, int], ConnectionState] = {}
        self._lock = threading.RLock()

        # Configuration
        self._connection_timeout = self.DEFAULT_CONNECTION_TIMEOUT
        self._cleanup_interval = self.DEFAULT_CLEANUP_INTERVAL
        self._emit_on_outbound = True
        self._emit_on_response = True

        # Cleanup thread
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False

        # Stats
        self._outbound_packets = 0
        self._inbound_packets = 0
        self._correlations = 0
        self._connections_emitted = 0
        self._connections_timed_out = 0

    def initialize(self, context: StageContext) -> bool:
        """Initialize correlator and start cleanup thread"""
        self.logger.info(
            f"ConnectionCorrelator initializing "
            f"(timeout={self._connection_timeout}s, cleanup_interval={self._cleanup_interval}s)"
        )

        # Start cleanup thread
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="correlator-cleanup",
            daemon=True
        )
        self._cleanup_thread.start()

        return True

    def shutdown(self) -> None:
        """Stop cleanup thread and clear state"""
        self._running = False
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2.0)

        with self._lock:
            conn_count = len(self._connections)
            self._connections.clear()

        self.logger.info(
            f"ConnectionCorrelator shutdown "
            f"(correlations={self._correlations}, connections_cleared={conn_count})"
        )

    def process(self, event: Dict, context: StageContext) -> StageResult:
        """
        Process a packet event and correlate into connection.

        Args:
            event: Raw packet dict from NetworkMonitor with 'direction' field
            context: Pipeline context

        Returns:
            StageResult with ConnectionEvent if ready to emit
        """
        result = StageResult()

        # Handle legacy connection events (backwards compatibility)
        event_type = event.get("type", "")
        if event_type == "connection":
            # Legacy format - convert to ConnectionEvent directly
            conn_event = ConnectionEvent.from_raw(event)
            # Set TTL from legacy event (outbound TTL, not useful for hops)
            if event.get("ttl", 0) > 0:
                conn_event.hop_data.ttl_observed = event.get("ttl")
            result.success = True
            result.data = conn_event
            return result

        # Handle device events (pass through)
        if event_type == "device":
            result.success = True
            result.data = event  # Pass through unchanged
            return result

        # Handle packet events (bidirectional)
        if event_type != "packet":
            result.success = True
            result.data = event  # Unknown type, pass through
            return result

        direction = event.get("direction", "")

        if direction == "outbound":
            return self._process_outbound(event, context)
        elif direction == "inbound":
            return self._process_inbound(event, context)
        else:
            result.success = True
            result.data = None  # Drop packet with unknown direction
            return result

    def _process_outbound(self, packet: Dict, context: StageContext) -> StageResult:
        """Process outbound packet - create or update connection state"""
        result = StageResult()
        self._outbound_packets += 1

        # Build connection key
        key = (
            packet.get("local_ip", ""),
            packet.get("local_port", 0),
            packet.get("remote_ip", ""),
            packet.get("remote_port", 0),
        )

        with self._lock:
            if key in self._connections:
                # Update existing connection
                conn = self._connections[key]
                conn.last_seen = time.time()
                conn.packets_out += 1
            else:
                # Create new connection state
                conn = ConnectionState(
                    local_ip=key[0],
                    local_port=key[1],
                    remote_ip=key[2],
                    remote_port=key[3],
                    protocol=packet.get("protocol", "TCP"),
                    src_mac=packet.get("src_mac", ""),
                    device_vendor=packet.get("device_vendor", ""),
                    outbound_ttl=packet.get("ttl", 0),
                    packets_out=1,
                )
                self._connections[key] = conn

        # Emit ConnectionEvent for outbound (without hop data yet)
        if self._emit_on_outbound and not conn.emitted:
            conn_event = self._create_connection_event(conn, packet)
            conn.emitted = True
            self._connections_emitted += 1
            result.success = True
            result.data = conn_event
        else:
            result.success = True
            result.data = None  # Already emitted or emit_on_outbound disabled

        return result

    def _process_inbound(self, packet: Dict, context: StageContext) -> StageResult:
        """Process inbound packet - correlate with existing connection and update TTL"""
        result = StageResult()
        self._inbound_packets += 1

        # Build connection key (same as outbound - local/remote perspective)
        key = (
            packet.get("local_ip", ""),
            packet.get("local_port", 0),
            packet.get("remote_ip", ""),
            packet.get("remote_port", 0),
        )

        with self._lock:
            if key not in self._connections:
                # No matching outbound connection - might be server-initiated
                # or we missed the outbound packet
                result.success = True
                result.data = None
                return result

            conn = self._connections[key]
            conn.last_seen = time.time()
            conn.packets_in += 1

            # Update response TTL (the key insight for hop estimation!)
            response_ttl = packet.get("ttl", 0)
            if response_ttl > 0 and not conn.response_received:
                conn.update_response_ttl(response_ttl)
                self._correlations += 1

                # Re-emit with hop data if configured
                if self._emit_on_response:
                    conn_event = self._create_connection_event(conn, packet)
                    conn_event.hop_data = conn.to_hop_data()
                    result.success = True
                    result.data = conn_event
                    return result

        result.success = True
        result.data = None  # No update needed
        return result

    def _create_connection_event(self, conn: ConnectionState, packet: Dict) -> ConnectionEvent:
        """Create ConnectionEvent from connection state"""
        event = ConnectionEvent(
            timestamp=conn.first_seen,
            src_ip=conn.local_ip,
            src_mac=conn.src_mac,
            dst_ip=conn.remote_ip,
            dst_port=conn.remote_port,
            protocol=conn.protocol,
            device_vendor=conn.device_vendor,
            hop_data=conn.to_hop_data(),
        )
        return event

    def _cleanup_loop(self) -> None:
        """Background thread that cleans up timed-out connections"""
        while self._running:
            time.sleep(self._cleanup_interval)

            if not self._running:
                break

            self._cleanup_stale_connections()

    def _cleanup_stale_connections(self) -> None:
        """Remove connections that have timed out"""
        now = time.time()
        cutoff = now - self._connection_timeout
        stale_keys = []

        with self._lock:
            for key, conn in self._connections.items():
                if conn.last_seen < cutoff:
                    stale_keys.append(key)

            for key in stale_keys:
                del self._connections[key]
                self._connections_timed_out += 1

        if stale_keys:
            self.logger.debug(f"Cleaned up {len(stale_keys)} stale connections")

    def get_stats(self) -> Dict[str, Any]:
        """Get correlator statistics"""
        stats = super().get_stats()
        with self._lock:
            active_connections = len(self._connections)
            correlated = sum(1 for c in self._connections.values() if c.response_received)

        stats.update({
            "outbound_packets": self._outbound_packets,
            "inbound_packets": self._inbound_packets,
            "active_connections": active_connections,
            "correlations": self._correlations,
            "correlation_rate": self._correlations / max(self._outbound_packets, 1),
            "connections_emitted": self._connections_emitted,
            "connections_timed_out": self._connections_timed_out,
            "connections_with_hop_data": correlated,
        })
        return stats

    def health_check(self) -> bool:
        """Check if correlator is healthy"""
        # Check if cleanup thread is alive
        if self._cleanup_thread and not self._cleanup_thread.is_alive():
            self.logger.warning("Cleanup thread is dead")
            return False
        return True

    def get_connection_count(self) -> int:
        """Get current number of tracked connections"""
        with self._lock:
            return len(self._connections)
