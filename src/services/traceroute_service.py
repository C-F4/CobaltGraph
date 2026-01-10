#!/usr/bin/env python3
"""
Traceroute Service
Real network hop counting via traceroute with caching and async support

Features:
- Actual traceroute execution for verified hop counts
- LRU caching with configurable TTL (default 1 hour)
- Async/background execution to avoid blocking
- Fallback to TTL estimation when traceroute fails
- Rate limiting to prevent network abuse
- Cross-platform support (Linux traceroute, Windows tracert)
"""

import logging
import subprocess
import platform
import re
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from threading import RLock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TracerouteResult:
    """Result of a traceroute operation"""
    dst_ip: str
    hop_count: int = 0                    # Verified hop count
    hops: List[Dict] = field(default_factory=list)  # Individual hop details
    verified: bool = False                # True if from actual traceroute
    ttl_estimated: int = 0                # Fallback TTL-based estimate
    error: Optional[str] = None           # Error message if failed
    timestamp: float = 0.0                # When traceroute was performed
    latency_ms: Optional[float] = None    # Total round-trip time
    cached: bool = False                  # Whether from cache

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "dst_ip": self.dst_ip,
            "hop_count": self.hop_count,
            "hops": self.hops,
            "verified": self.verified,
            "ttl_estimated": self.ttl_estimated,
            "error": self.error,
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
            "cached": self.cached,
        }


class TracerouteCache:
    """Thread-safe LRU cache for traceroute results"""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict = OrderedDict()
        self.lock = RLock()
        self._hits = 0
        self._misses = 0

    def get(self, ip: str) -> Optional[TracerouteResult]:
        """Get cached result if valid"""
        with self.lock:
            if ip in self.cache:
                result, timestamp = self.cache[ip]
                if time.time() - timestamp < self.ttl_seconds:
                    # Move to end (most recently used)
                    self.cache.move_to_end(ip)
                    self._hits += 1
                    result.cached = True
                    return result
                else:
                    # Expired, remove
                    del self.cache[ip]
            self._misses += 1
            return None

    def put(self, ip: str, result: TracerouteResult) -> None:
        """Cache a traceroute result"""
        with self.lock:
            # Remove oldest if at capacity
            while len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)

            self.cache[ip] = (result, time.time())

    def stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total = self._hits + self._misses
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": self._hits / max(total, 1),
            }


class TracerouteService:
    """
    Service for performing real traceroute operations

    Features:
    - Cross-platform traceroute execution
    - Background/async operation via thread pool
    - Caching to reduce network load
    - Rate limiting for responsible usage
    - Fallback to TTL estimation
    """

    # Common initial TTL values for estimation fallback
    COMMON_INITIAL_TTLS = [32, 60, 64, 128, 255]

    # Rate limiting: max traceroutes per minute
    RATE_LIMIT_PER_MINUTE = 30

    def __init__(
        self,
        cache_size: int = 1000,
        cache_ttl: int = 3600,
        timeout_seconds: int = 10,
        max_hops: int = 30,
        workers: int = 4,
    ):
        """
        Initialize traceroute service

        Args:
            cache_size: Maximum cached results
            cache_ttl: Cache TTL in seconds
            timeout_seconds: Traceroute timeout per hop
            max_hops: Maximum hops to trace
            workers: Thread pool workers for async operations
        """
        self.cache = TracerouteCache(max_size=cache_size, ttl_seconds=cache_ttl)
        self.timeout_seconds = timeout_seconds
        self.max_hops = max_hops
        self.is_windows = platform.system().lower() == "windows"

        # Thread pool for async traceroute
        self._executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="traceroute"
        )

        # Rate limiting
        self._rate_lock = RLock()
        self._rate_timestamps: List[float] = []

        # Statistics
        self._total_traces = 0
        self._successful_traces = 0
        self._failed_traces = 0
        self._rate_limited = 0

        logger.info(
            f"TracerouteService initialized "
            f"(cache={cache_size}, timeout={timeout_seconds}s, max_hops={max_hops})"
        )

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limit"""
        with self._rate_lock:
            now = time.time()
            # Remove timestamps older than 1 minute
            self._rate_timestamps = [
                ts for ts in self._rate_timestamps
                if now - ts < 60
            ]

            if len(self._rate_timestamps) >= self.RATE_LIMIT_PER_MINUTE:
                self._rate_limited += 1
                return False

            self._rate_timestamps.append(now)
            return True

    def trace(self, dst_ip: str, use_cache: bool = True) -> TracerouteResult:
        """
        Perform traceroute to destination IP

        Args:
            dst_ip: Destination IP address
            use_cache: Whether to check/use cache

        Returns:
            TracerouteResult with hop count and details
        """
        # Check cache first
        if use_cache:
            cached = self.cache.get(dst_ip)
            if cached:
                return cached

        # Check rate limit
        if not self._check_rate_limit():
            logger.debug(f"Rate limited traceroute to {dst_ip}")
            result = TracerouteResult(
                dst_ip=dst_ip,
                error="Rate limited",
                timestamp=time.time(),
            )
            return result

        # Perform actual traceroute
        self._total_traces += 1
        result = self._execute_traceroute(dst_ip)

        if result.verified:
            self._successful_traces += 1
        else:
            self._failed_traces += 1

        # Cache result
        if use_cache and (result.verified or result.ttl_estimated > 0):
            self.cache.put(dst_ip, result)

        return result

    def trace_async(self, dst_ip: str, use_cache: bool = True):
        """
        Perform traceroute asynchronously

        Args:
            dst_ip: Destination IP address
            use_cache: Whether to check/use cache

        Returns:
            Future that resolves to TracerouteResult
        """
        return self._executor.submit(self.trace, dst_ip, use_cache)

    def _execute_traceroute(self, dst_ip: str) -> TracerouteResult:
        """
        Execute the actual traceroute command

        Args:
            dst_ip: Destination IP address

        Returns:
            TracerouteResult with parsed output
        """
        result = TracerouteResult(
            dst_ip=dst_ip,
            timestamp=time.time(),
        )

        try:
            # Build command based on platform
            if self.is_windows:
                cmd = [
                    "tracert",
                    "-d",  # Don't resolve hostnames
                    "-w", str(self.timeout_seconds * 1000),  # Timeout in ms
                    "-h", str(self.max_hops),  # Max hops
                    dst_ip
                ]
            else:
                cmd = [
                    "traceroute",
                    "-n",  # Don't resolve hostnames
                    "-w", str(self.timeout_seconds),  # Timeout per probe
                    "-m", str(self.max_hops),  # Max hops
                    "-q", "1",  # Only 1 probe per hop (faster)
                    dst_ip
                ]

            # Execute traceroute with timeout
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds * self.max_hops + 10  # Overall timeout
            )

            # Parse output
            output = proc.stdout
            if self.is_windows:
                hops = self._parse_windows_output(output, dst_ip)
            else:
                hops = self._parse_linux_output(output, dst_ip)

            if hops:
                result.hops = hops
                result.hop_count = len(hops)
                result.verified = True

                # Calculate total latency from last hop
                if hops and hops[-1].get("latency_ms"):
                    result.latency_ms = hops[-1]["latency_ms"]

                logger.debug(f"Traceroute to {dst_ip}: {result.hop_count} hops (verified)")
            else:
                result.error = "No hops parsed from output"
                logger.debug(f"Traceroute to {dst_ip} failed: no hops parsed")

        except subprocess.TimeoutExpired:
            result.error = "Traceroute timeout"
            logger.debug(f"Traceroute to {dst_ip} timed out")
        except FileNotFoundError:
            result.error = "Traceroute command not found"
            logger.warning("traceroute/tracert command not available")
        except subprocess.SubprocessError as e:
            result.error = f"Subprocess error: {e}"
            logger.debug(f"Traceroute to {dst_ip} failed: {e}")
        except Exception as e:
            result.error = f"Unexpected error: {e}"
            logger.debug(f"Traceroute to {dst_ip} failed: {e}")

        return result

    def _parse_linux_output(self, output: str, dst_ip: str) -> List[Dict]:
        """
        Parse Linux traceroute output

        Example output:
        traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
         1  192.168.1.1  0.458 ms
         2  10.0.0.1  5.234 ms
         3  * * *
         4  8.8.8.8  12.456 ms
        """
        hops = []

        # Pattern to match hop lines
        # Matches: "N  IP  latency ms" or "N  * * *"
        hop_pattern = re.compile(
            r'^\s*(\d+)\s+(?:(\d+\.\d+\.\d+\.\d+)\s+(\d+\.?\d*)\s*ms|(\*)\s*)'
        )

        for line in output.split('\n'):
            match = hop_pattern.match(line)
            if match:
                hop_num = int(match.group(1))
                ip = match.group(2)
                latency = match.group(3)
                is_timeout = match.group(4) == '*'

                hop_info = {
                    "hop": hop_num,
                    "ip": ip if ip else None,
                    "latency_ms": float(latency) if latency else None,
                    "timeout": is_timeout,
                }
                hops.append(hop_info)

                # Stop if we reached the destination
                if ip == dst_ip:
                    break

        return hops

    def _parse_windows_output(self, output: str, dst_ip: str) -> List[Dict]:
        """
        Parse Windows tracert output

        Example output:
        Tracing route to 8.8.8.8 over a maximum of 30 hops
          1     1 ms     1 ms     1 ms  192.168.1.1
          2     5 ms     5 ms     5 ms  10.0.0.1
          3     *        *        *     Request timed out.
          4    12 ms    12 ms    12 ms  8.8.8.8
        """
        hops = []

        # Pattern to match hop lines
        hop_pattern = re.compile(
            r'^\s*(\d+)\s+(?:(?:(<?\d+)\s*ms\s+(<?\d+)\s*ms\s+(<?\d+)\s*ms)|(?:\*\s+\*\s+\*))\s+(\d+\.\d+\.\d+\.\d+|Request timed out\.)?'
        )

        for line in output.split('\n'):
            match = hop_pattern.match(line)
            if match:
                hop_num = int(match.group(1))
                latency1 = match.group(2)
                latency2 = match.group(3)
                latency3 = match.group(4)
                ip_or_timeout = match.group(5)

                is_timeout = ip_or_timeout == "Request timed out." if ip_or_timeout else True
                ip = ip_or_timeout if ip_or_timeout and ip_or_timeout != "Request timed out." else None

                # Average latency from the three probes
                latency = None
                if latency1 and latency2 and latency3:
                    try:
                        vals = [
                            float(l.replace('<', ''))
                            for l in [latency1, latency2, latency3]
                        ]
                        latency = sum(vals) / len(vals)
                    except ValueError:
                        pass

                hop_info = {
                    "hop": hop_num,
                    "ip": ip,
                    "latency_ms": latency,
                    "timeout": is_timeout,
                }
                hops.append(hop_info)

                # Stop if we reached the destination
                if ip == dst_ip:
                    break

        return hops

    def estimate_hops_from_ttl(self, observed_ttl: int) -> Tuple[int, int]:
        """
        Fallback: Estimate hops from observed TTL

        Args:
            observed_ttl: TTL value from received packet

        Returns:
            Tuple of (estimated_initial_ttl, estimated_hops)
        """
        if observed_ttl <= 0:
            return (0, 0)

        best_initial = 64
        min_hops = 999

        for initial in self.COMMON_INITIAL_TTLS:
            if initial >= observed_ttl:
                hops = initial - observed_ttl
                if hops < min_hops:
                    min_hops = hops
                    best_initial = initial

        # Sanity check - more than 30 hops is unusual
        if min_hops > 30:
            for check in [32, 60, 64, 128, 255]:
                if check >= observed_ttl:
                    hops = check - observed_ttl
                    if hops <= 30:
                        return (check, hops)

        return (best_initial, max(0, min_hops))

    def trace_with_fallback(
        self,
        dst_ip: str,
        observed_ttl: Optional[int] = None,
        use_cache: bool = True
    ) -> TracerouteResult:
        """
        Perform traceroute with TTL-based fallback

        If traceroute fails or times out, falls back to TTL estimation.

        Args:
            dst_ip: Destination IP address
            observed_ttl: Observed TTL for fallback estimation
            use_cache: Whether to use cache

        Returns:
            TracerouteResult with verified or estimated hop count
        """
        result = self.trace(dst_ip, use_cache=use_cache)

        # If traceroute succeeded, return result
        if result.verified:
            return result

        # Fall back to TTL estimation
        if observed_ttl and observed_ttl > 0:
            initial_ttl, estimated_hops = self.estimate_hops_from_ttl(observed_ttl)
            result.ttl_estimated = estimated_hops
            result.hop_count = estimated_hops  # Use estimate if no verified count
            logger.debug(
                f"Using TTL estimate for {dst_ip}: {estimated_hops} hops "
                f"(initial TTL: {initial_ttl}, observed: {observed_ttl})"
            )

        return result

    def get_stats(self) -> Dict:
        """Get service statistics"""
        return {
            "total_traces": self._total_traces,
            "successful_traces": self._successful_traces,
            "failed_traces": self._failed_traces,
            "rate_limited": self._rate_limited,
            "success_rate": self._successful_traces / max(self._total_traces, 1),
            "cache": self.cache.stats(),
        }

    def shutdown(self) -> None:
        """Shutdown the service"""
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
        logger.info(f"TracerouteService shutdown (traces: {self._total_traces})")
