"""
Enrichment Stage

Parallel enrichment of connection data with geo, ASN, and threat intel.
Extracted from DataPipeline._enrich_geo(), _enrich_threat_intel(), and parallel execution.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Dict, Optional, Any

from .base import PipelineStage, StageContext
from ..config import PipelineConfig
from ..events import ConnectionEvent, GeoData, ASNData, ThreatIntelData, HopData, StageResult

logger = logging.getLogger(__name__)


class EnrichmentStage(PipelineStage[ConnectionEvent]):
    """
    Enriches connection events with geolocation, ASN, and threat intelligence.

    Features:
    - Parallel execution of geo and threat intel lookups
    - Configurable timeouts
    - Graceful degradation on failures
    - Cache hit tracking

    Extracted from:
    - orchestrator.py lines 505-521 (_enrich_geo, _enrich_threat_intel)
    - orchestrator.py lines 600-622 (parallel execution with ThreadPoolExecutor)
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        super().__init__("EnrichmentStage")
        self.config = config or PipelineConfig()

        # Thread pool for parallel enrichment
        self._executor: Optional[ThreadPoolExecutor] = None

        # Stats
        self._geo_lookups = 0
        self._geo_hits = 0
        self._geo_failures = 0
        self._threat_lookups = 0
        self._threat_hits = 0
        self._threat_failures = 0
        self._parallel_speedup_sum = 0.0
        self._enrichment_count = 0

    def initialize(self, context: StageContext) -> bool:
        """Initialize enrichment services and thread pool"""
        if context.config:
            self.config = context.config

        workers = self.config.enrichment.workers
        self._executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="enrichment"
        )

        self.logger.info(
            f"EnrichmentStage initialized "
            f"(workers={workers}, timeout={self.config.enrichment.timeout_seconds}s)"
        )
        return True

    def shutdown(self) -> None:
        """Shutdown thread pool"""
        if self._executor:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None

        self.logger.info(
            f"EnrichmentStage shutting down "
            f"(geo_lookups={self._geo_lookups}, threat_lookups={self._threat_lookups})"
        )

    def process(self, event: ConnectionEvent, context: StageContext) -> StageResult:
        """
        Enrich connection event with geo and threat data.

        Runs geo and threat intel lookups in parallel for better performance.

        Args:
            event: Connection event to enrich
            context: Pipeline context with services

        Returns:
            StageResult with enriched event
        """
        result = StageResult()

        # Skip enrichment for duplicate events
        if event.is_duplicate:
            result.success = True
            result.data = event
            result.items_skipped = 1
            return result

        dst_ip = event.dst_ip
        if not dst_ip:
            result.success = True
            result.data = event
            return result

        # Run enrichment in parallel
        start_time = time.perf_counter()
        geo_data, threat_data = self._parallel_enrich(dst_ip, context)
        parallel_time = time.perf_counter() - start_time

        # Apply geo data
        if geo_data:
            event.geo = GeoData(
                country=geo_data.get("country", ""),
                country_code=geo_data.get("countryCode", geo_data.get("country_code", "")),
                city=geo_data.get("city", ""),
                latitude=geo_data.get("lat"),
                longitude=geo_data.get("lon"),
                isp=geo_data.get("isp", ""),
                timezone=geo_data.get("timezone", ""),
            )
            event.enrichment_sources.append("geo")

        # Apply ASN data (may come from geo or consensus)
        if geo_data:
            event.asn = ASNData(
                asn=geo_data.get("as", 0) if isinstance(geo_data.get("as"), int) else 0,
                asn_name=geo_data.get("asname", ""),
                organization=geo_data.get("org", geo_data.get("isp", "")),
            )

        # Apply threat intel data
        if threat_data:
            event.threat_intel = ThreatIntelData(
                is_malicious=threat_data.get("is_malicious", False),
                is_tor_exit=threat_data.get("is_tor", False),
                is_vpn=threat_data.get("is_vpn", False),
                is_proxy=threat_data.get("is_proxy", False),
                abuse_score=float(threat_data.get("abuse_score", 0)),
                virustotal_score=float(threat_data.get("vt_score", 0)),
            )
            event.enrichment_sources.append("threat_intel")

        # Track parallel speedup
        self._enrichment_count += 1
        result.add_metric("parallel_time_ms", parallel_time * 1000)

        result.success = True
        result.data = event
        result.items_processed = 1
        return result

    def _parallel_enrich(
        self,
        dst_ip: str,
        context: StageContext
    ) -> tuple:
        """
        Run geo and threat intel lookups in parallel.

        Args:
            dst_ip: Destination IP to look up
            context: Pipeline context with services

        Returns:
            Tuple of (geo_data, threat_data)
        """
        geo_data = {}
        threat_data = {}
        timeout = self.config.enrichment.timeout_seconds

        if not self._executor:
            # Fallback to sequential if no executor
            geo_data = self._enrich_geo(dst_ip, context)
            threat_data = self._enrich_threat_intel(dst_ip, context)
            return geo_data, threat_data

        futures = {}

        # Submit geo lookup
        if context.geo_lookup and self.config.enrichment.geo_enabled:
            futures["geo"] = self._executor.submit(
                self._enrich_geo, dst_ip, context
            )

        # Submit threat intel lookup
        if context.threat_intel and self.config.enrichment.threat_intel_enabled:
            futures["threat"] = self._executor.submit(
                self._enrich_threat_intel, dst_ip, context
            )

        # Collect results with timeout
        for name, future in futures.items():
            try:
                result = future.result(timeout=timeout)
                if name == "geo":
                    geo_data = result
                elif name == "threat":
                    threat_data = result
            except TimeoutError:
                self.logger.debug(f"{name} lookup timeout for {dst_ip}")
                if name == "geo":
                    self._geo_failures += 1
                else:
                    self._threat_failures += 1
            except Exception as e:
                self.logger.debug(f"{name} lookup failed for {dst_ip}: {e}")
                if name == "geo":
                    self._geo_failures += 1
                else:
                    self._threat_failures += 1

        return geo_data, threat_data

    def _enrich_geo(self, dst_ip: str, context: StageContext) -> Dict[str, Any]:
        """
        Geo enrichment lookup.

        Args:
            dst_ip: Destination IP
            context: Pipeline context

        Returns:
            Geo data dict or empty dict on failure
        """
        self._geo_lookups += 1

        if not context.geo_lookup:
            return {}

        try:
            result = context.geo_lookup.lookup(dst_ip)
            if result:
                self._geo_hits += 1
                return result
            return {}
        except Exception as e:
            self._geo_failures += 1
            self.logger.debug(f"Geo lookup failed for {dst_ip}: {e}")
            return {}

    def _enrich_threat_intel(self, dst_ip: str, context: StageContext) -> Dict[str, Any]:
        """
        Threat intelligence lookup.

        Args:
            dst_ip: Destination IP
            context: Pipeline context

        Returns:
            Threat intel data dict or empty dict on failure
        """
        self._threat_lookups += 1

        if not context.threat_intel:
            return {}

        try:
            result = context.threat_intel.check_ip(dst_ip)
            if result:
                self._threat_hits += 1
                return result
            return {}
        except Exception as e:
            self._threat_failures += 1
            self.logger.debug(f"Threat intel lookup failed for {dst_ip}: {e}")
            return {}

    def get_stats(self) -> Dict:
        """Get enrichment stage statistics"""
        stats = super().get_stats()
        stats.update({
            "geo_lookups": self._geo_lookups,
            "geo_hits": self._geo_hits,
            "geo_failures": self._geo_failures,
            "geo_hit_rate": self._geo_hits / max(self._geo_lookups, 1),
            "threat_lookups": self._threat_lookups,
            "threat_hits": self._threat_hits,
            "threat_failures": self._threat_failures,
            "threat_hit_rate": self._threat_hits / max(self._threat_lookups, 1),
        })
        return stats

    def health_check(self) -> bool:
        """Check if enrichment stage is healthy"""
        # Check if executor is alive
        if self._executor is None:
            return False

        # Check failure rates
        geo_failure_rate = self._geo_failures / max(self._geo_lookups, 1)
        threat_failure_rate = self._threat_failures / max(self._threat_lookups, 1)

        if geo_failure_rate > 0.5:
            self.logger.warning(f"High geo failure rate: {geo_failure_rate:.2%}")

        if threat_failure_rate > 0.5:
            self.logger.warning(f"High threat intel failure rate: {threat_failure_rate:.2%}")

        return True
