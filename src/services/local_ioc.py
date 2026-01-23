"""
Local IOC (Indicator of Compromise) Service for CobaltGraph

Loads site-specific threat intelligence from local CSV/JSON files.
Allows organizations to maintain their own IOC lists that integrate
into the consensus scoring system.

Usage:
    ioc_service = LocalIOCService("data/ioc/")
    match = ioc_service.check_ip("1.2.3.4")
    if match:
        print(f"IOC Match: {match.threat_type} from {match.source}")
"""

import csv
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock, Thread
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class IOCMatch:
    """Represents a matched IOC indicator"""
    indicator: str  # The matched value (IP, domain, hash)
    indicator_type: str  # ip, domain, hash, url
    threat_type: str  # malware, c2, botnet, scanner, etc.
    confidence: float  # 0.0 - 1.0
    source: str  # Source file or feed name
    description: str = ""
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class IOCEntry:
    """Internal representation of an IOC entry"""
    value: str
    indicator_type: str
    threat_type: str
    confidence: float
    source: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    metadata: Dict = field(default_factory=dict)


class LocalIOCService:
    """
    Local IOC loading and matching service

    Features:
    - Loads IOCs from CSV and JSON files
    - Supports IP, domain, hash, and URL indicators
    - Auto-reloads when files change (optional)
    - Thread-safe lookups with LRU cache
    - CIDR network matching for IP ranges
    """

    # Supported file formats
    SUPPORTED_EXTENSIONS = {".csv", ".json", ".txt"}

    # Default column mappings for CSV files
    CSV_COLUMNS = {
        "indicator": ["indicator", "ioc", "value", "ip", "domain", "hash"],
        "type": ["type", "indicator_type", "ioc_type"],
        "threat_type": ["threat_type", "category", "classification", "threat"],
        "confidence": ["confidence", "score", "severity"],
        "source": ["source", "feed", "provider"],
        "description": ["description", "desc", "notes", "comment"],
        "tags": ["tags", "labels"],
    }

    def __init__(
        self,
        ioc_directory: str = "data/ioc/",
        auto_reload: bool = True,
        reload_interval: int = 300,  # 5 minutes
        cache_size: int = 10000,
    ):
        """
        Initialize Local IOC Service

        Args:
            ioc_directory: Directory containing IOC files
            auto_reload: Automatically reload files when they change
            reload_interval: Seconds between reload checks
            cache_size: Maximum cache entries
        """
        self.ioc_directory = Path(ioc_directory)
        self.auto_reload = auto_reload
        self.reload_interval = reload_interval
        self.cache_size = cache_size

        # IOC storage by type
        self._ip_iocs: Dict[str, IOCEntry] = {}  # IP -> IOCEntry
        self._domain_iocs: Dict[str, IOCEntry] = {}  # domain -> IOCEntry
        self._hash_iocs: Dict[str, IOCEntry] = {}  # hash -> IOCEntry
        self._cidr_iocs: List[tuple] = []  # [(network, prefix_len, IOCEntry)]

        # Thread safety
        self._lock = Lock()
        self._file_mtimes: Dict[str, float] = {}

        # Cache for repeated lookups
        self._cache: Dict[str, Optional[IOCMatch]] = {}
        self._cache_order: List[str] = []
        self._cache_lock = Lock()

        # Statistics
        self.stats = {
            "total_iocs": 0,
            "ip_iocs": 0,
            "domain_iocs": 0,
            "hash_iocs": 0,
            "cidr_iocs": 0,
            "files_loaded": 0,
            "lookups": 0,
            "cache_hits": 0,
            "matches": 0,
            "last_reload": 0,
        }

        # Auto-reload thread
        self._running = True
        self._reload_thread: Optional[Thread] = None

        # Initial load
        self._load_all_iocs()

        # Start auto-reload if enabled
        if auto_reload:
            self._start_reload_thread()

        logger.info(
            f"LocalIOCService initialized: {self.stats['total_iocs']} indicators "
            f"from {self.stats['files_loaded']} files"
        )

    def _start_reload_thread(self):
        """Start background thread for auto-reloading IOC files"""
        self._reload_thread = Thread(target=self._reload_loop, daemon=True)
        self._reload_thread.start()

    def _reload_loop(self):
        """Background loop to check for file changes"""
        while self._running:
            time.sleep(self.reload_interval)
            if not self._running:
                break

            try:
                self._check_and_reload()
            except Exception as e:
                logger.error(f"IOC reload error: {e}")

    def _check_and_reload(self):
        """Check if any IOC files have changed and reload if needed"""
        if not self.ioc_directory.exists():
            return

        needs_reload = False
        current_files = set()

        for ext in self.SUPPORTED_EXTENSIONS:
            for ioc_file in self.ioc_directory.glob(f"*{ext}"):
                current_files.add(str(ioc_file))
                mtime = ioc_file.stat().st_mtime
                if str(ioc_file) not in self._file_mtimes or mtime > self._file_mtimes[str(ioc_file)]:
                    needs_reload = True
                    break

        # Check for deleted files
        if set(self._file_mtimes.keys()) != current_files:
            needs_reload = True

        if needs_reload:
            logger.info("IOC files changed, reloading...")
            self._load_all_iocs()
            self._clear_cache()

    def _load_all_iocs(self):
        """Load all IOC files from the directory"""
        with self._lock:
            # Clear existing IOCs
            self._ip_iocs.clear()
            self._domain_iocs.clear()
            self._hash_iocs.clear()
            self._cidr_iocs.clear()
            self._file_mtimes.clear()

            if not self.ioc_directory.exists():
                logger.warning(f"IOC directory does not exist: {self.ioc_directory}")
                self._update_stats()
                return

            files_loaded = 0
            for ext in self.SUPPORTED_EXTENSIONS:
                for ioc_file in self.ioc_directory.glob(f"*{ext}"):
                    try:
                        self._load_file(ioc_file)
                        self._file_mtimes[str(ioc_file)] = ioc_file.stat().st_mtime
                        files_loaded += 1
                    except Exception as e:
                        logger.error(f"Failed to load IOC file {ioc_file}: {e}")

            self.stats["files_loaded"] = files_loaded
            self.stats["last_reload"] = time.time()
            self._update_stats()

    def _load_file(self, file_path: Path):
        """Load IOCs from a single file"""
        ext = file_path.suffix.lower()
        source = file_path.stem

        if ext == ".csv":
            self._load_csv(file_path, source)
        elif ext == ".json":
            self._load_json(file_path, source)
        elif ext == ".txt":
            self._load_txt(file_path, source)

    def _load_csv(self, file_path: Path, source: str):
        """Load IOCs from CSV file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    return

                # Map columns to standard names
                column_map = {}
                for std_name, variants in self.CSV_COLUMNS.items():
                    for variant in variants:
                        for col in reader.fieldnames:
                            if col.lower().strip() == variant.lower():
                                column_map[std_name] = col
                                break
                        if std_name in column_map:
                            break

                if "indicator" not in column_map:
                    logger.warning(f"No indicator column found in {file_path}")
                    return

                for row in reader:
                    try:
                        indicator = row.get(column_map.get("indicator", ""), "").strip()
                        if not indicator:
                            continue

                        # Determine indicator type
                        ioc_type = row.get(column_map.get("type", ""), "").lower()
                        if not ioc_type:
                            ioc_type = self._detect_indicator_type(indicator)

                        # Parse confidence
                        confidence_str = row.get(column_map.get("confidence", ""), "0.8")
                        try:
                            confidence = float(confidence_str)
                            if confidence > 1:
                                confidence = confidence / 100  # Assume percentage
                        except ValueError:
                            confidence = 0.8

                        # Parse tags
                        tags_str = row.get(column_map.get("tags", ""), "")
                        tags = [t.strip() for t in tags_str.split(",") if t.strip()]

                        entry = IOCEntry(
                            value=indicator,
                            indicator_type=ioc_type,
                            threat_type=row.get(column_map.get("threat_type", ""), "unknown"),
                            confidence=confidence,
                            source=source,
                            description=row.get(column_map.get("description", ""), ""),
                            tags=tags,
                        )
                        self._add_ioc(entry)

                    except Exception as e:
                        logger.debug(f"Error parsing CSV row: {e}")

        except Exception as e:
            logger.error(f"Error loading CSV {file_path}: {e}")

    def _load_json(self, file_path: Path, source: str):
        """Load IOCs from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Support both list and dict formats
            if isinstance(data, list):
                indicators = data
            elif isinstance(data, dict):
                # Check common keys
                for key in ["indicators", "iocs", "data", "items"]:
                    if key in data:
                        indicators = data[key]
                        break
                else:
                    indicators = [data]  # Single indicator
            else:
                return

            for item in indicators:
                if isinstance(item, str):
                    # Simple string indicator
                    ioc_type = self._detect_indicator_type(item)
                    entry = IOCEntry(
                        value=item,
                        indicator_type=ioc_type,
                        threat_type="unknown",
                        confidence=0.8,
                        source=source,
                    )
                elif isinstance(item, dict):
                    indicator = item.get("indicator") or item.get("value") or item.get("ip") or item.get("domain", "")
                    if not indicator:
                        continue

                    ioc_type = item.get("type") or item.get("indicator_type") or self._detect_indicator_type(indicator)

                    confidence = item.get("confidence") or item.get("score", 0.8)
                    if isinstance(confidence, str):
                        try:
                            confidence = float(confidence)
                        except ValueError:
                            confidence = 0.8

                    entry = IOCEntry(
                        value=indicator,
                        indicator_type=ioc_type,
                        threat_type=item.get("threat_type") or item.get("category", "unknown"),
                        confidence=confidence,
                        source=source,
                        description=item.get("description", ""),
                        tags=item.get("tags", []),
                        metadata=item.get("metadata", {}),
                    )
                else:
                    continue

                self._add_ioc(entry)

        except Exception as e:
            logger.error(f"Error loading JSON {file_path}: {e}")

    def _load_txt(self, file_path: Path, source: str):
        """Load IOCs from plain text file (one per line)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Handle format: indicator,type,threat_type,confidence
                    parts = line.split(",")
                    indicator = parts[0].strip()

                    if not indicator:
                        continue

                    ioc_type = parts[1].strip() if len(parts) > 1 else self._detect_indicator_type(indicator)
                    threat_type = parts[2].strip() if len(parts) > 2 else "unknown"

                    try:
                        confidence = float(parts[3].strip()) if len(parts) > 3 else 0.8
                    except ValueError:
                        confidence = 0.8

                    entry = IOCEntry(
                        value=indicator,
                        indicator_type=ioc_type,
                        threat_type=threat_type,
                        confidence=confidence,
                        source=source,
                    )
                    self._add_ioc(entry)

        except Exception as e:
            logger.error(f"Error loading TXT {file_path}: {e}")

    def _detect_indicator_type(self, value: str) -> str:
        """Detect the type of indicator based on format"""
        import re

        value = value.strip().lower()

        # IP address (v4)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', value):
            return "ip"

        # IP address (v6)
        if re.match(r'^[0-9a-f:]+(/\d{1,3})?$', value) and ":" in value:
            return "ip"

        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[0-9a-f]{32}$', value):  # MD5
            return "hash"
        if re.match(r'^[0-9a-f]{40}$', value):  # SHA1
            return "hash"
        if re.match(r'^[0-9a-f]{64}$', value):  # SHA256
            return "hash"

        # URL
        if value.startswith(("http://", "https://", "ftp://")):
            return "url"

        # Domain (default for anything else with dots)
        if "." in value and not value.startswith("/"):
            return "domain"

        return "unknown"

    def _add_ioc(self, entry: IOCEntry):
        """Add IOC entry to appropriate storage"""
        if entry.indicator_type == "ip":
            # Check for CIDR notation
            if "/" in entry.value:
                try:
                    network, prefix = entry.value.split("/")
                    prefix_len = int(prefix)
                    self._cidr_iocs.append((network, prefix_len, entry))
                except ValueError:
                    pass
            else:
                self._ip_iocs[entry.value.lower()] = entry
        elif entry.indicator_type == "domain":
            self._domain_iocs[entry.value.lower()] = entry
        elif entry.indicator_type == "hash":
            self._hash_iocs[entry.value.lower()] = entry

    def _update_stats(self):
        """Update statistics counters"""
        self.stats["ip_iocs"] = len(self._ip_iocs)
        self.stats["domain_iocs"] = len(self._domain_iocs)
        self.stats["hash_iocs"] = len(self._hash_iocs)
        self.stats["cidr_iocs"] = len(self._cidr_iocs)
        self.stats["total_iocs"] = (
            self.stats["ip_iocs"] +
            self.stats["domain_iocs"] +
            self.stats["hash_iocs"] +
            self.stats["cidr_iocs"]
        )

    def _clear_cache(self):
        """Clear the lookup cache"""
        with self._cache_lock:
            self._cache.clear()
            self._cache_order.clear()

    def _cache_get(self, key: str) -> tuple[bool, Optional[IOCMatch]]:
        """Get from cache. Returns (found, value)"""
        with self._cache_lock:
            if key in self._cache:
                self.stats["cache_hits"] += 1
                return True, self._cache[key]
        return False, None

    def _cache_put(self, key: str, value: Optional[IOCMatch]):
        """Put in cache with LRU eviction"""
        with self._cache_lock:
            if len(self._cache) >= self.cache_size:
                # Remove oldest entries
                for old_key in self._cache_order[:self.cache_size // 5]:
                    self._cache.pop(old_key, None)
                self._cache_order = self._cache_order[self.cache_size // 5:]

            self._cache[key] = value
            self._cache_order.append(key)

    def check_ip(self, ip: str) -> Optional[IOCMatch]:
        """
        Check if IP address matches any IOC

        Args:
            ip: IP address to check

        Returns:
            IOCMatch if found, None otherwise
        """
        self.stats["lookups"] += 1

        # Check cache first
        cache_key = f"ip:{ip}"
        found, cached = self._cache_get(cache_key)
        if found:
            return cached

        ip_lower = ip.lower().strip()

        with self._lock:
            # Direct IP lookup
            if ip_lower in self._ip_iocs:
                entry = self._ip_iocs[ip_lower]
                match = self._entry_to_match(entry)
                self.stats["matches"] += 1
                self._cache_put(cache_key, match)
                return match

            # CIDR range check (simplified - for production use ipaddress module)
            for network, prefix_len, entry in self._cidr_iocs:
                if self._ip_in_cidr(ip_lower, network, prefix_len):
                    match = self._entry_to_match(entry)
                    self.stats["matches"] += 1
                    self._cache_put(cache_key, match)
                    return match

        self._cache_put(cache_key, None)
        return None

    def check_domain(self, domain: str) -> Optional[IOCMatch]:
        """
        Check if domain matches any IOC

        Args:
            domain: Domain name to check

        Returns:
            IOCMatch if found, None otherwise
        """
        self.stats["lookups"] += 1

        cache_key = f"domain:{domain}"
        found, cached = self._cache_get(cache_key)
        if found:
            return cached

        domain_lower = domain.lower().strip()

        with self._lock:
            # Direct domain lookup
            if domain_lower in self._domain_iocs:
                entry = self._domain_iocs[domain_lower]
                match = self._entry_to_match(entry)
                self.stats["matches"] += 1
                self._cache_put(cache_key, match)
                return match

            # Check parent domains
            parts = domain_lower.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in self._domain_iocs:
                    entry = self._domain_iocs[parent]
                    match = self._entry_to_match(entry)
                    self.stats["matches"] += 1
                    self._cache_put(cache_key, match)
                    return match

        self._cache_put(cache_key, None)
        return None

    def check_hash(self, file_hash: str) -> Optional[IOCMatch]:
        """
        Check if hash matches any IOC

        Args:
            file_hash: File hash to check (MD5, SHA1, or SHA256)

        Returns:
            IOCMatch if found, None otherwise
        """
        self.stats["lookups"] += 1

        cache_key = f"hash:{file_hash}"
        found, cached = self._cache_get(cache_key)
        if found:
            return cached

        hash_lower = file_hash.lower().strip()

        with self._lock:
            if hash_lower in self._hash_iocs:
                entry = self._hash_iocs[hash_lower]
                match = self._entry_to_match(entry)
                self.stats["matches"] += 1
                self._cache_put(cache_key, match)
                return match

        self._cache_put(cache_key, None)
        return None

    def _ip_in_cidr(self, ip: str, network: str, prefix_len: int) -> bool:
        """Check if IP is in CIDR range (simplified implementation)"""
        try:
            # Convert IP to integer
            ip_parts = [int(p) for p in ip.split(".")]
            network_parts = [int(p) for p in network.split(".")]

            if len(ip_parts) != 4 or len(network_parts) != 4:
                return False

            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
            network_int = (network_parts[0] << 24) + (network_parts[1] << 16) + (network_parts[2] << 8) + network_parts[3]

            # Create mask
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

            return (ip_int & mask) == (network_int & mask)

        except (ValueError, IndexError):
            return False

    def _entry_to_match(self, entry: IOCEntry) -> IOCMatch:
        """Convert IOCEntry to IOCMatch"""
        return IOCMatch(
            indicator=entry.value,
            indicator_type=entry.indicator_type,
            threat_type=entry.threat_type,
            confidence=entry.confidence,
            source=entry.source,
            description=entry.description,
            tags=entry.tags,
            first_seen=entry.first_seen,
            last_seen=entry.last_seen,
            metadata=entry.metadata,
        )

    def get_stats(self) -> Dict:
        """Get service statistics"""
        return dict(self.stats)

    def shutdown(self):
        """Graceful shutdown"""
        self._running = False
        if self._reload_thread and self._reload_thread.is_alive():
            self._reload_thread.join(timeout=2)
        logger.info("LocalIOCService shutdown complete")
