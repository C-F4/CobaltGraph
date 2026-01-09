"""
Pipeline Configuration

Centralizes all pipeline configuration values that were previously
scattered as magic numbers across the codebase.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional
import os


@dataclass
class EnrichmentConfig:
    """Configuration for parallel enrichment stage"""
    workers: int = 4
    timeout_seconds: float = 3.0
    geo_enabled: bool = True
    threat_intel_enabled: bool = True
    hostname_resolution_enabled: bool = True


@dataclass
class DeduplicationConfig:
    """Configuration for connection deduplication"""
    window_seconds: float = 60.0
    max_cache_size: int = 10000
    cleanup_threshold: float = 0.8  # Cleanup when cache reaches 80%


@dataclass
class ScoringConfig:
    """Configuration for threat scoring"""
    fallback_threat_score: float = 0.2
    fallback_confidence: float = 0.5
    high_threat_threshold: float = 0.7
    medium_threat_threshold: float = 0.5
    low_threat_threshold: float = 0.3


@dataclass
class AnomalyConfig:
    """Configuration for anomaly detection"""
    critical_threshold: float = 0.8
    high_threshold: float = 0.7
    warning_threshold: float = 0.5
    enabled: bool = True


@dataclass
class StorageConfig:
    """Configuration for database storage"""
    batch_size: int = 50
    batch_timeout_seconds: float = 0.5
    database_path: str = "data/cobaltgraph.db"
    wal_mode: bool = True
    cache_size_kb: int = 65536  # 64MB


@dataclass
class QueueConfig:
    """Configuration for processing queues"""
    input_queue_size: int = 1000
    output_buffer_size: int = 100
    drop_policy: str = "oldest"  # "oldest", "newest", "block"


@dataclass
class ExportConfig:
    """Configuration for data export"""
    enabled: bool = True
    export_directory: str = "exports"
    buffer_size: int = 100
    formats: list = field(default_factory=lambda: ["jsonl", "csv"])


@dataclass
class IPCConfig:
    """Configuration for IPC with C++ TUI"""
    socket_path: str = "/tmp/cobaltgraph.sock"
    update_interval_ms: int = 100
    max_connections_per_update: int = 50
    max_devices_per_update: int = 25


@dataclass
class PipelineConfig:
    """
    Master configuration for the entire pipeline.

    Centralizes all configuration values that were previously scattered
    as magic numbers across orchestrator.py, database.py, and other files.

    Usage:
        config = PipelineConfig()
        config = PipelineConfig.from_env()  # Load from environment
        config = PipelineConfig.from_file("config/pipeline.conf")
    """

    # Sub-configurations
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    deduplication: DeduplicationConfig = field(default_factory=DeduplicationConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    queue: QueueConfig = field(default_factory=QueueConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    ipc: IPCConfig = field(default_factory=IPCConfig)

    # Pipeline behavior
    parallel_enrichment: bool = True
    stage_metrics_enabled: bool = True
    debug_mode: bool = False

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        """
        Load configuration from environment variables.

        Environment variables use COBALTGRAPH_ prefix:
            COBALTGRAPH_ENRICHMENT_WORKERS=8
            COBALTGRAPH_DEDUP_WINDOW=120
            COBALTGRAPH_DEBUG=true
        """
        config = cls()

        # Enrichment
        if workers := os.getenv("COBALTGRAPH_ENRICHMENT_WORKERS"):
            config.enrichment.workers = int(workers)
        if timeout := os.getenv("COBALTGRAPH_ENRICHMENT_TIMEOUT"):
            config.enrichment.timeout_seconds = float(timeout)

        # Deduplication
        if window := os.getenv("COBALTGRAPH_DEDUP_WINDOW"):
            config.deduplication.window_seconds = float(window)
        if cache_size := os.getenv("COBALTGRAPH_DEDUP_CACHE_SIZE"):
            config.deduplication.max_cache_size = int(cache_size)

        # Scoring
        if fallback := os.getenv("COBALTGRAPH_FALLBACK_THREAT"):
            config.scoring.fallback_threat_score = float(fallback)

        # Storage
        if db_path := os.getenv("COBALTGRAPH_DATABASE_PATH"):
            config.storage.database_path = db_path
        if batch_size := os.getenv("COBALTGRAPH_BATCH_SIZE"):
            config.storage.batch_size = int(batch_size)

        # Debug
        if debug := os.getenv("COBALTGRAPH_DEBUG"):
            config.debug_mode = debug.lower() in ("true", "1", "yes")

        return config

    @classmethod
    def from_dict(cls, data: Dict) -> "PipelineConfig":
        """Create configuration from dictionary"""
        config = cls()

        if enrichment := data.get("enrichment"):
            config.enrichment = EnrichmentConfig(**enrichment)
        if dedup := data.get("deduplication"):
            config.deduplication = DeduplicationConfig(**dedup)
        if scoring := data.get("scoring"):
            config.scoring = ScoringConfig(**scoring)
        if anomaly := data.get("anomaly"):
            config.anomaly = AnomalyConfig(**anomaly)
        if storage := data.get("storage"):
            config.storage = StorageConfig(**storage)
        if queue := data.get("queue"):
            config.queue = QueueConfig(**queue)
        if export := data.get("export"):
            config.export = ExportConfig(**export)
        if ipc := data.get("ipc"):
            config.ipc = IPCConfig(**ipc)

        config.parallel_enrichment = data.get("parallel_enrichment", True)
        config.stage_metrics_enabled = data.get("stage_metrics_enabled", True)
        config.debug_mode = data.get("debug_mode", False)

        return config

    def to_dict(self) -> Dict:
        """Convert configuration to dictionary for serialization"""
        from dataclasses import asdict
        return asdict(self)

    def validate(self) -> list:
        """
        Validate configuration values.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if self.enrichment.workers < 1:
            errors.append("enrichment.workers must be >= 1")
        if self.enrichment.timeout_seconds <= 0:
            errors.append("enrichment.timeout_seconds must be > 0")

        if self.deduplication.window_seconds <= 0:
            errors.append("deduplication.window_seconds must be > 0")
        if self.deduplication.max_cache_size < 100:
            errors.append("deduplication.max_cache_size must be >= 100")

        if not 0 <= self.scoring.fallback_threat_score <= 1:
            errors.append("scoring.fallback_threat_score must be 0-1")
        if not 0 <= self.scoring.fallback_confidence <= 1:
            errors.append("scoring.fallback_confidence must be 0-1")

        if self.storage.batch_size < 1:
            errors.append("storage.batch_size must be >= 1")
        if self.storage.batch_timeout_seconds <= 0:
            errors.append("storage.batch_timeout_seconds must be > 0")

        if self.queue.input_queue_size < 10:
            errors.append("queue.input_queue_size must be >= 10")
        if self.queue.drop_policy not in ("oldest", "newest", "block"):
            errors.append("queue.drop_policy must be 'oldest', 'newest', or 'block'")

        return errors


# Default configuration instance
DEFAULT_CONFIG = PipelineConfig()
