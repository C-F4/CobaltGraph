#!/usr/bin/env python3
"""
Smart Alert Engine for CobaltGraph Intelligence Dashboard
Intelligent alert filtering and prioritization

Features:
- High-value event detection (anomalies, high threats, new devices)
- Alert categorization: CRITICAL / WARNING / INFO
- Auto-dismiss logic for low-value events
- Deduplication to prevent alert fatigue
- Rate limiting and throttling
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Dict, List, Optional, Set, Any

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "CRITICAL"  # Immediate attention required
    WARNING = "WARNING"    # Should be investigated
    INFO = "INFO"          # Informational only


class AlertCategory(Enum):
    """Alert categories"""
    HIGH_THREAT = "HIGH_THREAT"              # Threat score > 0.7
    ANOMALY = "ANOMALY"                      # Statistical anomaly detected
    NEW_DEVICE = "NEW_DEVICE"                # New device discovered
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN" # Unusual behavior pattern
    THREAT_SPIKE = "THREAT_SPIKE"            # Sudden threat increase
    NEW_DESTINATION = "NEW_DESTINATION"      # First connection to IP/org
    PORT_SCAN = "PORT_SCAN"                  # Potential port scanning
    GEO_ANOMALY = "GEO_ANOMALY"             # Unusual geographic destination


@dataclass
class Alert:
    """Smart alert object"""
    alert_id: str                  # Unique alert identifier
    severity: AlertSeverity        # Alert severity level
    category: AlertCategory        # Alert category
    title: str                     # Short alert title
    message: str                   # Detailed alert message
    source_ip: Optional[str]       # Source IP if applicable
    dst_ip: Optional[str]          # Destination IP if applicable
    dst_org: Optional[str]         # Destination organization
    threat_score: float            # Associated threat score
    confidence: float              # Alert confidence (0-1)
    metadata: Dict[str, Any]       # Additional metadata
    timestamp: float = field(default_factory=time.time)
    auto_dismiss: bool = False     # Should auto-dismiss after viewing
    dismissed: bool = False        # User dismissed flag


@dataclass
class AlertRule:
    """Alert generation rule"""
    name: str
    category: AlertCategory
    severity: AlertSeverity
    condition: callable            # Condition function
    message_template: str
    auto_dismiss: bool = False
    cooldown_seconds: int = 300    # Minimum time between same alerts


class AlertEngine:
    """
    Smart alert filtering and generation engine

    Only surfaces high-value events to prevent alert fatigue
    """

    # Alert thresholds
    CRITICAL_THRESHOLD = 0.7       # Threat score for CRITICAL alerts
    WARNING_THRESHOLD = 0.4        # Threat score for WARNING alerts
    ANOMALY_THRESHOLD = 0.6        # Anomaly score threshold
    PORT_SCAN_THRESHOLD = 10       # Unique ports in short time

    # Rate limiting
    MAX_ALERTS_PER_MINUTE = 50     # Max alerts to prevent flooding
    DEDUP_WINDOW = 300             # 5 minutes deduplication window

    def __init__(self, db_connection=None):
        """
        Initialize alert engine

        Args:
            db_connection: Database connection for logging alerts
        """
        self.db = db_connection
        self._lock = RLock()

        # Active alerts
        self._active_alerts: Dict[str, Alert] = {}
        self._alert_counter = 0

        # Deduplication tracking
        self._recent_alert_hashes: Dict[str, float] = {}  # hash -> timestamp
        self._rule_last_fired: Dict[str, float] = {}      # rule_name -> timestamp

        # Rate limiting
        self._alerts_this_minute: deque = deque()  # timestamps

        # Tracking for pattern detection
        self._connection_history: deque = deque(maxlen=1000)
        self._seen_ips: Set[str] = set()
        self._seen_orgs: Set[str] = set()
        self._port_scans: Dict[str, Set[int]] = defaultdict(set)  # src_ip -> ports

        # Alert rules
        self._rules: List[AlertRule] = self._initialize_rules()

        # Statistics
        self.stats = {
            "total_generated": 0,
            "critical": 0,
            "warning": 0,
            "info": 0,
            "auto_dismissed": 0,
            "deduplicated": 0,
            "rate_limited": 0,
        }

        logger.info("Alert Engine initialized with %d rules", len(self._rules))

    def _initialize_rules(self) -> List[AlertRule]:
        """Initialize alert detection rules"""
        return [
            # CRITICAL alerts
            AlertRule(
                name="high_threat_connection",
                category=AlertCategory.HIGH_THREAT,
                severity=AlertSeverity.CRITICAL,
                condition=lambda ctx: ctx.get("threat_score", 0) > self.CRITICAL_THRESHOLD,
                message_template="High threat connection detected to {dst_org} ({dst_ip})",
                auto_dismiss=False,
                cooldown_seconds=60,
            ),
            AlertRule(
                name="critical_anomaly",
                category=AlertCategory.ANOMALY,
                severity=AlertSeverity.CRITICAL,
                condition=lambda ctx: (
                    ctx.get("anomaly_score", 0) > 0.8 and
                    ctx.get("threat_score", 0) > self.WARNING_THRESHOLD
                ),
                message_template="Critical anomaly detected: {anomaly_type}",
                auto_dismiss=False,
                cooldown_seconds=300,
            ),
            AlertRule(
                name="threat_spike",
                category=AlertCategory.THREAT_SPIKE,
                severity=AlertSeverity.CRITICAL,
                condition=lambda ctx: ctx.get("threat_trend") == "increasing" and ctx.get("trend_change", 0) > 50,
                message_template="Threat level spiking: {trend_change:.1f}% increase",
                auto_dismiss=False,
                cooldown_seconds=600,
            ),

            # WARNING alerts
            AlertRule(
                name="medium_threat_connection",
                category=AlertCategory.HIGH_THREAT,
                severity=AlertSeverity.WARNING,
                condition=lambda ctx: (
                    self.WARNING_THRESHOLD < ctx.get("threat_score", 0) <= self.CRITICAL_THRESHOLD
                ),
                message_template="Medium threat connection to {dst_org} ({dst_ip})",
                auto_dismiss=True,
                cooldown_seconds=300,
            ),
            AlertRule(
                name="suspicious_anomaly",
                category=AlertCategory.ANOMALY,
                severity=AlertSeverity.WARNING,
                condition=lambda ctx: (
                    self.ANOMALY_THRESHOLD < ctx.get("anomaly_score", 0) <= 0.8
                ),
                message_template="Suspicious behavior detected: {anomaly_type}",
                auto_dismiss=True,
                cooldown_seconds=300,
            ),
            AlertRule(
                name="new_high_risk_org",
                category=AlertCategory.NEW_DESTINATION,
                severity=AlertSeverity.WARNING,
                condition=lambda ctx: (
                    ctx.get("is_new_org", False) and
                    ctx.get("org_risk") in ["HIGH", "CRITICAL"]
                ),
                message_template="First connection to high-risk organization: {dst_org}",
                auto_dismiss=False,
                cooldown_seconds=3600,
            ),
            AlertRule(
                name="port_scan_detected",
                category=AlertCategory.PORT_SCAN,
                severity=AlertSeverity.WARNING,
                condition=lambda ctx: ctx.get("unique_ports_count", 0) > self.PORT_SCAN_THRESHOLD,
                message_template="Potential port scan from {src_ip}: {unique_ports_count} ports",
                auto_dismiss=False,
                cooldown_seconds=300,
            ),

            # INFO alerts
            AlertRule(
                name="new_device_discovered",
                category=AlertCategory.NEW_DEVICE,
                severity=AlertSeverity.INFO,
                condition=lambda ctx: ctx.get("is_new_device", False),
                message_template="New device discovered: {device_vendor} ({src_mac})",
                auto_dismiss=True,
                cooldown_seconds=3600,
            ),
            AlertRule(
                name="new_destination",
                category=AlertCategory.NEW_DESTINATION,
                severity=AlertSeverity.INFO,
                condition=lambda ctx: (
                    ctx.get("is_new_ip", False) and
                    ctx.get("threat_score", 0) < self.WARNING_THRESHOLD
                ),
                message_template="New destination: {dst_org} ({dst_ip})",
                auto_dismiss=True,
                cooldown_seconds=1800,
            ),
        ]

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        self._alert_counter += 1
        return f"ALERT-{int(time.time())}-{self._alert_counter:04d}"

    def _compute_alert_hash(self, category: AlertCategory, key: str) -> str:
        """Compute hash for deduplication"""
        return f"{category.value}:{key}"

    def _is_duplicate(self, alert_hash: str) -> bool:
        """Check if alert is duplicate within dedup window"""
        with self._lock:
            if alert_hash in self._recent_alert_hashes:
                last_time = self._recent_alert_hashes[alert_hash]
                if time.time() - last_time < self.DEDUP_WINDOW:
                    return True

            # Record this alert
            self._recent_alert_hashes[alert_hash] = time.time()

            # Clean old entries
            cutoff = time.time() - self.DEDUP_WINDOW
            self._recent_alert_hashes = {
                h: t for h, t in self._recent_alert_hashes.items() if t > cutoff
            }

            return False

    def _check_rate_limit(self) -> bool:
        """Check if rate limit exceeded"""
        with self._lock:
            now = time.time()

            # Remove alerts older than 1 minute
            cutoff = now - 60
            while self._alerts_this_minute and self._alerts_this_minute[0] < cutoff:
                self._alerts_this_minute.popleft()

            # Check limit
            if len(self._alerts_this_minute) >= self.MAX_ALERTS_PER_MINUTE:
                return False

            # Add current alert
            self._alerts_this_minute.append(now)
            return True

    def _check_rule_cooldown(self, rule_name: str, cooldown: int) -> bool:
        """Check if rule is in cooldown period"""
        with self._lock:
            if rule_name in self._rule_last_fired:
                elapsed = time.time() - self._rule_last_fired[rule_name]
                if elapsed < cooldown:
                    return False

            self._rule_last_fired[rule_name] = time.time()
            return True

    def process_connection(self, connection: Dict) -> List[Alert]:
        """
        Process a connection and generate alerts

        Args:
            connection: Connection data dictionary

        Returns:
            List of generated alerts
        """
        alerts = []

        # Track connection
        self._connection_history.append(connection)

        # Build context for rule evaluation
        context = self._build_context(connection)

        # Evaluate each rule
        for rule in self._rules:
            try:
                # Check if condition met
                if not rule.condition(context):
                    continue

                # Check cooldown
                if not self._check_rule_cooldown(rule.name, rule.cooldown_seconds):
                    continue

                # Generate alert
                alert = self._create_alert(rule, context)

                if alert:
                    alerts.append(alert)

            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")

        return alerts

    def _build_context(self, connection: Dict) -> Dict[str, Any]:
        """Build context for rule evaluation"""
        dst_ip = connection.get("dst_ip", "")
        dst_org = connection.get("dst_org", "")
        src_ip = connection.get("src_ip", "")
        src_mac = connection.get("src_mac", "")

        # Check if new
        is_new_ip = dst_ip not in self._seen_ips
        is_new_org = dst_org and dst_org not in self._seen_orgs
        is_new_device = src_mac and src_mac not in {c.get("src_mac") for c in self._connection_history if c.get("src_mac")}

        # Update tracking
        if dst_ip:
            self._seen_ips.add(dst_ip)
        if dst_org:
            self._seen_orgs.add(dst_org)

        # Port scan detection
        dst_port = connection.get("dst_port")
        if src_ip and dst_port:
            self._port_scans[src_ip].add(dst_port)
            # Clean old entries (only keep last 5 minutes of data)
            if len(self._port_scans) > 100:
                oldest_ip = next(iter(self._port_scans))
                del self._port_scans[oldest_ip]

        unique_ports_count = len(self._port_scans.get(src_ip, set()))

        # Build context
        context = {
            **connection,
            "is_new_ip": is_new_ip,
            "is_new_org": is_new_org,
            "is_new_device": is_new_device,
            "unique_ports_count": unique_ports_count,
        }

        return context

    def _create_alert(self, rule: AlertRule, context: Dict) -> Optional[Alert]:
        """Create alert from rule and context"""
        # Format message
        try:
            message = rule.message_template.format(**context)
        except KeyError:
            message = rule.message_template

        # Generate alert hash for deduplication
        key_parts = [
            context.get("dst_ip", ""),
            context.get("dst_org", ""),
            context.get("src_ip", ""),
        ]
        alert_hash = self._compute_alert_hash(rule.category, "-".join(filter(None, key_parts)))

        # Check deduplication
        if self._is_duplicate(alert_hash):
            self.stats["deduplicated"] += 1
            logger.debug(f"Alert deduplicated: {rule.name}")
            return None

        # Check rate limit
        if not self._check_rate_limit():
            self.stats["rate_limited"] += 1
            logger.warning(f"Alert rate limit exceeded, dropping: {rule.name}")
            return None

        # Create alert
        alert = Alert(
            alert_id=self._generate_alert_id(),
            severity=rule.severity,
            category=rule.category,
            title=f"{rule.category.value}: {context.get('dst_org', context.get('dst_ip', 'Unknown'))}",
            message=message,
            source_ip=context.get("src_ip"),
            dst_ip=context.get("dst_ip"),
            dst_org=context.get("dst_org"),
            threat_score=context.get("threat_score", 0.0),
            confidence=context.get("confidence", 0.8),
            metadata={
                "rule": rule.name,
                "category": rule.category.value,
                "anomaly_score": context.get("anomaly_score"),
                "anomaly_type": context.get("anomaly_type"),
            },
            auto_dismiss=rule.auto_dismiss,
        )

        # Store active alert
        with self._lock:
            self._active_alerts[alert.alert_id] = alert

        # Update stats
        self.stats["total_generated"] += 1
        if rule.severity == AlertSeverity.CRITICAL:
            self.stats["critical"] += 1
        elif rule.severity == AlertSeverity.WARNING:
            self.stats["warning"] += 1
        else:
            self.stats["info"] += 1

        if rule.auto_dismiss:
            self.stats["auto_dismissed"] += 1

        # Log to database if available
        if self.db:
            self._log_alert_to_db(alert)

        logger.info(f"Alert generated: [{alert.severity.value}] {alert.title}")

        return alert

    def _log_alert_to_db(self, alert: Alert):
        """Log alert to database"""
        try:
            import json

            self.db.log_event(
                event_type="ALERT",
                message=alert.message,
                severity=alert.severity.value,
                source_ip=alert.source_ip,
                dst_ip=alert.dst_ip,
                threat_score=alert.threat_score,
                org_name=alert.dst_org,
                rule_matched=alert.metadata.get("rule"),
                metadata=json.dumps(alert.metadata),
            )
        except Exception as e:
            logger.error(f"Failed to log alert to database: {e}")

    def generate_smart_alerts(
        self,
        threat_posture=None,
        recent_connections: List[Dict] = None
    ) -> List[Alert]:
        """
        Generate smart alerts based on current state

        Args:
            threat_posture: ThreatPosture object from intelligence_aggregator
            recent_connections: Recent connection data

        Returns:
            List of high-value alerts only
        """
        alerts = []

        # Threat posture alerts
        if threat_posture:
            context = {
                "threat_trend": threat_posture.trend,
                "trend_change": threat_posture.trend_change,
                "current_threat": threat_posture.current_threat,
            }

            # Check threat spike rule
            for rule in self._rules:
                if rule.name == "threat_spike":
                    if rule.condition(context):
                        alert = self._create_alert(rule, context)
                        if alert:
                            alerts.append(alert)

        # Process recent connections
        if recent_connections:
            for conn in recent_connections:
                conn_alerts = self.process_connection(conn)
                alerts.extend(conn_alerts)

        return alerts

    def get_active_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        dismissed: bool = False
    ) -> List[Alert]:
        """
        Get active alerts with optional filtering

        Args:
            severity: Filter by severity level
            dismissed: Include dismissed alerts

        Returns:
            List of alerts
        """
        with self._lock:
            alerts = list(self._active_alerts.values())

            if severity:
                alerts = [a for a in alerts if a.severity == severity]

            if not dismissed:
                alerts = [a for a in alerts if not a.dismissed]

            # Sort by timestamp (newest first)
            alerts.sort(key=lambda a: a.timestamp, reverse=True)

            return alerts

    def dismiss_alert(self, alert_id: str):
        """Dismiss an alert"""
        with self._lock:
            if alert_id in self._active_alerts:
                self._active_alerts[alert_id].dismissed = True
                logger.debug(f"Alert dismissed: {alert_id}")

    def clear_old_alerts(self, max_age_seconds: int = 3600):
        """Clear alerts older than specified age"""
        with self._lock:
            cutoff = time.time() - max_age_seconds
            to_remove = [
                alert_id for alert_id, alert in self._active_alerts.items()
                if alert.timestamp < cutoff and (alert.dismissed or alert.auto_dismiss)
            ]

            for alert_id in to_remove:
                del self._active_alerts[alert_id]

            if to_remove:
                logger.info(f"Cleared {len(to_remove)} old alerts")

    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert engine statistics"""
        with self._lock:
            active_count = len([a for a in self._active_alerts.values() if not a.dismissed])
            critical_count = len([a for a in self._active_alerts.values()
                                 if a.severity == AlertSeverity.CRITICAL and not a.dismissed])
            warning_count = len([a for a in self._active_alerts.values()
                                if a.severity == AlertSeverity.WARNING and not a.dismissed])

            return {
                **self.stats,
                "active_alerts": active_count,
                "active_critical": critical_count,
                "active_warning": warning_count,
                "total_alerts_stored": len(self._active_alerts),
            }


# Convenience factory function
def create_alert_engine(db_connection=None) -> AlertEngine:
    """
    Create an AlertEngine instance

    Args:
        db_connection: Database connection from src.storage.database.Database

    Returns:
        Configured AlertEngine
    """
    return AlertEngine(db_connection=db_connection)


if __name__ == "__main__":
    # Test alert engine
    logging.basicConfig(level=logging.INFO)

    print("=" * 70)
    print("Alert Engine Test")
    print("=" * 70)

    engine = AlertEngine()

    # Test connection data
    test_connections = [
        {
            "src_ip": "192.168.1.100",
            "src_mac": "00:11:22:33:44:55",
            "dst_ip": "185.220.101.1",
            "dst_port": 443,
            "dst_org": "Tor Exit Node",
            "threat_score": 0.85,
            "device_vendor": "Apple",
        },
        {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "dst_org": "Google",
            "threat_score": 0.1,
        },
        {
            "src_ip": "192.168.1.101",
            "src_mac": "AA:BB:CC:DD:EE:FF",
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
            "dst_org": "Cloudflare",
            "threat_score": 0.15,
            "device_vendor": "Samsung",
        },
    ]

    print("\n--- Processing Test Connections ---")
    for conn in test_connections:
        alerts = engine.process_connection(conn)
        for alert in alerts:
            print(f"[{alert.severity.value}] {alert.message}")

    print("\n--- Active Alerts ---")
    active = engine.get_active_alerts(dismissed=False)
    print(f"Total active: {len(active)}")
    for alert in active:
        print(f"  [{alert.severity.value}] {alert.title}")

    print("\n--- Alert Statistics ---")
    stats = engine.get_alert_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
