#!/usr/bin/env python3
"""
CobaltGraph Investigation Queue Panel

A dashboard widget showing high-priority connections for SOC analyst triage.
Surfaces connections requiring human review based on:
- High scorer uncertainty (disagreement)
- New high-risk destinations
- Beaconing patterns detected
- Local IOC matches
- Domain intelligence alerts (DGA, ASN mismatch)

Usage:
    panel = InvestigationQueuePanel()
    panel.add_investigation_item(connection_data)
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.app import ComposeResult
from textual.containers import Container, Vertical, ScrollableContainer
from textual.widgets import Static, Button, Label
from textual.reactive import reactive
from textual.binding import Binding

logger = logging.getLogger(__name__)


class InvestigationPriority(Enum):
    """Priority levels for investigation items"""
    CRITICAL = 1  # Immediate action required
    HIGH = 2      # Should be reviewed soon
    MEDIUM = 3    # Review when time permits
    LOW = 4       # Informational


class InvestigationReason(Enum):
    """Reasons a connection was flagged for investigation"""
    HIGH_UNCERTAINTY = "high_uncertainty"
    NEW_HIGH_RISK = "new_high_risk"
    BEACONING = "beaconing"
    LOCAL_IOC_MATCH = "local_ioc_match"
    DGA_DETECTED = "dga_detected"
    DOMAIN_ASN_MISMATCH = "domain_asn_mismatch"
    MULTI_DEVICE_CONTACT = "multi_device_contact"
    UNUSUAL_PORT = "unusual_port"
    TOR_PROXY = "tor_proxy"
    MANUAL_FLAG = "manual_flag"


@dataclass
class InvestigationItem:
    """A connection flagged for analyst review"""
    item_id: str
    timestamp: float
    dst_ip: str
    dst_port: int
    reason: InvestigationReason
    priority: InvestigationPriority

    # Connection details
    src_ip: str = ""
    domain: str = ""  # DNS query or TLS SNI
    dst_org: str = ""
    dst_asn: Optional[int] = None
    threat_score: float = 0.0
    confidence: float = 0.0

    # Scorer breakdown (for uncertainty visualization)
    score_statistical: Optional[float] = None
    score_rule_based: Optional[float] = None
    score_ml_based: Optional[float] = None
    score_organization: Optional[float] = None

    # Additional context
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Status tracking
    status: str = "pending"  # pending, investigating, dismissed, resolved
    assigned_to: str = ""
    notes: str = ""

    def get_priority_color(self) -> str:
        """Get color for priority display"""
        return {
            InvestigationPriority.CRITICAL: "bold red",
            InvestigationPriority.HIGH: "bold yellow",
            InvestigationPriority.MEDIUM: "yellow",
            InvestigationPriority.LOW: "dim",
        }.get(self.priority, "white")

    def get_reason_display(self) -> tuple:
        """Get display text and icon for reason"""
        reason_info = {
            InvestigationReason.HIGH_UNCERTAINTY: ("HIGH UNCERTAINTY", "!", "Scorers Disagreed"),
            InvestigationReason.NEW_HIGH_RISK: ("NEW HIGH-RISK", "!", "First Contact"),
            InvestigationReason.BEACONING: ("BEACONING", "?", "Pattern Detected"),
            InvestigationReason.LOCAL_IOC_MATCH: ("IOC MATCH", "!", "Local Database Hit"),
            InvestigationReason.DGA_DETECTED: ("DGA DETECTED", "!", "Algorithmic Domain"),
            InvestigationReason.DOMAIN_ASN_MISMATCH: ("DOMAIN MISMATCH", "?", "ASN Correlation Failed"),
            InvestigationReason.MULTI_DEVICE_CONTACT: ("MULTI-DEVICE", "?", "Multiple Sources"),
            InvestigationReason.UNUSUAL_PORT: ("UNUSUAL PORT", "?", "Non-standard Port"),
            InvestigationReason.TOR_PROXY: ("TOR/PROXY", "!", "Anonymization Detected"),
            InvestigationReason.MANUAL_FLAG: ("MANUAL FLAG", "?", "User Flagged"),
        }
        return reason_info.get(self.reason, ("UNKNOWN", "?", "Unknown reason"))

    def get_age_display(self) -> str:
        """Get human-readable age"""
        age_seconds = time.time() - self.timestamp
        if age_seconds < 60:
            return f"{int(age_seconds)}s ago"
        elif age_seconds < 3600:
            return f"{int(age_seconds / 60)}m ago"
        elif age_seconds < 86400:
            return f"{int(age_seconds / 3600)}h ago"
        else:
            return f"{int(age_seconds / 86400)}d ago"


class InvestigationQueue:
    """
    Manages the queue of connections requiring investigation.
    Thread-safe for use with the async data pipeline.
    """

    MAX_ITEMS = 100  # Maximum items to keep in queue
    AUTO_DISMISS_AGE = 3600 * 24  # Auto-dismiss items older than 24h

    def __init__(self):
        self._items: Dict[str, InvestigationItem] = {}
        self._lock = Lock()
        self._item_counter = 0

        # Statistics
        self.stats = {
            "total_added": 0,
            "auto_dismissed": 0,
            "manually_dismissed": 0,
            "resolved": 0,
        }

    def add_item(self, item: InvestigationItem) -> str:
        """Add item to investigation queue"""
        with self._lock:
            # Generate ID if not provided
            if not item.item_id:
                self._item_counter += 1
                item.item_id = f"INV-{self._item_counter:06d}"

            # Check for duplicates (same IP within 5 minutes)
            for existing in self._items.values():
                if (existing.dst_ip == item.dst_ip and
                    existing.reason == item.reason and
                    time.time() - existing.timestamp < 300):
                    # Update existing instead of adding duplicate
                    existing.timestamp = item.timestamp
                    existing.threat_score = max(existing.threat_score, item.threat_score)
                    return existing.item_id

            # Add new item
            self._items[item.item_id] = item
            self.stats["total_added"] += 1

            # Cleanup old items
            self._cleanup()

            return item.item_id

    def get_items(self, priority: Optional[InvestigationPriority] = None,
                  status: str = "pending", limit: int = 50) -> List[InvestigationItem]:
        """Get items from queue, sorted by priority and timestamp"""
        with self._lock:
            items = list(self._items.values())

            # Filter by status
            if status:
                items = [i for i in items if i.status == status]

            # Filter by priority
            if priority:
                items = [i for i in items if i.priority == priority]

            # Sort by priority (lower is higher priority), then by timestamp (newer first)
            items.sort(key=lambda x: (x.priority.value, -x.timestamp))

            return items[:limit]

    def get_item(self, item_id: str) -> Optional[InvestigationItem]:
        """Get specific item by ID"""
        with self._lock:
            return self._items.get(item_id)

    def update_status(self, item_id: str, status: str, notes: str = "") -> bool:
        """Update item status"""
        with self._lock:
            if item_id not in self._items:
                return False

            item = self._items[item_id]
            old_status = item.status
            item.status = status
            if notes:
                item.notes = notes

            # Update stats
            if status == "dismissed" and old_status != "dismissed":
                self.stats["manually_dismissed"] += 1
            elif status == "resolved" and old_status != "resolved":
                self.stats["resolved"] += 1

            return True

    def dismiss_item(self, item_id: str, reason: str = "") -> bool:
        """Dismiss an investigation item"""
        return self.update_status(item_id, "dismissed", reason)

    def resolve_item(self, item_id: str, resolution: str = "") -> bool:
        """Mark item as resolved"""
        return self.update_status(item_id, "resolved", resolution)

    def _cleanup(self):
        """Remove old items and enforce max size"""
        now = time.time()
        to_remove = []

        for item_id, item in self._items.items():
            # Auto-dismiss old items
            if item.status == "pending" and now - item.timestamp > self.AUTO_DISMISS_AGE:
                item.status = "auto_dismissed"
                self.stats["auto_dismissed"] += 1
                to_remove.append(item_id)

            # Remove resolved/dismissed items older than 1 hour
            if item.status in ("dismissed", "resolved", "auto_dismissed"):
                if now - item.timestamp > 3600:
                    to_remove.append(item_id)

        for item_id in to_remove:
            del self._items[item_id]

        # Enforce max size by removing oldest low-priority items
        if len(self._items) > self.MAX_ITEMS:
            items = sorted(self._items.values(),
                          key=lambda x: (-x.priority.value, x.timestamp))
            excess = len(self._items) - self.MAX_ITEMS
            for item in items[:excess]:
                del self._items[item.item_id]

    def get_stats(self) -> Dict:
        """Get queue statistics"""
        with self._lock:
            pending = sum(1 for i in self._items.values() if i.status == "pending")
            critical = sum(1 for i in self._items.values()
                          if i.status == "pending" and i.priority == InvestigationPriority.CRITICAL)
            return {
                **self.stats,
                "pending": pending,
                "critical": critical,
                "total_in_queue": len(self._items),
            }


class InvestigationQueuePanel(Static):
    """
    Dashboard panel showing investigation queue for SOC analysts.
    Displays high-priority connections requiring human review.
    """

    DEFAULT_CSS = """
    InvestigationQueuePanel {
        width: 100%;
        height: 100%;
        padding: 0;
    }
    """

    # Reactive property for queue updates
    queue_version = reactive(0)

    def __init__(self, queue: Optional[InvestigationQueue] = None, **kwargs):
        super().__init__(**kwargs)
        self.queue = queue or InvestigationQueue()
        self._on_item_select: Optional[Callable[[InvestigationItem], None]] = None

    def set_on_select(self, callback: Callable[[InvestigationItem], None]):
        """Set callback for when an item is selected"""
        self._on_item_select = callback

    def add_from_connection(self, connection_data: Dict[str, Any]) -> Optional[str]:
        """
        Analyze a connection and add to investigation queue if warranted.

        Returns item_id if added, None otherwise.
        """
        # Check if this connection should be investigated
        reason, priority = self._should_investigate(connection_data)
        if not reason:
            return None

        # Create investigation item
        item = InvestigationItem(
            item_id="",  # Will be assigned by queue
            timestamp=connection_data.get("timestamp", time.time()),
            dst_ip=connection_data.get("dst_ip", ""),
            dst_port=connection_data.get("dst_port", 0),
            reason=reason,
            priority=priority,
            src_ip=connection_data.get("src_ip", ""),
            domain=connection_data.get("dns_query") or connection_data.get("tls_sni") or "",
            dst_org=connection_data.get("dst_org", ""),
            dst_asn=connection_data.get("dst_asn"),
            threat_score=connection_data.get("threat_score", 0),
            confidence=connection_data.get("confidence", 0),
            score_statistical=connection_data.get("score_statistical"),
            score_rule_based=connection_data.get("score_rule_based"),
            score_ml_based=connection_data.get("score_ml_based"),
            score_organization=connection_data.get("score_organization"),
            description=self._generate_description(connection_data, reason),
            metadata=self._extract_metadata(connection_data),
        )

        item_id = self.queue.add_item(item)

        # Trigger UI update
        self.queue_version += 1

        return item_id

    def _should_investigate(self, data: Dict) -> tuple:
        """
        Determine if a connection should be added to investigation queue.

        Returns (reason, priority) or (None, None) if not warranted.
        """
        # Priority 1: Local IOC match - always investigate
        if data.get("local_ioc_match"):
            return (InvestigationReason.LOCAL_IOC_MATCH, InvestigationPriority.CRITICAL)

        # Priority 2: DGA detected - high risk
        if data.get("dga_detected"):
            return (InvestigationReason.DGA_DETECTED, InvestigationPriority.CRITICAL)

        # Priority 3: Tor/Proxy with high threat
        org_type = (data.get("dst_org_type") or "").lower()
        threat = data.get("threat_score", 0)
        if org_type in ("tor", "proxy") and threat >= 0.5:
            return (InvestigationReason.TOR_PROXY, InvestigationPriority.HIGH)

        # Priority 4: High uncertainty (scorers disagreed significantly)
        if data.get("high_uncertainty") and threat >= 0.3:
            return (InvestigationReason.HIGH_UNCERTAINTY, InvestigationPriority.HIGH)

        # Priority 5: Domain-ASN mismatch with elevated threat
        if data.get("domain_asn_mismatch") and threat >= 0.4:
            return (InvestigationReason.DOMAIN_ASN_MISMATCH, InvestigationPriority.MEDIUM)

        # Priority 6: Unusual ephemeral destination port with high threat
        dst_port = data.get("dst_port", 0)
        if dst_port >= 49152 and threat >= 0.5:
            return (InvestigationReason.UNUSUAL_PORT, InvestigationPriority.MEDIUM)

        # Priority 7: Beaconing detected (will be set by beaconing detector)
        if data.get("beaconing_detected"):
            return (InvestigationReason.BEACONING, InvestigationPriority.HIGH)

        # Priority 8: New high-risk destination (first contact with high threat)
        if data.get("first_contact") and threat >= 0.6:
            return (InvestigationReason.NEW_HIGH_RISK, InvestigationPriority.MEDIUM)

        return (None, None)

    def _generate_description(self, data: Dict, reason: InvestigationReason) -> str:
        """Generate human-readable description for investigation item"""
        dst_ip = data.get("dst_ip", "Unknown")
        domain = data.get("dns_query") or data.get("tls_sni") or ""
        threat = data.get("threat_score", 0)

        descriptions = {
            InvestigationReason.HIGH_UNCERTAINTY: (
                f"Scorers significantly disagreed on {dst_ip}. "
                f"Review individual scorer outputs to understand discrepancy."
            ),
            InvestigationReason.LOCAL_IOC_MATCH: (
                f"Connection matches local IOC database entry. "
                f"Source: {data.get('local_ioc_source', 'unknown')}, "
                f"Type: {data.get('local_ioc_type', 'unknown')}"
            ),
            InvestigationReason.DGA_DETECTED: (
                f"Domain '{domain}' appears algorithmically generated. "
                f"Common indicator of malware C2 communication."
            ),
            InvestigationReason.DOMAIN_ASN_MISMATCH: (
                f"Domain '{domain}' doesn't match ASN owner. "
                f"May indicate CDN usage, MITM, or domain fronting."
            ),
            InvestigationReason.TOR_PROXY: (
                f"Connection to Tor/Proxy service with threat score {threat:.2f}. "
                f"Review for potential data exfiltration or C2."
            ),
            InvestigationReason.UNUSUAL_PORT: (
                f"Connection to ephemeral port {data.get('dst_port')} with elevated threat. "
                f"May indicate custom tunneling or C2 callback."
            ),
            InvestigationReason.BEACONING: (
                f"Regular beaconing pattern detected to {dst_ip}. "
                f"Interval and jitter consistent with C2 communication."
            ),
            InvestigationReason.NEW_HIGH_RISK: (
                f"First contact with high-risk destination {dst_ip}. "
                f"Threat score: {threat:.2f}"
            ),
        }

        return descriptions.get(reason, f"Flagged for review: {dst_ip}")

    def _extract_metadata(self, data: Dict) -> Dict:
        """Extract relevant metadata for investigation context"""
        return {
            k: v for k, v in data.items()
            if k in (
                "greynoise_riot", "greynoise_benign_scanner", "greynoise_malicious",
                "otx_pulse_count", "otx_tags",
                "tcp_state", "tcp_is_scan",
                "hop_count", "os_fingerprint",
                "verification_status", "verification_reason",
            ) and v
        }

    def render(self):
        """Render the investigation queue panel"""
        items = self.queue.get_items(status="pending", limit=10)
        stats = self.queue.get_stats()

        lines = []

        # Header with stats
        critical_count = stats.get("critical", 0)
        pending_count = stats.get("pending", 0)

        if critical_count > 0:
            lines.append(f"[bold red]! {critical_count} CRITICAL[/bold red] | "
                        f"[yellow]{pending_count} pending[/yellow]")
        elif pending_count > 0:
            lines.append(f"[yellow]{pending_count} items pending review[/yellow]")
        else:
            lines.append("[green]No items requiring investigation[/green]")
        lines.append("")

        if not items:
            lines.append("[dim]Queue is empty - monitoring for anomalies...[/dim]")
        else:
            # Show each investigation item
            for i, item in enumerate(items[:7]):  # Show max 7 items
                reason_text, icon, subtitle = item.get_reason_display()
                priority_color = item.get_priority_color()
                age = item.get_age_display()

                # Item header
                lines.append(f"[{priority_color}][{icon}] {reason_text}[/{priority_color}]")

                # Target info
                target = item.domain or item.dst_ip
                if item.dst_port and item.dst_port not in (80, 443):
                    target += f":{item.dst_port}"
                lines.append(f"    [cyan]{target}[/cyan]")

                # Scorer breakdown for uncertainty items
                if item.reason == InvestigationReason.HIGH_UNCERTAINTY:
                    scores = []
                    if item.score_rule_based is not None:
                        scores.append(f"Rule:{item.score_rule_based:.2f}")
                    if item.score_ml_based is not None:
                        scores.append(f"ML:{item.score_ml_based:.2f}")
                    if item.score_organization is not None:
                        scores.append(f"Org:{item.score_organization:.2f}")
                    if scores:
                        lines.append(f"    [dim]{', '.join(scores)}[/dim]")

                # Reason subtitle and age
                lines.append(f"    [dim]{subtitle} | {age}[/dim]")
                lines.append("")

        # Footer with hints
        lines.append("[dim]Press [I] on connection to investigate[/dim]")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]Investigation Queue[/bold cyan]",
            border_style="cyan",
            height=25,
        )

    def watch_queue_version(self, new_version: int):
        """React to queue updates"""
        self.refresh()


# Global investigation queue instance
_investigation_queue: Optional[InvestigationQueue] = None


def get_investigation_queue() -> InvestigationQueue:
    """Get or create the global investigation queue"""
    global _investigation_queue
    if _investigation_queue is None:
        _investigation_queue = InvestigationQueue()
    return _investigation_queue
