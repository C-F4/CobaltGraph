"""
CobaltGraph Heartbeat and Health Monitoring
Centralized component health tracking and status reporting

This module provides a singleton HeartbeatMonitor that all CobaltGraph components
use to report their health status. The dashboard reads from this monitor to display
real-time system status gumballs.

Components:
- database: SQLite database connection
- capture: Network packet capture (device_monitor or network_monitor)
- pipeline: Data processing pipeline (orchestrator)
- consensus: BFT threat scoring engine
- geo_engine: Geolocation service (ip-api.com)
- asn_lookup: ASN/Organization lookup (Team Cymru)
- reputation: IP reputation services (VirusTotal/AbuseIPDB)
- dashboard: Terminal UI interface

Usage:
    from src.utils.heartbeat import heartbeat

    # Component reports it's alive
    heartbeat.beat("database")

    # Check if component is alive
    if heartbeat.is_alive("capture"):
        ...

    # Get full status for dashboard
    status = heartbeat.get_status()
"""

import logging
import time
import threading
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ComponentStatus(Enum):
    """Component health status levels"""
    ACTIVE = "ACTIVE"      # Recently heartbeat, fully operational
    DEGRADED = "DEGRADED"  # Heartbeat aging, may have issues
    DEAD = "DEAD"          # No heartbeat, offline/failed
    UNKNOWN = "UNKNOWN"    # Not yet checked


@dataclass
class ComponentInfo:
    """Information about a monitored component"""
    name: str
    display_name: str
    description: str
    critical: bool = True  # If True, system degrades without it
    requires_root: bool = False


# Define all CobaltGraph components
COBALTGRAPH_COMPONENTS: List[ComponentInfo] = [
    ComponentInfo("database", "Database", "SQLite WAL database", critical=True),
    ComponentInfo("capture", "Capture", "Network packet capture", critical=False, requires_root=True),
    ComponentInfo("pipeline", "Pipeline", "Data processing pipeline", critical=True),
    ComponentInfo("consensus", "Consensus", "BFT threat scoring", critical=False),
    ComponentInfo("geo_engine", "GeoIP", "Geolocation service", critical=False),
    ComponentInfo("asn_lookup", "ASN", "ASN/Org lookup", critical=False),
    ComponentInfo("reputation", "Reputation", "IP reputation APIs", critical=False),
    ComponentInfo("dashboard", "Dashboard", "Terminal UI", critical=True),
]


class HeartbeatMonitor:
    """
    Centralized component health monitoring via heartbeat signals.

    This is a singleton - use the global `heartbeat` instance.

    Each component calls beat() periodically to indicate it's alive.
    Health degrades over time if no heartbeat is received.

    States:
    - ACTIVE (health=100): Recent heartbeat (within timeout/2)
    - DEGRADED (health=50): Approaching timeout (timeout/2 to timeout)
    - DEAD (health=0): No heartbeat for timeout period
    """

    _instance: Optional['HeartbeatMonitor'] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern - only one heartbeat monitor per process"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, timeout: int = 30):
        """
        Initialize heartbeat monitor (only runs once due to singleton)

        Args:
            timeout: Seconds before component is considered DEAD
        """
        if self._initialized:
            return

        self.timeout = timeout
        self._components_lock = threading.Lock()

        # Initialize all known components as DEAD/offline
        self.components: Dict[str, dict] = {}
        self.component_info: Dict[str, ComponentInfo] = {}

        for comp in COBALTGRAPH_COMPONENTS:
            self.components[comp.name] = {
                "health": 0,
                "last_beat": 0,
                "message": "Not started",
                "check_passed": False,
            }
            self.component_info[comp.name] = comp

        self._initialized = True
        logger.info("💓 HeartbeatMonitor initialized (timeout: %ds, components: %d)",
                   timeout, len(self.components))

    def beat(self, component: str, message: str = "OK"):
        """
        Record heartbeat from component - marks it as ACTIVE

        Args:
            component: Component name (e.g., 'database', 'pipeline')
            message: Optional status message
        """
        with self._components_lock:
            if component not in self.components:
                # Auto-register unknown component
                self.components[component] = {
                    "health": 100,
                    "last_beat": time.time(),
                    "message": message,
                    "check_passed": True,
                }
                self.component_info[component] = ComponentInfo(
                    component, component.title(), f"Auto-registered: {component}", critical=False
                )
                logger.debug("💓 Auto-registered component: %s", component)
            else:
                self.components[component]["last_beat"] = time.time()
                self.components[component]["health"] = 100
                self.components[component]["message"] = message
                self.components[component]["check_passed"] = True

            logger.debug("💓 Heartbeat: %s - %s", component, message)

    def set_component_status(self, component: str, passed: bool, message: str = ""):
        """
        Set component status from system check results

        Args:
            component: Component name
            passed: Whether the system check passed
            message: Status message from the check
        """
        with self._components_lock:
            if component not in self.components:
                return

            self.components[component]["check_passed"] = passed
            self.components[component]["message"] = message

            if passed:
                # Mark as alive if check passed
                self.components[component]["health"] = 100
                self.components[component]["last_beat"] = time.time()
            else:
                # Mark as dead if check failed
                self.components[component]["health"] = 0
                self.components[component]["last_beat"] = 0

    def mark_online(self, component: str, message: str = "Online"):
        """Convenience method to mark a component as online"""
        self.beat(component, message)

    def mark_offline(self, component: str, message: str = "Offline"):
        """Convenience method to mark a component as offline"""
        with self._components_lock:
            if component in self.components:
                self.components[component]["health"] = 0
                self.components[component]["last_beat"] = 0
                self.components[component]["message"] = message
                self.components[component]["check_passed"] = False

    def _update_health(self):
        """Update health scores based on heartbeat age"""
        now = time.time()

        with self._components_lock:
            for name, data in self.components.items():
                if data["last_beat"] == 0:
                    # Never received a heartbeat
                    data["health"] = 0
                    continue

                age = now - data["last_beat"]

                if age > self.timeout:
                    data["health"] = 0
                elif age > self.timeout / 2:
                    data["health"] = 50
                # Otherwise health stays at 100 (set by beat())

    def get_status(self) -> Dict[str, dict]:
        """
        Get detailed component status for dashboard display

        Returns:
            Dict mapping component name to status info
        """
        self._update_health()
        now = time.time()

        with self._components_lock:
            return {
                name: {
                    "status": self._health_to_status(data["health"]),
                    "health_percentage": data["health"],
                    "last_beat_age": int(now - data["last_beat"]) if data["last_beat"] > 0 else 999,
                    "message": data.get("message", ""),
                    "check_passed": data.get("check_passed", False),
                    "display_name": self.component_info.get(name, ComponentInfo(name, name, "")).display_name,
                    "critical": self.component_info.get(name, ComponentInfo(name, name, "", False)).critical,
                }
                for name, data in self.components.items()
            }

    def _health_to_status(self, health: int) -> str:
        """Convert health percentage to status string"""
        if health == 0:
            return "DEAD"
        elif health < 100:
            return "DEGRADED"
        return "ACTIVE"

    def is_alive(self, component: str) -> bool:
        """Check if a component is alive (ACTIVE or DEGRADED)"""
        self._update_health()
        with self._components_lock:
            return self.components.get(component, {}).get("health", 0) > 0

    def check_health(self) -> float:
        """
        Calculate overall system health (0.0 to 1.0)

        Only considers critical components in the calculation.
        """
        self._update_health()

        with self._components_lock:
            critical_healths = []
            for name, data in self.components.items():
                info = self.component_info.get(name)
                if info and info.critical:
                    critical_healths.append(data["health"])

            if not critical_healths:
                return 1.0
            return sum(critical_healths) / (len(critical_healths) * 100)

    def get_online_count(self) -> Tuple[int, int]:
        """
        Get count of online components

        Returns:
            Tuple of (online_count, total_count)
        """
        self._update_health()

        with self._components_lock:
            total = len(self.components)
            online = sum(1 for data in self.components.values() if data["health"] > 0)
            return online, total

    def get_summary(self) -> str:
        """Get a one-line summary of system health"""
        online, total = self.get_online_count()
        health = self.check_health()
        return f"{online}/{total} online | {health * 100:.0f}% health"

    def print_status(self):
        """Print human-readable status to console"""
        status = self.get_status()

        print("\n" + "=" * 60)
        print("  COBALTGRAPH SYSTEM HEALTH")
        print("=" * 60)

        for name, info in status.items():
            symbol = {
                "ACTIVE": "🟢",
                "DEGRADED": "🟡",
                "DEAD": "🔴"
            }.get(info["status"], "⚪")

            critical = "[CRITICAL]" if info["critical"] else ""
            age_str = f"{info['last_beat_age']}s ago" if info["last_beat_age"] < 999 else "never"

            print(f"{symbol} {info['display_name']:12s} | {info['status']:8s} | "
                  f"{info['health_percentage']:3d}% | {age_str:10s} {critical}")
            if info["message"]:
                print(f"   └─ {info['message']}")

        online, total = self.get_online_count()
        health = self.check_health()

        print("=" * 60)
        print(f"Overall: {online}/{total} components online | System health: {health * 100:.0f}%")
        print("=" * 60 + "\n")

    def reset(self):
        """Reset all components to offline state (for testing)"""
        with self._components_lock:
            for name in self.components:
                self.components[name] = {
                    "health": 0,
                    "last_beat": 0,
                    "message": "Reset",
                    "check_passed": False,
                }


# Global singleton instance - import this in other modules
heartbeat = HeartbeatMonitor(timeout=30)


# Convenience functions for direct import
def beat(component: str, message: str = "OK"):
    """Record heartbeat from component"""
    heartbeat.beat(component, message)


def is_alive(component: str) -> bool:
    """Check if component is alive"""
    return heartbeat.is_alive(component)


def get_status() -> Dict:
    """Get full status dict"""
    return heartbeat.get_status()


def mark_online(component: str, message: str = "Online"):
    """Mark component as online"""
    heartbeat.mark_online(component, message)


def mark_offline(component: str, message: str = "Offline"):
    """Mark component as offline"""
    heartbeat.mark_offline(component, message)
