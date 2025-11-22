"""
CobaltGraph Heartbeat and Health Monitoring
Component health tracking and status reporting

Extracted from watchfloor.py Heartbeat class

Monitors:
- Component liveness (last heartbeat time)
- Health scores (0-100 based on heartbeat age)
- Component status (ACTIVE, DEGRADED, DEAD)
- System-wide health (0.0-1.0 overall score)
"""

import time
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class Heartbeat:
    """
    Component health monitoring via heartbeat signals

    Each component calls beat() periodically to indicate it's alive.
    Health degrades over time if no heartbeat is received.

    States:
    - ACTIVE (health=100): Recent heartbeat (within timeout/2)
    - DEGRADED (health=50): Approaching timeout (timeout/2 to timeout)
    - DEAD (health=0): No heartbeat for timeout period
    """

    def __init__(self, timeout: int = 30):
        """
        Initialize heartbeat monitor

        Args:
            timeout: Seconds before component is considered DEAD
        """
        self.timeout = timeout  # Seconds before component is considered DEAD
        self.components = {
            'database': {'health': 100, 'last_beat': time.time()},
            'geo_engine': {'health': 100, 'last_beat': time.time()},
            'dashboard': {'health': 100, 'last_beat': time.time()},
            'connection_monitor': {'health': 0, 'last_beat': 0},  # Starts offline
            'orchestrator': {'health': 100, 'last_beat': time.time()},
            'capture': {'health': 0, 'last_beat': 0},  # Starts offline
            'processor': {'health': 0, 'last_beat': 0}  # Starts offline
        }

        logger.info(f"💓 Heartbeat monitor initialized (timeout: {timeout}s)")

    def beat(self, component: str):
        """
        Record heartbeat from component

        Updates last_beat timestamp and resets health to 100.
        Automatically registers new components if not present.

        Args:
            component: Component name (e.g., 'database', 'dashboard')
        """
        if component not in self.components:
            # Auto-register new component
            self.components[component] = {'health': 100, 'last_beat': time.time()}
            logger.debug(f"💓 Registered new component: {component}")
        else:
            self.components[component]['last_beat'] = time.time()
            self.components[component]['health'] = 100
            logger.debug(f"💓 Heartbeat: {component}")

    def _update_health(self):
        """
        Update health scores based on last heartbeat time

        Called internally before checking health or status.

        Health calculation:
        - age <= timeout/2: health = 100 (ACTIVE)
        - timeout/2 < age <= timeout: health = 50 (DEGRADED)
        - age > timeout: health = 0 (DEAD)
        """
        now = time.time()

        for name, data in self.components.items():
            age = now - data['last_beat']

            if age > self.timeout:
                # Component is DEAD (no heartbeat for timeout period)
                data['health'] = 0
            elif age > self.timeout / 2:
                # Component is DEGRADED (approaching timeout)
                data['health'] = 50
            # Otherwise health stays at 100 (set by beat())

    def check_health(self) -> float:
        """
        Calculate overall system health score

        Returns:
            Float 0.0-1.0 representing overall system health
            (average of all component health scores)
        """
        self._update_health()
        healths = [c['health'] for c in self.components.values()]
        return sum(healths) / (len(healths) * 100)

    def get_status(self) -> Dict:
        """
        Get detailed component status for dashboard

        Returns:
            Dict mapping component name to status info:
            {
                'component_name': {
                    'status': 'ACTIVE'|'DEGRADED'|'DEAD',
                    'health_percentage': 0-100,
                    'last_beat_age': seconds since last beat
                }
            }
        """
        self._update_health()
        now = time.time()

        return {
            name: {
                'status': (
                    'DEAD' if data['health'] == 0 else
                    ('DEGRADED' if data['health'] < 100 else 'ACTIVE')
                ),
                'health_percentage': data['health'],
                'last_beat_age': int(now - data['last_beat'])
            }
            for name, data in self.components.items()
        }

    def is_component_alive(self, component: str) -> bool:
        """
        Check if specific component is alive (not DEAD)

        Args:
            component: Component name

        Returns:
            True if component health > 0, False otherwise
        """
        self._update_health()
        return self.components.get(component, {}).get('health', 0) > 0

    def register_component(self, component: str, initial_state: str = 'offline'):
        """
        Register a new component for monitoring

        Args:
            component: Component name
            initial_state: 'online' (health=100) or 'offline' (health=0)
        """
        if initial_state == 'online':
            self.components[component] = {
                'health': 100,
                'last_beat': time.time()
            }
        else:
            self.components[component] = {
                'health': 0,
                'last_beat': 0
            }

        logger.info(f"📋 Registered component: {component} ({initial_state})")

    def print_status(self):
        """Print human-readable status (for debugging)"""
        status = self.get_status()
        print("\n" + "=" * 50)
        print("SYSTEM HEALTH STATUS")
        print("=" * 50)

        for component, info in status.items():
            symbol = {
                'ACTIVE': '✅',
                'DEGRADED': '⚠️ ',
                'DEAD': '❌'
            }.get(info['status'], '❓')

            print(f"{symbol} {component:20s} | {info['status']:8s} | "
                  f"Health: {info['health_percentage']:3d}% | "
                  f"Age: {info['last_beat_age']:3d}s")

        overall = self.check_health()
        print("=" * 50)
        print(f"Overall System Health: {overall * 100:.1f}%")
        print("=" * 50)
