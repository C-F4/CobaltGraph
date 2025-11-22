#!/usr/bin/env python3
"""
CobaltGraph Minimal - Geographic Intelligence Watchfloor
Ultimate minimal system - Dashboard-first architecture

Philosophy:
- Geographic intelligence ONLY
- Live data pipeline to dashboard
- Zero deprecated code
- Maximum integration
"""

import os
import sys
import json
import time
import signal
import sqlite3
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread, Lock
from datetime import datetime
from collections import deque
from queue import Queue, Empty
from typing import Dict, List, Optional, Tuple

# Minimal imports - only essentials
try:
    import requests
    GEOIP_AVAILABLE = True
except:
    GEOIP_AVAILABLE = False

# Import configuration and IP reputation (Phase 3: Updated to use src/ modules)
try:
    from src.core.config import load_config
    from src.intelligence.ip_reputation import IPReputationManager
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    # Note: logger not yet initialized at this point

# Import modular components (Phase 2 refactor)
try:
    from src.storage.database import Database
    from src.dashboard.server import DashboardHandler
    from src.utils.heartbeat import Heartbeat
    MODULAR_IMPORTS_AVAILABLE = True

    # Backward compatibility aliases
    MinimalDatabase = Database
    MinimalDashboardHandler = DashboardHandler
    # Heartbeat is already named correctly

except ImportError as e:
    MODULAR_IMPORTS_AVAILABLE = False
    print(f"⚠️  Modular imports not available: {e}")
    print("⚠️  Falling back to inline class definitions")

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s :: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("CobaltGraph")


# =============================================================================
# LEGACY INLINE CLASS DEFINITIONS (Phase 2: DEPRECATED - moved to modules)
# These classes have been extracted to modular structure:
# - MinimalDatabase → src/storage/database.py (Database)
# - MinimalDashboardHandler → src/dashboard/server.py (DashboardHandler)
# - Heartbeat → src/utils/heartbeat.py (Heartbeat)
#
# Backward compatibility aliases are defined in the import section above.
# The inline definitions below are commented out but kept for reference.
# =============================================================================

# DEPRECATED: Moved to src/storage/database.py
# MinimalDatabase class removed - now in src/storage/database.py



class GeoIntelligence:
    """Minimal geographic intelligence - live data focused"""

    def __init__(self, ip_reputation_manager=None):
        self.cache = {}  # IP -> geo data
        self.threat_zones = []  # Active threat zones
        self.countries = set()
        self.dns_cache = {}  # IP -> DNS/org data
        self.ip_reputation = ip_reputation_manager  # External threat intel

    def reverse_dns_lookup(self, ip: str) -> Dict:
        """Reverse DNS and organization lookup"""
        if ip in self.dns_cache:
            return self.dns_cache[ip]

        import socket
        dns_data = {
            'hostname': None,
            'organization': None
        }

        try:
            # Reverse DNS lookup
            hostname = socket.gethostbyaddr(ip)[0]
            dns_data['hostname'] = hostname

            # Extract organization from hostname
            # Common patterns: *.google.com, *.github.com, *.cloudflare.com
            if hostname:
                parts = hostname.split('.')
                if len(parts) >= 2:
                    domain = parts[-2]
                    org_map = {
                        'google': 'Google LLC',
                        'googleapis': 'Google LLC',
                        'cloudflare': 'Cloudflare Inc',
                        'github': 'GitHub Inc',
                        'amazon': 'Amazon.com Inc',
                        'amazonaws': 'Amazon Web Services',
                        'microsoft': 'Microsoft Corporation',
                        'azure': 'Microsoft Azure',
                        'akamai': 'Akamai Technologies',
                        'fastly': 'Fastly Inc'
                    }
                    dns_data['organization'] = org_map.get(domain, domain.capitalize())

        except (socket.herror, socket.gaierror, socket.timeout):
            pass  # No reverse DNS

        self.dns_cache[ip] = dns_data
        return dns_data

    def geolocate(self, ip: str) -> Dict:
        """
        Get geographic data + organization for IP

        Multi-service geolocation with fallback:
        1. ip-api.com - Free, 45 req/min, no key
        2. ipapi.co - Free, 1000 req/day, no key
        3. DNS/org fallback
        """
        if ip in self.cache:
            return self.cache[ip]

        # Get DNS/org info
        dns_info = self.reverse_dns_lookup(ip)

        # Try multiple geolocation services
        if GEOIP_AVAILABLE:
            # Service 1: ip-api.com (primary)
            for attempt in range(2):  # Retry once
                try:
                    response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
                    if response.status_code == 200:
                        data = response.json()

                        if data.get('status') == 'success':
                            geo = {
                                'country': data.get('country', 'Unknown'),
                                'country_code': data.get('countryCode', '??'),
                                'lat': data.get('lat', 0),
                                'lon': data.get('lon', 0),
                                'city': data.get('city', ''),
                                'isp': data.get('isp', dns_info.get('organization')),
                                'org': data.get('org', dns_info.get('organization')),
                                'hostname': dns_info.get('hostname'),
                                'geo_failed': False
                            }
                            self.cache[ip] = geo
                            if geo['country_code'] != '??':
                                self.countries.add(geo['country_code'])
                            return geo
                        else:
                            logger.debug(f"ip-api failed: {data.get('message', 'unknown')}")

                    elif response.status_code == 429:
                        logger.debug(f"ip-api rate limited (attempt {attempt + 1}/2)")
                        if attempt == 0:
                            time.sleep(1)
                            continue
                        else:
                            break  # Try next service

                except requests.Timeout:
                    logger.debug(f"ip-api timeout (attempt {attempt + 1}/2)")
                    if attempt == 0:
                        time.sleep(0.5)
                        continue
                except Exception as e:
                    logger.debug(f"ip-api error: {e}")
                    break

            # Service 2: ipapi.co (fallback)
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
                if response.status_code == 200:
                    data = response.json()

                    if 'error' not in data:
                        geo = {
                            'country': data.get('country_name', 'Unknown'),
                            'country_code': data.get('country_code', '??'),
                            'lat': data.get('latitude', 0),
                            'lon': data.get('longitude', 0),
                            'city': data.get('city', ''),
                            'isp': data.get('org', dns_info.get('organization')),
                            'org': data.get('org', dns_info.get('organization')),
                            'hostname': dns_info.get('hostname'),
                            'geo_failed': False
                        }
                        self.cache[ip] = geo
                        if geo['country_code'] != '??':
                            self.countries.add(geo['country_code'])
                        logger.info(f"✓ ipapi.co success for {ip}")
                        return geo
                    else:
                        logger.debug(f"ipapi.co error: {data.get('reason', 'unknown')}")

            except Exception as e:
                logger.debug(f"ipapi.co failed: {e}")

        # Fallback - mark as geo_failed so we can show it differently
        logger.warning(f"⚠️  All geolocation services failed for {ip}")
        fallback = {
            'country': 'Unknown',
            'country_code': '??',
            'lat': 0,
            'lon': 0,
            'city': '',
            'isp': dns_info.get('organization'),
            'org': dns_info.get('organization'),
            'hostname': dns_info.get('hostname'),
            'geo_failed': True
        }
        self.cache[ip] = fallback
        return fallback

    def analyze_threat(self, connection: Dict) -> Tuple[float, Dict]:
        """
        Calculate threat score (0-1) with IP reputation integration

        Returns:
            Tuple of (threat_score, reputation_details)
        """
        score = 0.0
        reputation_details = {}

        # Check IP reputation if available
        if self.ip_reputation:
            dst_ip = connection.get('dst_ip')
            if dst_ip:
                try:
                    rep_score, rep_details = self.ip_reputation.check_ip(dst_ip)
                    # Use reputation score as base (weighted higher)
                    score = rep_score * 0.7  # 70% weight on external reputation
                    reputation_details = rep_details
                except Exception as e:
                    logger.debug(f"IP reputation lookup failed for {dst_ip}: {e}")

        # Add local threat indicators (30% weight if reputation available, 100% otherwise)
        local_score = 0.0

        # High-risk ports
        risky_ports = {22, 23, 3389, 445, 139}
        if connection.get('dst_port') in risky_ports:
            local_score += 0.3

        # Unknown countries
        if connection.get('dst_country') == 'Unknown':
            local_score += 0.2

        # Combine scores
        if self.ip_reputation:
            score = (score) + (local_score * 0.3)  # 70% external, 30% local
        else:
            score = local_score  # 100% local if no reputation available

        return min(score, 1.0), reputation_details

    def update_threat_zones(self, connections: List[Dict]):
        """Calculate threat zones from connections"""
        # Group by location
        location_threats = {}

        for conn in connections:
            lat = conn.get('dst_lat', 0)
            lon = conn.get('dst_lon', 0)
            # Skip invalid coordinates (0,0 = no geolocation)
            if lat != 0 and lon != 0:
                key = (round(lat, 1), round(lon, 1))
                if key not in location_threats:
                    location_threats[key] = []
                location_threats[key].append(conn['threat_score'])

        # Create threat zones (1+ connections creates a zone)
        self.threat_zones = [
            {
                'lat': lat,
                'lon': lon,
                'threat_score': sum(scores) / len(scores),
                'radius_km': 50,
                'connection_count': len(scores)
            }
            for (lat, lon), scores in location_threats.items()
        ]

        # Sort by threat score
        self.threat_zones.sort(key=lambda x: x['threat_score'], reverse=True)


# DEPRECATED: Moved to src/dashboard/server.py
# MinimalDashboardHandler class removed - now in src/dashboard/server.py

# End of MinimalDashboardHandler class (now in src/dashboard/server.py)


# DEPRECATED: Moved to src/utils/heartbeat.py
# Heartbeat class removed - now in src/utils/heartbeat.py

# End of Heartbeat class (now in src/utils/heartbeat.py)


class ConnectionMonitor:
    """
    Passive connection monitoring with async geolocation

    Architecture:
    1. stdin thread → ingest_connection() → queue (non-blocking, <1ms)
    2. worker pool (4 threads) → dequeue → geolocate (blocking 5-10s, parallel)
    3. workers → finalize → DB + buffer

    This keeps stdin unblocked while allowing parallel geo lookups.
    """

    def __init__(self, db: MinimalDatabase, geo: GeoIntelligence, worker_count: int = 4):
        self.db = db
        self.geo = geo
        self.active = False
        self.connection_buffer = deque(maxlen=100)
        self.buffer_lock = Lock()  # Thread-safe buffer access

        # Worker queue for async geolocation
        self.geo_queue = Queue()
        self.worker_count = worker_count
        self.workers = []

        # Start worker threads
        self._start_workers()
        logger.info(f"🔧 Geo worker pool started: {worker_count} threads")

    def _start_workers(self):
        """Start background worker threads for geolocation"""
        for i in range(self.worker_count):
            worker = Thread(target=self._geo_worker, daemon=True, name=f"GeoWorker-{i+1}")
            worker.start()
            self.workers.append(worker)

    def _geo_worker(self):
        """Background worker: processes geolocation tasks from queue"""
        while True:
            try:
                task = self.geo_queue.get(timeout=1.0)

                # Perform blocking geolocation (this happens in parallel across workers)
                geo_data = self.geo.geolocate(task['dst_ip'])

                # Finalize connection with geo data
                self._finalize_connection(task, geo_data)

                self.geo_queue.task_done()

            except Empty:
                continue  # No tasks, keep waiting
            except Exception as e:
                logger.error(f"Geo worker error: {e}")
                self.geo_queue.task_done()

    def _finalize_connection(self, task: Dict, geo_data: Dict):
        """Finalize connection after geolocation (runs in worker thread)"""
        # Build connection with metadata + organization
        connection = {
            'timestamp': task['timestamp'],
            'src_ip': task['src_ip'],
            'dst_ip': task['dst_ip'],
            'dst_port': task['dst_port'],
            'dst_country': geo_data['country_code'],
            'dst_lat': geo_data['lat'],
            'dst_lon': geo_data['lon'],
            'dst_org': geo_data.get('org'),
            'dst_hostname': geo_data.get('hostname'),
            'protocol': task.get('protocol', 'TCP'),
            'geo_failed': geo_data.get('geo_failed', False)
        }

        # Threat analysis (now returns tuple with reputation details)
        threat_score, reputation_details = self.geo.analyze_threat(connection)
        connection['threat_score'] = threat_score
        connection['reputation'] = reputation_details  # Store reputation metadata

        # Store in database
        self.db.add_connection(connection)

        # Add to buffer (thread-safe)
        with self.buffer_lock:
            self.connection_buffer.append(connection)

        # Clean logging with organization
        org_info = f" ({connection['dst_org']})" if connection.get('dst_org') else ""
        logger.info(f"📍 {task['dst_ip']}:{task['dst_port']} [{geo_data['country_code']}]{org_info} Threat: {connection['threat_score']:.2f}")

    def ingest_connection(self, src_ip: str, dst_ip: str, dst_port: int, metadata: Dict = None, heartbeat=None):
        """
        Non-blocking connection ingestion
        Queues connection for background geolocation
        SIGINT(METADATA) pattern - metadata contains all context
        """
        # Update heartbeat if provided
        if heartbeat:
            heartbeat.beat('connection_monitor')

        # Queue task for background processing (non-blocking, <1ms)
        task = {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': metadata.get('protocol', 'TCP') if metadata else 'TCP',
            'metadata': metadata
        }

        self.geo_queue.put(task)
        logger.debug(f"⚡ Queued: {dst_ip}:{dst_port} (queue size: {self.geo_queue.qsize()})")

    def prune_dead_signals(self, time_window=60):
        """
        Remove dead/stale connections from buffer
        Runs concurrently with dashboard cycle

        Args:
            time_window: Time window in seconds (default 60s)
        """
        now = time.time()
        cutoff = now - time_window

        with self.buffer_lock:
            # Convert to list for filtering
            buffer_list = list(self.connection_buffer)
            live_connections = [conn for conn in buffer_list if conn.get('timestamp', 0) >= cutoff]

            # Clear and rebuild buffer with only live connections
            self.connection_buffer.clear()
            self.connection_buffer.extend(live_connections)

            dropped = len(buffer_list) - len(live_connections)
            if dropped > 0:
                logger.debug(f"🗑️  Dropped {dropped} dead signals (older than {time_window}s)")

    def get_recent(self, limit=50, time_window=60, heartbeat=None) -> List[Dict]:
        """
        Get recent connections from buffer (last 60 seconds only)
        Drops connections if component is DEAD

        Args:
            limit: Max connections to return
            time_window: Time window in seconds (default 60s for 1 minute)
            heartbeat: Heartbeat instance to check component health

        Returns:
            List of live connections within time window
        """
        now = time.time()
        cutoff = now - time_window

        # Check if connection monitor is DEAD
        if heartbeat:
            status = heartbeat.get_status()
            if status.get('connection_monitor', {}).get('status') == 'DEAD':
                logger.debug("Connection monitor DEAD - dropping all connections")
                return []

        # Thread-safe buffer access
        with self.buffer_lock:
            buffer_data = list(self.connection_buffer)

        if not buffer_data:
            logger.debug("Buffer empty, no recent connections")
            return []

        # Filter to only connections within time window (last 60 seconds)
        recent = [conn for conn in buffer_data if conn.get('timestamp', 0) >= cutoff]

        # Calculate age of most recent connection
        if recent:
            latest_timestamp = recent[-1].get('timestamp', 0)
            age = now - latest_timestamp
            logger.debug(f"Returning {len(recent)} live connections from last {time_window}s (age: {age:.1f}s)")
        else:
            # No connections in time window, but buffer has old data
            if buffer_data:
                latest_timestamp = buffer_data[-1].get('timestamp', 0)
                age = now - latest_timestamp
                logger.debug(f"No live connections in last {time_window}s (last seen {age:.0f}s ago)")

        return recent[-limit:]  # Return most recent, up to limit

    def get_buffer_age(self) -> Optional[float]:
        """Get age of most recent connection in buffer"""
        with self.buffer_lock:
            if self.connection_buffer:
                latest = self.connection_buffer[-1].get('timestamp', 0)
                return time.time() - latest
        return None


class SUARONMinimal:
    """
    Minimal CobaltGraph Watchfloor
    HEARTBEAT < CONNECTION < GEOINT < SIGINT(METADATA)
    """

    def __init__(self):
        logger.info("🌍 CobaltGraph Minimal - Initializing...")

        self.start_time = time.time()
        self.running = False

        # Load configuration
        if CONFIG_AVAILABLE:
            try:
                self.config = load_config(verbose=False)
                logger.info("✅ Configuration loaded")

                # Initialize IP reputation manager
                self.ip_reputation = IPReputationManager(self.config)
                logger.info("✅ IP reputation manager initialized")
            except Exception as e:
                logger.warning(f"⚠️  Config/reputation init failed: {e}")
                self.config = {}
                self.ip_reputation = None
        else:
            self.config = {}
            self.ip_reputation = None

        # Signal stack (bottom to top)
        self.db = MinimalDatabase()              # Foundation
        self.geo = GeoIntelligence(ip_reputation_manager=self.ip_reputation)  # GEOINT (with reputation)
        self.connection_monitor = ConnectionMonitor(self.db, self.geo)  # CONNECTION
        self.heartbeat = Heartbeat()             # HEARTBEAT (top)

        # Activate connection monitor
        self.connection_monitor.active = True

        # Dashboard server
        self.dashboard_server = None
        self.dashboard_thread = None

        # Initial heartbeats
        self.heartbeat.beat('database')
        self.heartbeat.beat('geo_engine')

        logger.info("✅ System initialized")

    def start_dashboard(self, port=8080):
        """Start dashboard server"""
        self.dashboard_server = HTTPServer(('localhost', port), MinimalDashboardHandler)
        self.dashboard_server.watchfloor = self  # Pass reference

        def run():
            logger.info(f"🌐 Dashboard: http://localhost:{port}")
            self.dashboard_server.serve_forever()

        self.dashboard_thread = Thread(target=run, daemon=True)
        self.dashboard_thread.start()

    def generate_demo_data(self):
        """Generate demo connections for testing"""
        demo_ips = [
            ('8.8.8.8', 443),      # Google DNS
            ('1.1.1.1', 443),      # Cloudflare
            ('192.0.2.1', 22),     # Example (risky port)
            ('198.18.0.1', 3389),  # Example (RDP - risky)
        ]

        for dst_ip, dst_port in demo_ips:
            self.connection_monitor.ingest_connection('192.168.1.100', dst_ip, dst_port, heartbeat=self.heartbeat)

        logger.info(f"✅ Generated {len(demo_ips)} demo connections")

    def run(self):
        """Main run loop"""
        self.running = True

        # Start dashboard
        self.start_dashboard()

        # Demo data disabled - waiting for real-time connections
        # if self.db.get_connection_count() == 0:
        #     logger.info("Generating demo data...")
        #     self.generate_demo_data()

        logger.info("👁️  CobaltGraph Minimal Active - Dashboard-First Architecture")
        logger.info("Press Ctrl+C to stop")

        # Main loop - update threat zones and prune dead signals concurrently
        try:
            update_counter = 0
            while self.running:
                time.sleep(5)  # Check every 5s
                update_counter += 1

                # Concurrent operations running with dashboard cycle
                # 1. Prune dead signals from buffer (every cycle)
                self.connection_monitor.prune_dead_signals(time_window=60)

                # 2. Update threat zones every 10s (every 2 iterations)
                if update_counter % 2 == 0:
                    connections = self.db.get_recent_connections()
                    self.geo.update_threat_zones(connections)
                    self.heartbeat.beat('geo_engine')
                    logger.debug(f"Updated threat zones: {len(self.geo.threat_zones)} zones")

                # 3. Heartbeat pulse
                self.heartbeat.beat('database')

        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self):
        """Graceful shutdown"""
        if not self.running:
            return  # Already shut down

        logger.info("🛑 Shutting down...")
        self.running = False

        if self.dashboard_server:
            try:
                self.dashboard_server.shutdown()
            except:
                pass  # Already stopped

        try:
            self.db.conn.close()
        except:
            pass  # Already closed

        logger.info("✅ Shutdown complete")


def main():
    # Signal handlers
    watchfloor = SUARONMinimal()

    def signal_handler(sig, frame):
        print()
        watchfloor.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Check for piped input - spawn thread to read stdin while dashboard runs
    if not sys.stdin.isatty():
        def read_stdin():
            logger.info("📥 Stdin thread started - listening for connections")
            line_count = 0
            last_data_time = time.time()

            try:
                for line in sys.stdin:
                    try:
                        packet_info = json.loads(line)
                        if packet_info.get('type') == 'connection':
                            watchfloor.connection_monitor.ingest_connection(
                                packet_info['src_ip'],
                                packet_info['dst_ip'],
                                packet_info['dst_port'],
                                metadata=packet_info.get('metadata'),
                                heartbeat=watchfloor.heartbeat
                            )
                            line_count += 1
                            last_data_time = time.time()
                        elif packet_info.get('type') == 'heartbeat':
                            # Keep pipe alive
                            last_data_time = time.time()
                            logger.debug(f"💓 Heartbeat: {packet_info.get('active_endpoints', 0)} endpoints")
                    except json.JSONDecodeError as e:
                        logger.debug(f"Non-JSON line: {line[:50]}")
                    except Exception as e:
                        logger.error(f"Stdin error: {e}")

            except Exception as e:
                logger.error(f"Stdin thread crashed: {e}")

            # Stdin closed - capture process died
            logger.error(f"🔴 STDIN CLOSED - Capture process died after {line_count} connections")
            logger.error(f"⚠️  Last data received {time.time() - last_data_time:.0f}s ago")
            logger.error(f"⚠️  Triggering system restart via supervisor...")

            # Mark connection monitor as dead
            watchfloor.connection_monitor.active = False
            watchfloor.heartbeat.components['connection_monitor']['health'] = 0

            # Shutdown the watchfloor to trigger supervisor restart
            watchfloor.shutdown()
            sys.exit(1)

        stdin_thread = Thread(target=read_stdin, daemon=True)
        stdin_thread.start()
    else:
        logger.warning("⚠️  No piped input detected - connection monitor will remain offline")
        logger.info("💡 Tip: Run with: python3 network_capture.py | python3 cobaltgraph_minimal.py")

    # Run
    try:
        watchfloor.run()
    finally:
        watchfloor.shutdown()


if __name__ == "__main__":
    main()
