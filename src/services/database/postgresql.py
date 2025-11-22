"""
CobaltGraph PostgreSQL Database Service
Phase 0: Device Discovery and Threat Intelligence

Responsibilities:
- PostgreSQL connection management
- Device inventory operations
- Connection tracking
- Event logging
- Thread-safe operations with connection pooling
"""

import psycopg2
from psycopg2 import pool, sql
from psycopg2.extras import RealDictCursor, Json
import logging
import time
import configparser
from threading import Lock
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager

# Import custom exceptions
from src.utils.errors import DatabaseError

logger = logging.getLogger(__name__)


class PostgreSQLDatabase:
    """
    PostgreSQL database service for CobaltGraph

    Features:
    - Connection pooling for performance
    - Thread-safe operations
    - Device inventory management
    - Connection tracking
    - Event audit trail
    - JSONB support for flexible metadata
    """

    def __init__(self, config_path: str = "config/database.conf"):
        """
        Initialize PostgreSQL connection pool

        Args:
            config_path: Path to database configuration file

        Raises:
            DatabaseError: If connection fails
        """
        self.config_path = Path(config_path)
        self.lock = Lock()
        self.pool = None

        # Load configuration
        try:
            self.config = self._load_config()
            logger.debug(f"Loaded database config: {self.config['user']}@{self.config['host']}/{self.config['database']}")
        except Exception as e:
            error_msg = f"Failed to load database configuration: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'config_path': str(config_path)})

        # Create connection pool
        try:
            self.pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=self.config.get('min_connections', 2),
                maxconn=self.config.get('max_connections', 10),
                host=self.config['host'],
                port=self.config['port'],
                database=self.config['database'],
                user=self.config['user'],
                password=self.config['password']
            )
            logger.info(f"📁 PostgreSQL connection pool initialized: {self.config['database']}")
        except psycopg2.Error as e:
            error_msg = f"Failed to create database connection pool: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'config': self.config})

    def _load_config(self) -> Dict:
        """Load database configuration from file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Database config not found: {self.config_path}")

        config = configparser.ConfigParser()
        config.read(self.config_path)

        return {
            'host': config.get('database', 'host'),
            'port': config.getint('database', 'port'),
            'database': config.get('database', 'database'),
            'user': config.get('database', 'user'),
            'password': config.get('database', 'password'),
            'min_connections': config.getint('database', 'min_connections', fallback=2),
            'max_connections': config.getint('database', 'max_connections', fallback=10)
        }

    @contextmanager
    def get_connection(self):
        """
        Get connection from pool (context manager)

        Yields:
            psycopg2 connection with RealDictCursor
        """
        conn = None
        try:
            conn = self.pool.getconn()
            yield conn
        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            if conn:
                self.pool.putconn(conn)

    # ========================================================================
    # DEVICE OPERATIONS (Phase 0)
    # ========================================================================

    def add_device(self, device_data: Dict) -> bool:
        """
        Add or update device in inventory

        Args:
            device_data: Device information
                Required: mac_address
                Optional: ip_address, vendor, device_type, hostname

        Returns:
            True if device was added/updated

        Raises:
            DatabaseError: If operation fails
        """
        if not device_data.get('mac_address'):
            raise DatabaseError("MAC address is required", details={'data': device_data})

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Upsert device (INSERT ... ON CONFLICT UPDATE)
                cursor.execute("""
                    INSERT INTO devices (
                        mac_address, ip_address, vendor, device_type, hostname,
                        first_seen, last_seen, last_activity, status, metadata
                    ) VALUES (
                        %(mac_address)s, %(ip_address)s, %(vendor)s, %(device_type)s, %(hostname)s,
                        NOW(), NOW(), NOW(), 'discovered', %(metadata)s
                    )
                    ON CONFLICT (mac_address) DO UPDATE SET
                        ip_address = EXCLUDED.ip_address,
                        vendor = EXCLUDED.vendor,
                        device_type = EXCLUDED.device_type,
                        hostname = EXCLUDED.hostname,
                        last_seen = NOW(),
                        metadata = EXCLUDED.metadata
                """, {
                    'mac_address': device_data['mac_address'],
                    'ip_address': device_data.get('ip_address'),
                    'vendor': device_data.get('vendor'),
                    'device_type': device_data.get('device_type', 'unknown'),
                    'hostname': device_data.get('hostname'),
                    'metadata': Json(device_data.get('metadata', {}))
                })

                conn.commit()
                logger.debug(f"Device added/updated: {device_data['mac_address']}")
                return True

        except psycopg2.Error as e:
            error_msg = f"Failed to add device: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'mac': device_data.get('mac_address')})

    def get_devices(self, status: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """
        Get devices from inventory

        Args:
            status: Filter by status (discovered, active, idle, offline)
            limit: Maximum number of devices to return

        Returns:
            List of device dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)

                if status:
                    cursor.execute("""
                        SELECT * FROM devices
                        WHERE status = %s
                        ORDER BY last_seen DESC
                        LIMIT %s
                    """, (status, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM devices
                        ORDER BY last_seen DESC
                        LIMIT %s
                    """, (limit,))

                devices = cursor.fetchall()
                logger.debug(f"Retrieved {len(devices)} devices (status={status}, limit={limit})")
                return [dict(row) for row in devices]

        except psycopg2.Error as e:
            error_msg = f"Failed to retrieve devices: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'status': status, 'limit': limit})

    def get_device_by_mac(self, mac_address: str) -> Optional[Dict]:
        """
        Get device by MAC address

        Args:
            mac_address: Device MAC address

        Returns:
            Device dictionary or None if not found
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("SELECT * FROM devices WHERE mac_address = %s", (mac_address,))
                result = cursor.fetchone()
                return dict(result) if result else None

        except psycopg2.Error as e:
            error_msg = f"Failed to get device: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'mac': mac_address})

    def get_device_by_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Get device by IP address

        Args:
            ip_address: Device IP address

        Returns:
            Device dictionary or None if not found
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute(
                    "SELECT * FROM devices WHERE ip_address = %s ORDER BY last_seen DESC LIMIT 1",
                    (ip_address,)
                )
                result = cursor.fetchone()
                return dict(result) if result else None

        except psycopg2.Error as e:
            error_msg = f"Failed to get device by IP: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'ip': ip_address})

    def update_device_status(self, mac_address: str, status: str) -> bool:
        """
        Update device status

        Args:
            mac_address: Device MAC address
            status: New status (discovered, active, idle, offline)

        Returns:
            True if updated successfully
        """
        valid_statuses = ['discovered', 'active', 'idle', 'offline']
        if status not in valid_statuses:
            raise DatabaseError(f"Invalid status: {status}", details={'valid': valid_statuses})

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE devices
                    SET status = %s, last_seen = NOW()
                    WHERE mac_address = %s
                """, (status, mac_address))
                conn.commit()

                logger.debug(f"Device status updated: {mac_address} -> {status}")
                return cursor.rowcount > 0

        except psycopg2.Error as e:
            error_msg = f"Failed to update device status: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'mac': mac_address, 'status': status})

    # ========================================================================
    # CONNECTION OPERATIONS
    # ========================================================================

    def add_connection(self, conn_data: Dict) -> bool:
        """
        Add connection to database

        Args:
            conn_data: Connection information
                Required: dst_ip, dst_port
                Optional: src_mac, src_ip, protocol, threat_score, metadata, etc.

        Returns:
            True if connection added successfully
        """
        if not conn_data.get('dst_ip') or conn_data.get('dst_port') is None:
            raise DatabaseError("dst_ip and dst_port are required", details={'data': conn_data})

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO connections (
                        timestamp, src_mac, src_ip, dst_ip, dst_port, protocol,
                        dst_country, dst_lat, dst_lon, dst_org, dst_hostname,
                        threat_score, threat_category, metadata
                    ) VALUES (
                        COALESCE(%(timestamp)s, NOW()),
                        %(src_mac)s, %(src_ip)s, %(dst_ip)s, %(dst_port)s, %(protocol)s,
                        %(dst_country)s, %(dst_lat)s, %(dst_lon)s, %(dst_org)s, %(dst_hostname)s,
                        %(threat_score)s, %(threat_category)s, %(metadata)s
                    )
                """, {
                    'timestamp': conn_data.get('timestamp'),
                    'src_mac': conn_data.get('src_mac'),
                    'src_ip': conn_data.get('src_ip'),
                    'dst_ip': conn_data['dst_ip'],
                    'dst_port': conn_data['dst_port'],
                    'protocol': conn_data.get('protocol', 'TCP'),
                    'dst_country': conn_data.get('dst_country'),
                    'dst_lat': conn_data.get('dst_lat'),
                    'dst_lon': conn_data.get('dst_lon'),
                    'dst_org': conn_data.get('dst_org'),
                    'dst_hostname': conn_data.get('dst_hostname'),
                    'threat_score': conn_data.get('threat_score', 0.0),
                    'threat_category': conn_data.get('threat_category'),
                    'metadata': Json(conn_data.get('metadata', {}))
                })

                conn.commit()
                logger.debug(f"Connection added: {conn_data['dst_ip']}:{conn_data['dst_port']}")
                return True

        except psycopg2.Error as e:
            error_msg = f"Failed to add connection: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'dst_ip': conn_data.get('dst_ip')})

    def get_recent_connections(self, limit: int = 50) -> List[Dict]:
        """
        Get recent connections

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of connection dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("""
                    SELECT * FROM connections
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, (limit,))

                connections = cursor.fetchall()
                logger.debug(f"Retrieved {len(connections)} recent connections")
                return [dict(row) for row in connections]

        except psycopg2.Error as e:
            error_msg = f"Failed to retrieve connections: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'limit': limit})

    def get_connections_by_device(self, mac_address: str, limit: int = 100) -> List[Dict]:
        """
        Get connections for a specific device

        Args:
            mac_address: Device MAC address
            limit: Maximum number of connections

        Returns:
            List of connection dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("""
                    SELECT * FROM connections
                    WHERE src_mac = %s
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, (mac_address, limit))

                connections = cursor.fetchall()
                logger.debug(f"Retrieved {len(connections)} connections for device {mac_address}")
                return [dict(row) for row in connections]

        except psycopg2.Error as e:
            error_msg = f"Failed to retrieve device connections: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'mac': mac_address})

    # ========================================================================
    # EVENT OPERATIONS (Phase 0)
    # ========================================================================

    def log_device_event(self, event_data: Dict) -> bool:
        """
        Log device event to audit trail

        Args:
            event_data: Event information
                Required: device_mac, event_type
                Optional: old_value, new_value, metadata

        Returns:
            True if event logged successfully
        """
        if not event_data.get('device_mac') or not event_data.get('event_type'):
            raise DatabaseError("device_mac and event_type are required", details={'data': event_data})

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO device_events (
                        device_mac, event_type, old_value, new_value, metadata
                    ) VALUES (
                        %(device_mac)s, %(event_type)s, %(old_value)s, %(new_value)s, %(metadata)s
                    )
                """, {
                    'device_mac': event_data['device_mac'],
                    'event_type': event_data['event_type'],
                    'old_value': event_data.get('old_value'),
                    'new_value': event_data.get('new_value'),
                    'metadata': Json(event_data.get('metadata', {}))
                })

                conn.commit()
                logger.debug(f"Event logged: {event_data['event_type']} for {event_data['device_mac']}")
                return True

        except psycopg2.Error as e:
            error_msg = f"Failed to log event: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'event': event_data.get('event_type')})

    def get_device_events(self, mac_address: str, limit: int = 50) -> List[Dict]:
        """
        Get events for a device

        Args:
            mac_address: Device MAC address
            limit: Maximum number of events

        Returns:
            List of event dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("""
                    SELECT * FROM device_events
                    WHERE device_mac = %s
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, (mac_address, limit))

                events = cursor.fetchall()
                logger.debug(f"Retrieved {len(events)} events for device {mac_address}")
                return [dict(row) for row in events]

        except psycopg2.Error as e:
            error_msg = f"Failed to retrieve device events: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'mac': mac_address})

    # ========================================================================
    # STATISTICS & UTILITIES
    # ========================================================================

    def get_connection_count(self) -> int:
        """Get total number of connections"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM connections")
                count = cursor.fetchone()[0]
                return count
        except psycopg2.Error as e:
            logger.error(f"Failed to get connection count: {e}")
            return 0

    def get_device_count(self) -> int:
        """Get total number of devices"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM devices")
                count = cursor.fetchone()[0]
                return count
        except psycopg2.Error as e:
            logger.error(f"Failed to get device count: {e}")
            return 0

    def close(self):
        """Close all connections in pool"""
        if self.pool:
            try:
                self.pool.closeall()
                logger.info("📁 PostgreSQL connection pool closed")
            except Exception as e:
                logger.warning(f"Error closing connection pool: {e}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
