"""
CobaltGraph Database Module
SQLite database operations and connection management

Extracted from watchfloor.py MinimalDatabase class

Responsibilities:
- Database connection lifecycle
- Thread-safe operations
- Query execution
- Schema management
- Connection tracking
"""

import sqlite3
import logging
import time
from threading import Lock
from typing import List, Dict, Optional
from pathlib import Path
from contextlib import contextmanager

# Import custom exceptions
from src.utils.errors import DatabaseError

logger = logging.getLogger(__name__)

class Database:
    """
    SQLite database wrapper for CobaltGraph

    Features:
    - Thread-safe operations with mutex locks
    - Auto-initialization of schema
    - Connection and device tracking
    - Indexed queries for performance
    """

    def __init__(self, db_path: str = "data/cobaltgraph.db"):
        """
        Initialize database connection

        Args:
            db_path: Path to SQLite database file

        Raises:
            DatabaseError: If connection or initialization fails
        """
        self.db_path = db_path
        self.lock = Lock()  # Thread-safe access
        self.conn = None  # Initialize to None

        try:
            # Create data directory if needed
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured data directory exists: {Path(self.db_path).parent}")

        except OSError as e:
            error_msg = f"Failed to create database directory: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'path': str(Path(self.db_path).parent)})

        try:
            # Open connection
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            logger.debug(f"Database connection established: {db_path}")

            # Initialize schema
            self._init_schema()

            logger.info(f"📁 Database initialized: {self.db_path}")

        except sqlite3.Error as e:
            error_msg = f"Failed to connect to database: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'db_path': db_path})

        except Exception as e:
            error_msg = f"Unexpected error initializing database: {e}"
            logger.error(error_msg)
            if self.conn:
                self.conn.close()
            raise DatabaseError(error_msg, details={'db_path': db_path})

    def _init_schema(self):
        """
        Initialize database schema

        Creates tables and indexes for:
        - Connections (network connections with geo data)
        - Indexes for timestamp and MAC address lookups

        Raises:
            DatabaseError: If schema creation fails
        """
        try:
            with self.lock:
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        src_mac TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        dst_country TEXT,
                        dst_lat REAL,
                        dst_lon REAL,
                        dst_org TEXT,
                        dst_hostname TEXT,
                        threat_score REAL DEFAULT 0,
                        device_vendor TEXT,
                        protocol TEXT DEFAULT 'TCP'
                    )
                """)

                # Create indexes for faster queries
                self.conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp ON connections(timestamp DESC)
                """)
                self.conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_src_mac ON connections(src_mac)
                """)

                self.conn.commit()
                logger.debug("Database schema initialized successfully")

        except sqlite3.Error as e:
            error_msg = f"Failed to initialize database schema: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'db_path': self.db_path})

    def add_connection(self, conn_data: Dict):
        """
        Add connection to database

        Args:
            conn_data: Dictionary with connection information
                Required keys: dst_ip, dst_port
                Optional: src_mac, src_ip, dst_country, dst_lat, dst_lon,
                         dst_org, dst_hostname, threat_score, device_vendor, protocol

        Raises:
            DatabaseError: If insert operation fails
        """
        # Validate required fields
        if not conn_data.get('dst_ip') or not conn_data.get('dst_port'):
            error_msg = "Missing required fields: dst_ip and dst_port are required"
            logger.warning(error_msg)
            raise DatabaseError(error_msg, details={'data': conn_data})

        try:
            with self.lock:
                self.conn.execute("""
                    INSERT INTO connections
                    (timestamp, src_mac, src_ip, dst_ip, dst_port, dst_country, dst_lat, dst_lon, dst_org, dst_hostname, threat_score, device_vendor, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    conn_data.get('timestamp', time.time()),
                    conn_data.get('src_mac'),
                    conn_data.get('src_ip'),
                    conn_data.get('dst_ip'),
                    conn_data.get('dst_port'),
                    conn_data.get('dst_country'),
                    conn_data.get('dst_lat'),
                    conn_data.get('dst_lon'),
                    conn_data.get('dst_org'),
                    conn_data.get('dst_hostname'),
                    conn_data.get('threat_score', 0),
                    conn_data.get('device_vendor'),
                    conn_data.get('protocol', 'TCP')
                ))
                self.conn.commit()
                logger.debug(f"Connection added: {conn_data.get('dst_ip')}:{conn_data.get('dst_port')}")

        except sqlite3.Error as e:
            error_msg = f"Failed to add connection: {e}"
            logger.error(error_msg)
            # Attempt rollback
            try:
                self.conn.rollback()
            except:
                pass
            raise DatabaseError(error_msg, details={'dst_ip': conn_data.get('dst_ip')})

    def get_recent_connections(self, limit: int = 50) -> List[Dict]:
        """
        Get recent connections for dashboard

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of connection dictionaries, newest first

        Raises:
            DatabaseError: If query fails
        """
        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT src_mac, src_ip, dst_ip, dst_port, dst_country, dst_lat, dst_lon, dst_org, dst_hostname, threat_score, timestamp, device_vendor, protocol
                    FROM connections
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

                results = [
                    {
                        'src_mac': row[0],
                        'src_ip': row[1],
                        'dst_ip': row[2],
                        'dst_port': row[3],
                        'dst_country': row[4],
                        'dst_lat': row[5],
                        'dst_lon': row[6],
                        'dst_org': row[7],
                        'dst_hostname': row[8],
                        'threat_score': row[9],
                        'timestamp': row[10],
                        'device_vendor': row[11],
                        'protocol': row[12] or 'TCP'
                    }
                    for row in cursor.fetchall()
                ]

                logger.debug(f"Retrieved {len(results)} recent connections (limit={limit})")
                return results

        except sqlite3.Error as e:
            error_msg = f"Failed to retrieve connections: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg, details={'limit': limit})

    def get_connection_count(self) -> int:
        """
        Get total number of connections in database

        Returns:
            Total connection count

        Raises:
            DatabaseError: If query fails
        """
        try:
            with self.lock:
                cursor = self.conn.execute("SELECT COUNT(*) FROM connections")
                count = cursor.fetchone()[0]
                logger.debug(f"Connection count: {count}")
                return count

        except sqlite3.Error as e:
            error_msg = f"Failed to get connection count: {e}"
            logger.error(error_msg)
            raise DatabaseError(error_msg)

    def close(self):
        """
        Close database connection

        Raises:
            DatabaseError: If closing fails (non-critical, logged only)
        """
        if self.conn:
            try:
                self.conn.close()
                logger.info("📁 Database connection closed")
            except sqlite3.Error as e:
                # Log but don't raise - closing errors are non-critical
                logger.warning(f"Error closing database connection: {e}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
