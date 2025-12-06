"""
Tests for src.storage.database module
"""

import time
from threading import Thread

import pytest

from src.storage.database import Database


@pytest.mark.unit
def test_database_init(temp_db):
    """Test database initialization and schema creation"""
    db = Database(temp_db)

    # Verify database file was created
    assert db.db_path == temp_db
    assert db.conn is not None

    # Verify tables were created
    cursor = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='connections'"
    )
    assert cursor.fetchone() is not None

    # Verify indexes were created
    cursor = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_timestamp_desc'"
    )
    assert cursor.fetchone() is not None

    cursor = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_src_mac'"
    )
    assert cursor.fetchone() is not None

    db.close()


@pytest.mark.unit
def test_connection_insert(temp_db, sample_connection):
    """Test inserting connection data"""
    db = Database(temp_db)

    # Add connection
    db.add_connection(sample_connection)

    # Flush batch before checking count
    db.flush()

    # Verify insertion
    count = db.get_connection_count()
    assert count == 1

    # Verify data
    connections = db.get_recent_connections(limit=1)
    assert len(connections) == 1
    assert connections[0]["dst_ip"] == sample_connection["dst_ip"]
    assert connections[0]["dst_port"] == sample_connection["dst_port"]
    assert connections[0]["protocol"] == sample_connection["protocol"]

    db.close()


@pytest.mark.unit
def test_query_recent_connections(temp_db):
    """Test querying recent connections with limit"""
    db = Database(temp_db)

    # Add multiple connections
    for i in range(10):
        conn = {
            "dst_ip": f"192.168.1.{i}",
            "dst_port": 443 + i,
            "src_ip": "10.0.0.1",
            "protocol": "TCP",
            "timestamp": time.time() + i,  # Incrementing timestamps
        }
        db.add_connection(conn)

    # Query with limit
    connections = db.get_recent_connections(limit=5)
    assert len(connections) == 5

    # Verify ordering (newest first)
    # The last added connection should be first
    assert connections[0]["dst_ip"] == "192.168.1.9"
    assert connections[4]["dst_ip"] == "192.168.1.5"

    db.close()


@pytest.mark.unit
def test_connection_count(temp_db):
    """Test connection count functionality"""
    db = Database(temp_db)

    # Initially empty
    assert db.get_connection_count() == 0

    # Add connections
    for i in range(5):
        db.add_connection({"dst_ip": f"8.8.8.{i}", "dst_port": 443, "protocol": "TCP"})

    # Flush batch before checking count
    db.flush()

    # Verify count
    assert db.get_connection_count() == 5

    db.close()


@pytest.mark.unit
def test_connection_with_full_data(temp_db):
    """Test connection with all optional fields"""
    db = Database(temp_db)

    full_connection = {
        "timestamp": time.time(),
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "src_ip": "192.168.1.100",
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
        "dst_country": "US",
        "dst_lat": 37.7749,
        "dst_lon": -122.4194,
        "dst_org": "Cloudflare",
        "dst_hostname": "one.one.one.one",
        "threat_score": 0.0,
        "device_vendor": "Apple",
        "protocol": "TCP",
    }

    db.add_connection(full_connection)

    # Retrieve and verify
    connections = db.get_recent_connections(limit=1)
    assert len(connections) == 1

    conn = connections[0]
    assert conn["src_mac"] == full_connection["src_mac"]
    assert conn["src_ip"] == full_connection["src_ip"]
    assert conn["dst_country"] == full_connection["dst_country"]
    assert conn["dst_lat"] == full_connection["dst_lat"]
    assert conn["dst_lon"] == full_connection["dst_lon"]
    assert conn["dst_org"] == full_connection["dst_org"]
    assert conn["dst_hostname"] == full_connection["dst_hostname"]
    assert conn["threat_score"] == full_connection["threat_score"]
    assert conn["device_vendor"] == full_connection["device_vendor"]

    db.close()


@pytest.mark.unit
def test_context_manager(temp_db):
    """Test database context manager usage"""
    with Database(temp_db) as db:
        db.add_connection({"dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "TCP"})
        db.flush()  # Flush batch before checking count
        count = db.get_connection_count()
        assert count == 1

    # Database should be closed after context exit
    # We can't check db.conn directly, but we can verify it was used


@pytest.mark.unit
def test_thread_safety(temp_db):
    """Test thread-safe database operations"""
    db = Database(temp_db)

    def add_connections(thread_id, count):
        for i in range(count):
            db.add_connection(
                {"dst_ip": f"10.0.{thread_id}.{i}", "dst_port": 443, "protocol": "TCP"}
            )

    # Create multiple threads
    threads = []
    for thread_id in range(5):
        thread = Thread(target=add_connections, args=(thread_id, 10))
        threads.append(thread)
        thread.start()

    # Wait for all threads
    for thread in threads:
        thread.join()

    # Verify all connections were added
    total = db.get_connection_count()
    assert total == 50  # 5 threads * 10 connections each

    db.close()


@pytest.mark.unit
def test_default_values(temp_db):
    """Test default values for optional fields"""
    db = Database(temp_db)

    # Add connection with minimal data
    db.add_connection({"dst_ip": "8.8.8.8", "dst_port": 443})

    # Retrieve and verify defaults
    connections = db.get_recent_connections(limit=1)
    assert len(connections) == 1

    conn = connections[0]
    assert conn["threat_score"] == 0  # Default
    assert conn["protocol"] == "TCP"  # Default
    assert conn["timestamp"] > 0  # Auto-generated

    db.close()


@pytest.mark.unit
def test_protocol_field_handling(temp_db):
    """Test protocol field with None values"""
    db = Database(temp_db)

    # Add connection with protocol=None (explicitly None is stored as None)
    db.add_connection({"dst_ip": "8.8.8.8", "dst_port": 443, "protocol": None})

    # Retrieve - explicit None is preserved (use get with default to handle None)
    connections = db.get_recent_connections(limit=1)
    # When protocol is explicitly None, it's stored as None
    assert connections[0]["protocol"] is None

    # Test that missing protocol defaults to TCP
    db.add_connection({"dst_ip": "8.8.4.4", "dst_port": 443})  # No protocol key
    connections = db.get_recent_connections(limit=1)
    assert connections[0]["protocol"] == "TCP"

    db.close()
