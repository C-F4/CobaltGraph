"""
Tests for detection recording: column contract, migration, add_event, retention.
"""

import sqlite3
import time

import pytest

from src.storage.database import Database

DAY = 86400


def _conn(dst_ip="203.0.113.5", dst_port=443, timestamp=None, **extra):
    data = {
        "timestamp": time.time() if timestamp is None else timestamp,
        "src_ip": "192.168.1.10",
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "threat_score": 0.2,
    }
    data.update(extra)
    return data


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "detections.db"))
    yield database
    database.close()


@pytest.mark.unit
def test_insert_columns_match_tuple_length_and_schema(db):
    """The positional INSERT must line up with _conn_to_tuple and the table."""
    row = db._conn_to_tuple(_conn(score_heuristic=0.4, beaconing_detected=True))
    assert len(row) == len(Database.INSERT_COLUMNS)

    table_cols = {r[1] for r in db.conn.execute("PRAGMA table_info(connections)")}
    assert set(Database.INSERT_COLUMNS) <= table_cols


@pytest.mark.unit
def test_detection_fields_round_trip(db):
    db.add_connection_immediate(_conn(
        score_heuristic=0.41,
        score_neural_net=0.12,
        beaconing_detected=True,
        beaconing_interval=30.0,
        beaconing_jitter=4.5,
        dga_detected=True,
    ))
    row = db.get_recent_connections(limit=1)[0]
    assert row["score_heuristic"] == pytest.approx(0.41)
    assert row["score_neural_net"] == pytest.approx(0.12)
    assert row["beaconing_detected"] == 1
    assert row["beaconing_interval"] == pytest.approx(30.0)
    assert row["beaconing_jitter"] == pytest.approx(4.5)


@pytest.mark.unit
def test_migration_adds_missing_columns_to_old_database(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(str(path))
    raw.execute(
        "CREATE TABLE connections (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp REAL NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL, "
        "threat_score REAL DEFAULT 0)"
    )
    raw.commit()
    raw.close()

    database = Database(str(path))
    try:
        cols = {r[1] for r in database.conn.execute("PRAGMA table_info(connections)")}
        assert {"beaconing_detected", "score_heuristic", "score_neural_net"} <= cols
    finally:
        database.close()


@pytest.mark.unit
def test_add_event_maps_src_ip_and_records_row(db):
    db.add_event(
        event_type="high_threat",
        message="High threat: 203.0.113.5:443",
        severity="HIGH",
        src_ip="10.0.0.2",
        dst_ip="203.0.113.5",
        dst_port=443,
        threat_score=0.9,
        org_name="Example",
        metadata="{}",
    )
    rows = db.get_recent_events(limit=5)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "high_threat"
    assert rows[0]["source_ip"] == "10.0.0.2"
    assert rows[0]["dst_ip"] == "203.0.113.5"


@pytest.mark.unit
def test_prune_removes_only_rows_past_retention(db):
    now = time.time()
    db.add_connection_immediate(_conn(timestamp=now - 40 * DAY))
    db.add_connection_immediate(_conn(timestamp=now - 35 * DAY))
    db.add_connection_immediate(_conn(timestamp=now - 1 * DAY))

    deleted = db.prune_connections(retention_days=30, batch_size=1, pause=0)

    assert deleted == 2
    remaining = db.conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
    assert remaining == 1


@pytest.mark.unit
def test_prune_is_noop_when_retention_disabled(db):
    db.add_connection_immediate(_conn(timestamp=time.time() - 400 * DAY))
    assert db.prune_connections(retention_days=0) == 0
    assert db.conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 1


@pytest.mark.unit
def test_maintenance_thread_starts_once_and_stops_on_close(tmp_path):
    database = Database(str(tmp_path / "maint.db"))
    database.start_maintenance(30)
    first = database._maintenance_thread
    database.start_maintenance(30)
    assert database._maintenance_thread is first
    assert first.is_alive()

    database._stop_maintenance()
    assert not first.is_alive()
    assert database._maintenance_thread is None
    database.close()
