#!/usr/bin/env python3
"""
CobaltGraph Database Utilities
Manage mode-specific databases

Each mode has its own database to avoid permission conflicts:
- Device mode: data/device.db (no sudo required)
- Network mode: data/network.db (requires sudo)

This prevents issues when switching between sudo and non-sudo runs.
"""

import sqlite3
import sys
from pathlib import Path

def get_stats(db_path):
    """Get database statistics"""
    if not Path(db_path).exists():
        return None

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    stats = {}

    # Total connections
    cursor.execute("SELECT COUNT(*) FROM connections")
    stats['total'] = cursor.fetchone()[0]

    # Unique destinations
    cursor.execute("SELECT COUNT(DISTINCT dst_ip) FROM connections")
    stats['unique_ips'] = cursor.fetchone()[0]

    # Countries
    cursor.execute("SELECT COUNT(DISTINCT dst_country) FROM connections WHERE dst_country IS NOT NULL")
    stats['countries'] = cursor.fetchone()[0]

    # Date range
    cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM connections")
    min_ts, max_ts = cursor.fetchone()
    stats['first_seen'] = min_ts
    stats['last_seen'] = max_ts

    conn.close()
    return stats

def list_databases():
    """List all CobaltGraph databases and their stats"""
    print("=" * 70)
    print("CobaltGraph Database Summary")
    print("=" * 70)
    print()

    data_dir = Path("data")
    if not data_dir.exists():
        print("❌ No data directory found")
        return

    databases = {
        'device.db': 'Device Mode (no sudo)',
        'network.db': 'Network Mode (requires sudo)',
        'cobaltgraph.db': 'Legacy (unified database)',
    }

    for db_file, description in databases.items():
        db_path = data_dir / db_file

        print(f"📊 {db_file} - {description}")
        print("-" * 70)

        if not db_path.exists():
            print("   Status: Not created yet")
            print()
            continue

        # File info
        size = db_path.stat().st_size
        print(f"   Size: {size:,} bytes ({size/1024:.1f} KB)")

        # Stats
        stats = get_stats(db_path)
        if stats:
            print(f"   Connections: {stats['total']:,}")
            print(f"   Unique IPs: {stats['unique_ips']:,}")
            print(f"   Countries: {stats['countries']}")
            if stats['first_seen']:
                from datetime import datetime
                first = datetime.fromtimestamp(stats['first_seen']).strftime('%Y-%m-%d %H:%M')
                last = datetime.fromtimestamp(stats['last_seen']).strftime('%Y-%m-%d %H:%M')
                print(f"   Time Range: {first} → {last}")

        print()

def merge_databases():
    """Merge device and network databases into combined.db"""
    print("🔄 Merging device and network databases...")
    print()

    device_db = Path("data/device.db")
    network_db = Path("data/network.db")
    combined_db = Path("data/combined.db")

    if not device_db.exists() and not network_db.exists():
        print("❌ No databases to merge")
        return

    # Create combined database
    if combined_db.exists():
        print(f"⚠️  {combined_db} already exists, removing...")
        combined_db.unlink()

    combined = sqlite3.connect(combined_db)

    # Create schema
    combined.execute("""
        CREATE TABLE connections (
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
            protocol TEXT DEFAULT 'TCP',
            capture_mode TEXT
        )
    """)

    total = 0

    # Copy from device.db
    if device_db.exists():
        print(f"📥 Importing from {device_db}...")
        device_conn = sqlite3.connect(device_db)
        cursor = device_conn.execute("SELECT * FROM connections")
        rows = cursor.fetchall()

        for row in rows:
            combined.execute("""
                INSERT INTO connections
                (timestamp, src_mac, src_ip, dst_ip, dst_port, dst_country, dst_lat, dst_lon, dst_org, dst_hostname, threat_score, device_vendor, protocol, capture_mode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'device')
            """, row[1:])  # Skip ID

        device_count = len(rows)
        total += device_count
        print(f"   ✅ Imported {device_count} connections from device mode")
        device_conn.close()

    # Copy from network.db
    if network_db.exists():
        print(f"📥 Importing from {network_db}...")
        network_conn = sqlite3.connect(network_db)
        cursor = network_conn.execute("SELECT * FROM connections")
        rows = cursor.fetchall()

        for row in rows:
            combined.execute("""
                INSERT INTO connections
                (timestamp, src_mac, src_ip, dst_ip, dst_port, dst_country, dst_lat, dst_lon, dst_org, dst_hostname, threat_score, device_vendor, protocol, capture_mode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'network')
            """, row[1:])  # Skip ID

        network_count = len(rows)
        total += network_count
        print(f"   ✅ Imported {network_count} connections from network mode")
        network_conn.close()

    combined.commit()
    combined.close()

    print()
    print(f"✅ Merged database created: {combined_db}")
    print(f"   Total connections: {total}")

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("CobaltGraph Database Utilities")
        print()
        print("Usage:")
        print("  python3 tools/db_utils.py list    - List all databases and stats")
        print("  python3 tools/db_utils.py merge   - Merge device+network into combined.db")
        print()
        print("Database Layout:")
        print("  data/device.db   - Device mode captures (no sudo)")
        print("  data/network.db  - Network mode captures (sudo required)")
        print("  data/combined.db - Merged view of both modes")
        print()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == 'list':
        list_databases()
    elif command == 'merge':
        merge_databases()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()
