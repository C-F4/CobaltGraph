# CobaltGraph Database Management

**Last Updated**: November 11, 2025

## Overview

CobaltGraph uses **mode-specific databases** to avoid permission conflicts between sudo and non-sudo runs.

### Database Files

| File | Mode | Requires Sudo | Description |
|------|------|---------------|-------------|
| `data/device.db` | Device | ❌ No | Monitors only your device's connections |
| `data/network.db` | Network | ✅ Yes | Monitors entire network traffic |

## Why Separate Databases?

**Problem**: SQLite files are owned by whoever creates them:
- Running `python3 start.py` → database owned by you
- Running `sudo python3 start.py` → database owned by root
- **Result**: The other user can't write to it! 😢

**Solution**: Each mode uses its own database:
- ✅ No permission conflicts
- ✅ Works on all operating systems
- ✅ Clear separation of device vs network data
- ✅ Simple to understand and manage

## Usage

### Device Mode (No Sudo)
```bash
python3 start.py --mode device
# Creates/uses: data/device.db
```

### Network Mode (Requires Sudo)
```bash
sudo python3 start.py --mode network
# Creates/uses: data/network.db
```

## Database Utilities

CobaltGraph includes a utility script to manage databases:

### View Database Stats
```bash
python3 tools/db_utils.py list
```

Output:
```
📊 device.db - Device Mode (no sudo)
   Size: 20,480 bytes (20.0 KB)
   Connections: 8
   Unique IPs: 4
   Countries: 1
   Time Range: 2025-11-11 15:19 → 2025-11-11 15:20

📊 network.db - Network Mode (requires sudo)
   Status: Not created yet
```

### Merge Databases
To combine device and network data into a single view:
```bash
python3 tools/db_utils.py merge
# Creates: data/combined.db
```

This is useful for:
- Getting a unified view of all traffic
- Exporting all data for analysis
- Creating reports across both modes

## Dashboard Behavior

The dashboard shows data from the **currently running mode**:
- Device mode → shows `device.db` connections
- Network mode → shows `network.db` connections

If you want to see data from both modes, merge the databases first.

## Manual Database Operations

### View Connections
```bash
# Device mode connections
sqlite3 data/device.db "SELECT * FROM connections ORDER BY timestamp DESC LIMIT 10;"

# Network mode connections
sqlite3 data/network.db "SELECT * FROM connections ORDER BY timestamp DESC LIMIT 10;"
```

### Export to CSV
```bash
sqlite3 -header -csv data/device.db "SELECT * FROM connections;" > device_connections.csv
```

### Check Database Size
```bash
ls -lh data/*.db
```

### Delete Old Data
```bash
# Delete connections older than 7 days
sqlite3 data/device.db "DELETE FROM connections WHERE timestamp < strftime('%s', 'now', '-7 days');"
```

## Troubleshooting

### "Database is locked"
Multiple processes accessing same database. Stop CobaltGraph first:
```bash
pkill -f start.py
```

### "Permission denied"
Database was created by a different user. Solutions:
1. Use mode-specific databases (already implemented!)
2. Or manually change ownership:
   ```bash
   sudo chown $USER data/device.db
   ```

### Old `data/cobaltgraph.db` exists
This is the legacy unified database. It's not used anymore.

**Options**:
1. Keep it as backup (recommended)
2. Migrate data to mode-specific databases:
   ```bash
   # Copy to device.db
   sqlite3 data/cobaltgraph.db ".dump" | sqlite3 data/device.db
   ```
3. Delete it:
   ```bash
   rm data/cobaltgraph.db
   ```

## Advanced: Custom Database Path

Override database path in config:

**config/database.yaml**:
```yaml
database_path: /custom/path/my_database.db
```

**Note**: Custom paths still use mode suffix:
- Device: `/custom/path/device.db`
- Network: `/custom/path/network.db`

## Database Schema

Each database has identical schema:

```sql
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
    protocol TEXT DEFAULT 'TCP'
);
```

Indexes:
- `idx_timestamp` - Fast time-range queries
- `idx_src_mac` - Fast device lookups

## Best Practices

1. **Regular Backups**:
   ```bash
   cp data/device.db backups/device_$(date +%Y%m%d).db
   ```

2. **Periodic Cleanup**:
   - Delete old connections (> 30 days)
   - Keep database size manageable

3. **Monitoring**:
   - Use `db_utils.py list` to check database health
   - Watch disk space in `data/` directory

4. **Export Before Major Changes**:
   ```bash
   sqlite3 data/device.db .dump > device_backup.sql
   ```

## Summary

✅ **Simple**: Each mode = its own database
✅ **No conflicts**: No sudo permission issues
✅ **Cross-platform**: Works everywhere
✅ **Manageable**: Easy to backup, merge, export

Questions? Check `tools/db_utils.py --help` or see documentation.
