# CobaltGraph Database

PostgreSQL database schema, migrations, and scripts for CobaltGraph network intelligence platform.

## Directory Structure

```
database/
├── migrations/          # Database migration scripts (versioned)
│   └── 001_device_inventory.sql
├── schema/             # Reference schema documentation
├── seeds/              # Seed data for testing/development
└── scripts/            # Database utility scripts
    └── migrate.py      # Migration runner
```

## Database Architecture

**Database Engine:** PostgreSQL 12+
**Key Features:** JSONB support, Triggers, Views, GIS-ready (PostGIS optional for Phase 3)

### Tables

1. **devices** - Network device inventory (discovered via ARP)
   - Primary Key: `mac_address`
   - Status states: discovered → active → idle → offline
   - Auto-updated via triggers

2. **connections** - Network connections with threat intelligence
   - Links to devices via `src_mac` foreign key
   - JSONB metadata for flexible threat intel storage
   - Indexed for fast queries by device, time, threat score

3. **device_events** - Audit trail for device state changes
   - Immutable event log
   - Tracks: discoveries, status changes, IP changes, threats

### Views

- **active_devices** - Devices seen in last 30 minutes
- **device_summary** - Device stats with connection aggregates

## Running Migrations

### Prerequisites

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Install Python PostgreSQL driver
pip install psycopg2-binary
```

### Configuration

Create `config/database.conf`:

```ini
[database]
host = localhost
port = 5432
database = cobaltgraph
user = cobaltgraph_user
password = CHANGE_ME
```

### Execute Migration

```bash
# Run migration script
python database/scripts/migrate.py

# Or manually via psql
psql -U cobaltgraph_user -d cobaltgraph -f database/migrations/001_device_inventory.sql
```

## Schema Diagram

```
┌─────────────────┐
│    devices      │
│─────────────────│
│ mac_address PK  │◄─────┐
│ ip_address      │      │
│ vendor          │      │
│ device_type     │      │
│ status          │      │
│ first_seen      │      │
│ last_seen       │      │
│ metadata JSONB  │      │
└─────────────────┘      │
                         │
                    ┌────┴──────────────┐
                    │   connections     │
                    │───────────────────│
                    │ id PK             │
                    │ timestamp         │
                    │ src_mac FK        │
                    │ dst_ip            │
                    │ dst_port          │
                    │ threat_score      │
                    │ metadata JSONB    │
                    └───────────────────┘
```

## Performance Targets

- **Device list query:** <100ms for 1,000 devices
- **Connection lookup:** <200ms for 10,000 connections
- **Device detail:** <500ms with full connection history
- **Index coverage:** 95%+ queries use indexes

## Maintenance

### Backup

```bash
pg_dump cobaltgraph > backup_$(date +%Y%m%d).sql
```

### Vacuum (optimize)

```bash
VACUUM ANALYZE devices;
VACUUM ANALYZE connections;
```

## Migration History

| Version | Date | Description |
|---------|------|-------------|
| 001 | 2025-11-19 | Device inventory, connections, events |

---

**Next:** Migration 002 will add Phase 1 enhancements (threat scoring, filtering)
