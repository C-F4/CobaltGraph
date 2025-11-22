# CobaltGraph Archive Directory

**Archive Date**: November 11, 2025
**Reason**: Legacy code cleanup (Phase 10 - Expanded)

---

## 📦 **Archived Files**

This directory contains legacy files that have been replaced by the new modular architecture.

### **legacy_scripts/**

#### 1. **cobaltgraph_minimal.py** (37KB)
- **Original Purpose**: Monolithic dashboard-first watchfloor
- **Status**: Replaced by modular architecture
- **Replacement**: `src/core/watchfloor.py` + `src/dashboard/server.py`
- **Why Archived**: Duplicated functionality, hard to maintain
- **Migration**: Use `python3 start.py` instead

**Key Features (now in modules)**:
- Watchfloor orchestration → `src/core/watchfloor.py`
- Dashboard HTTP server → `src/dashboard/server.py`
- Database operations → `src/storage/database.py`
- Configuration loading → `src/core/config.py`

#### 2. **check_health.sh** (3.9KB)
- **Original Purpose**: Health check script for legacy processes
- **Status**: Obsolete (checked for cobaltgraph_minimal.py, old launchers)
- **Replacement**: Future health check endpoint (see Phase 5)
- **Why Archived**: Checks for processes that no longer exist
- **Migration**: Use `python3 start.py --health` (when implemented)

### **legacy_data/**

#### 1. **cobaltgraph_minimal.db** (20KB)
- **Original Purpose**: SQLite database for cobaltgraph_minimal.py
- **Status**: Old database file
- **Replacement**: `data/cobaltgraph.db` (new location)
- **Why Archived**: Old schema, old location
- **Migration**: Data not migrated (test data only)

**Note**: If you need this data, you can:
1. Open with: `sqlite3 archive/legacy_data/cobaltgraph_minimal.db`
2. Export: `.mode csv` then `.output data.csv` then `SELECT * FROM connections;`
3. Import to new DB using `src/storage/database.py`

---

## 🗑️ **Removed Files**

### **Broken Symlinks**
- `cobaltgraph.py` → `bin/cobaltgraph.py` (target archived in `bin/archive/`)
- `cobaltgraph.bat` → `bin/cobaltgraph.bat` (target archived in `bin/archive/`)

**Why Removed**: These symlinks pointed to files that were archived in Phase 4. They are no longer needed as the unified launchers (`start.py`, `start.sh`) replace all old entry points.

---

## ✅ **What to Keep**

The following root-level files are **intentionally kept** for backward compatibility:

### **Thin Wrappers (Phase 3)**
- `config_loader.py` (953 bytes) - Wrapper for `src.core.config`
- `ip_reputation.py` (1.3KB) - Wrapper for `src.intelligence.ip_reputation`
- `network_monitor.py` (970 bytes) - Wrapper for `src.capture.network_monitor`

These files show deprecation warnings and redirect to the proper src/ modules.

**Migration**: Update imports:
```python
# OLD (deprecated, but still works):
from config_loader import load_config

# NEW (recommended):
from src.core.config import load_config
```

---

## 🚀 **New Architecture**

### **Entry Points**
- **start.py** - Cross-platform Python launcher
- **start.sh** - Interactive bash launcher

### **Core Modules**
- **src/core/launcher.py** - Startup orchestration
- **src/core/watchfloor.py** - Main system orchestrator
- **src/core/config.py** - Configuration management

### **Supporting Modules**
- **src/storage/database.py** - Database operations
- **src/dashboard/server.py** - Web dashboard
- **src/capture/network_monitor.py** - Network capture
- **src/intelligence/ip_reputation.py** - Threat intelligence
- **src/utils/errors.py** - Custom exceptions
- **src/utils/logging_config.py** - Logging setup

---

## 📊 **Archive Statistics**

| Category | Files | Size | Notes |
|----------|-------|------|-------|
| **Legacy Scripts** | 2 | ~41KB | cobaltgraph_minimal.py, check_health.sh |
| **Legacy Data** | 1 | 20KB | cobaltgraph_minimal.db |
| **Removed Symlinks** | 2 | 0 | cobaltgraph.py, cobaltgraph.bat |
| **Total Archived** | 5 | ~61KB | Safe to delete after verification |

---

## ⚠️ **Important Notes**

1. **These files are preserved for reference only**
   - Do not use these archived files
   - They will not work with the new architecture
   - Use the unified launchers instead

2. **Can be safely deleted**
   - After verifying the new system works
   - After migrating any needed data
   - These files are no longer maintained

3. **Restoration not recommended**
   - The new system is more maintainable
   - Old scripts have compatibility issues
   - Use the unified system going forward

---

## 📖 **Migration Guide**

### **From cobaltgraph_minimal.py → start.py**

```bash
# OLD (monolithic):
python3 cobaltgraph_minimal.py

# NEW (modular):
python3 start.py
# or
./start.sh
```

### **From check_health.sh → health check**

```bash
# OLD (legacy):
./check_health.sh

# NEW (planned):
python3 start.py --health
# or use the web dashboard: http://localhost:8080/api/health
```

---

## 📚 **Documentation**

For more information, see:
- `README.md` - User guide
- `ARCHITECTURE.md` - Technical architecture
- `REFACTOR_COMPLETE.md` - Refactor summary
- `PHASE10_COMPLETE.md` - Cleanup details

---

**Archive created as part of**: Phase 10 - Comprehensive Cleanup (Expanded)
**See**: `PHASE10_COMPLETE.md` for full cleanup details
