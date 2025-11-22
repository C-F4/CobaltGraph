# CobaltGraph Project Structure
## Network Security Platform - Enterprise Directory Layout

```
CobaltGraph/
├── bin/                           # Executable entry points
│   ├── cobaltgraph                     # Main startup script
│   ├── cobaltgraph-health              # Health check utility
│   └── cobaltgraph-export              # Data export utility
│
├── src/                           # Source code (Python modules)
│   ├── core/                      # Core system modules
│   │   ├── __init__.py
│   │   ├── watchfloor.py          # Main watchfloor system
│   │   ├── config.py              # Configuration loader
│   │   └── database.py            # Database abstraction
│   │
│   ├── capture/                   # Network capture modules
│   │   ├── __init__.py
│   │   ├── network_monitor.py     # Network-wide monitoring
│   │   ├── device_tracker.py      # Device discovery
│   │   ├── legacy_ss.py           # Socket statistics capture
│   │   └── legacy_raw.py          # Raw packet capture
│   │
│   ├── intelligence/              # Threat intelligence
│   │   ├── __init__.py
│   │   ├── ip_reputation.py       # IP reputation services
│   │   ├── geo_intelligence.py    # Geolocation services
│   │   └── ml_detector.py         # ML anomaly detection
│   │
│   ├── dashboard/                 # Web dashboard
│   │   ├── __init__.py
│   │   ├── server.py              # HTTP server
│   │   └── auth.py                # Authentication
│   │
│   ├── api/                       # REST API
│   │   ├── __init__.py
│   │   ├── endpoints.py           # API endpoints
│   │   └── export.py              # Data export API
│   │
│   └── utils/                     # Utilities
│       ├── __init__.py
│       ├── logging.py             # Logging utilities
│       └── validators.py          # Input validation
│
├── config/                        # Configuration files
│   ├── cobaltgraph.conf                # Main configuration
│   ├── auth.conf                  # Authentication config
│   ├── threat_intel.conf          # Threat intel API keys
│   └── README.md                  # Config documentation
│
├── templates/                     # HTML templates
│   └── dashboard.html             # Web dashboard UI
│
├── static/                        # Static web assets
│   ├── css/                       # Stylesheets
│   ├── js/                        # JavaScript
│   └── img/                       # Images
│
├── data/                          # Runtime data (gitignored)
│   ├── db/                        # Database files
│   ├── logs/                      # Log files
│   └── exports/                   # Data exports
│
├── docs/                          # Documentation
│   ├── README.md                  # Main documentation
│   ├── ARCHITECTURE.md            # System architecture
│   ├── API.md                     # API documentation
│   ├── DEPLOYMENT.md              # Deployment guide
│   └── SECURITY.md                # Security considerations
│
├── tests/                         # Test suite
│   ├── unit/                      # Unit tests
│   ├── integration/               # Integration tests
│   └── fixtures/                  # Test data
│
├── scripts/                       # Utility scripts
│   ├── setup.sh                   # First-time setup
│   ├── migrate_db.sh              # Database migrations
│   └── install_deps.sh            # Dependency installation
│
├── .gitignore                     # Git ignore rules
├── requirements.txt               # Python dependencies
├── setup.py                       # Package setup
└── README.md                      # Project README

```

## Directory Purpose

### `/bin` - Executables
Entry point scripts that users interact with directly.

### `/src` - Source Code
All Python modules organized by function. Follows Python package structure with `__init__.py` files.

### `/config` - Configuration
All `.conf` files and configuration documentation. Should be version controlled (except sensitive keys).

### `/templates` - HTML Templates
Web dashboard HTML files. Separated from source code for clean organization.

### `/static` - Static Assets
CSS, JavaScript, images for web dashboard. Can be served directly by HTTP server.

### `/data` - Runtime Data
**NOT version controlled**. Contains databases, logs, exports. Created at runtime.

### `/docs` - Documentation
All markdown documentation. GitHub will automatically render these.

### `/tests` - Test Suite
Unit tests, integration tests, and test fixtures. Follows `pytest` conventions.

### `/scripts` - Utility Scripts
Helper scripts for setup, migration, deployment. Not part of main application flow.

## Benefits of This Structure

1. **Industry Standard**: Follows Python packaging best practices (PEP 8, setuptools)
2. **Scalable**: Easy to add new modules without cluttering root directory
3. **Maintainable**: Clear separation of concerns (capture vs intelligence vs dashboard)
4. **Testable**: Proper test directory structure for `pytest`
5. **Deployable**: Can be packaged with `setup.py` for `pip install`
6. **Professional**: Looks like a real open-source project on GitHub
7. **Developer-Friendly**: New developers can navigate easily

## Migration Notes

All existing functionality is preserved. Old scripts create symlinks for backward compatibility.
