# CobaltGraph - Start Here

**Pure Terminal Network Intelligence Platform**

---

## Quick Start

### Linux / macOS / WSL

```bash
# Interactive mode (recommended)
python3 start.py

# Device-only monitoring (no root required)
python3 start.py --mode device --no-disclaimer

# Network-wide monitoring (requires root)
sudo python3 start.py --mode network

# Health check
python3 start.py --health
```

### Windows

```powershell
# Interactive mode
python start.py

# For network monitoring (Run PowerShell as Administrator)
python start.py --mode network
```

---

## System Requirements

- Python 3.8+
- SQLite (included with Python)
- Terminal/Command Prompt
- Root/Admin privileges (only for network-wide mode)

---

## Features

✅ **Multi-Agent Consensus** - Byzantine Fault Tolerant threat intelligence
✅ **Pure Terminal Interface** - No web server, no HTTP ports
✅ **Device Monitoring** - No root required for device-level capture
✅ **Export Functionality** - JSON Lines + CSV export
✅ **Threat Intelligence** - VirusTotal, AbuseIPDB integration
✅ **Geolocation** - IP geolocation tracking

---

## Documentation

- **Quick Start**: This file
- **Consensus System**: `docs/consensus-transformation/`
- **Configuration**: `docs/02-CONFIGURATION/`
- **Testing**: `docs/03-TESTING/`
- **Main README**: `README.md`

---

## Support

For issues or questions:
- Check the health status: `python3 start.py --health`
- Review logs in `logs/` directory
- See `README.md` for detailed documentation

---

**CobaltGraph** - Revolutionary Blue-Team Network Intelligence
