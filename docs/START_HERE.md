# CobaltGraph - Start Here

**Pure Terminal Network Intelligence Platform**

---

## Quick Start

### Linux / macOS / WSL

```bash
# Interactive mode (recommended)
./cobaltgraph

# Device-only monitoring (no root required)
./cobaltgraph --mode device

# Network-wide monitoring (requires root)
sudo ./cobaltgraph --mode network

# Health check
bin/cobaltgraph-health
```

### Windows (WSL required for network mode)

```bash
# Interactive mode
./cobaltgraph

# For network monitoring (run in WSL with root)
sudo ./cobaltgraph --mode network
```

---

## System Requirements

- Python 3.10+
- SQLite (included with Python)
- Terminal / WSL
- Root privileges only for network-wide mode

---

## Features

- **5-Agent BFT Consensus** - Statistical, Rule, Heuristic, Organization, Neural scorers
- **Pure Terminal Interface** - No web server, no HTTP ports
- **Device Monitoring** - No root required for device-level capture
- **Passive Network Discovery** - LAN device enumeration without sending packets
- **Export Functionality** - JSON Lines, CSV, and STIX 2.1
- **Threat Intelligence** - VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise
- **Geolocation & ASN** - IP geolocation with ASN/org trust scoring
- **Beaconing Detection** - C2 pattern recognition via timing analysis
- **JA3 TLS Fingerprinting** - Passive TLS client identification

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
- Check the health status: `bin/cobaltgraph-health`
- Review logs in `logs/` directory
- See `README.md` for full documentation

---

**CobaltGraph** - Revolutionary Blue-Team Network Intelligence
