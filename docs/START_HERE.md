# CobaltGraph - Start Here

**Terminal Network Intelligence Platform**

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

- **5-Scorer Median Consensus** - Statistical, Rule, Heuristic, Organization, and Neural scorers. Scores are heuristic risk estimates.
- **Pure Terminal Interface** - No web server, no HTTP ports
- **Device Monitoring** - No root required for device-level capture
- **Passive Network Discovery** - LAN device enumeration without sending packets
- **Export Functionality** - JSON Lines, CSV, and STIX 2.1
- **Threat Intelligence** - VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise
- **Geolocation & ASN** - IP geolocation with ASN/org-type risk weighting
- **Regular-Interval Analysis** - Flags unusually regular connection timing (heuristic; see Known Limitations in the README)
- **Detection Queue and Log** - Recorded detections grouped by destination (`a` queue, `l` log). In the log, `s` sets the minimum severity; `e` exports JSON Lines and `c` exports CSV. The main table's `s` switches between time and risk order.
- **JA3 TLS Fingerprinting** - Passive TLS client identification

---

## Documentation

- **Quick Start**: This file
- **Architecture and detection logic**: `README.md`
- **Configuration**: `config/cobaltgraph.conf` (comments on their own lines)
- **Tests**: `pytest src/`
- **Main README**: `README.md`

---

## Support

For issues or questions:
- Check the health status: `bin/cobaltgraph-health`
- Review logs in `logs/` directory
- See `README.md` for full documentation, including Known Limitations

---

**CobaltGraph** - Blue-Team Network Intelligence Platform
