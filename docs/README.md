# Cobalt Graph

**Blue-Team Network Intelligence Platform**

A terminal-based network security monitoring system that provides real-time threat intelligence through multi-agent consensus scoring.

---

## Overview

Cobalt Graph passively monitors network traffic to detect and score potential threats. It uses multiple independent threat scoring algorithms with Byzantine Fault Tolerant (BFT) consensus to provide reliable, trustworthy threat assessments.

### Key Capabilities

- **Passive Network Monitoring**: Captures and analyzes network traffic without generating any packets
- **Multi-Agent Threat Scoring**: Three independent scorers (statistical, rule-based, ML-based) vote on threat levels
- **Device Discovery**: Automatically discovers devices on the network via MAC address tracking
- **Threat Intelligence Enrichment**: Integrates with VirusTotal, AbuseIPDB, and geolocation services
- **Terminal Dashboard**: Real-time visualization with no web server required

---

## Modes of Operation

| Mode | Description | Requirements |
|------|-------------|--------------|
| **Device** | Monitors only this machine's connections | No root required |
| **Network** | Monitors entire network segment | Root + promiscuous mode |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/C-F4/CobaltGraph.git
cd CobaltGraph

# Install dependencies
pip3 install -r requirements.txt

# Run in device mode (no root required)
python3 start.py --mode device

# Run in network mode (requires root)
sudo python3 start.py --mode network
```

---

## Architecture

```
Network Traffic (passive capture)
        │
        ▼
┌──────────────────────────────────────┐
│       PACKET CAPTURE ENGINE          │
│  MAC resolution │ Protocol parsing   │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│      THREAT INTELLIGENCE APIs        │
│  Geolocation │ ASN │ IP Reputation   │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│       CONSENSUS ENGINE (BFT)         │
├──────────────────────────────────────┤
│  Statistical  │  Rule-Based  │  ML   │
│   Scorer      │   Scorer     │Scorer │
├──────────────────────────────────────┤
│         Median Voting + Outlier      │
│         Detection + Uncertainty      │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│         TERMINAL DASHBOARD           │
│  Threat Globe │ Connection Table     │
│  Device Tree  │ Network Topology     │
└──────────────────────────────────────┘
```

---

## Dashboard Features

The terminal UI displays:

- **Threat Posture**: Current threat level with top threat radar visualization
- **Threat Globe**: Geographic visualization of connection destinations
- **Connection Table**: Real-time connection log with enrichment data (IP, port, protocol, organization, threat score)
- **Network Topology** (network mode): Device-to-destination flow mapping with MAC addresses, IPs, and protocol types
- **Device Discovery** (device mode): Discovered devices with MAC addresses, vendors, and threat assessments

### Display Information

Each connection shows:
- Source/Destination IP addresses
- MAC addresses and resolved vendor names
- Port and protocol (TCP/UDP)
- Organization and ASN information
- Threat score with confidence level
- Geographic location (country, coordinates)
- Hop count estimation

---

## Threat Scoring

### Consensus Algorithm

Three independent scorers evaluate each connection:

1. **Statistical Scorer**: Uses confidence intervals and baseline deviation
2. **Rule-Based Scorer**: Applies expert-defined heuristics (port analysis, known bad ranges)
3. **ML-Based Scorer**: Trained model for pattern recognition

Scores are combined using Byzantine Fault Tolerant median voting:
- **Outlier Detection**: Identifies when scorers significantly disagree
- **Uncertainty Flag**: Raised when consensus confidence is low
- **Final Score**: 0.0 (safe) to 1.0 (critical threat)

---

## Configuration

### Optional API Keys

Create `config/config.conf` to enable enhanced threat intelligence:

```ini
[threat_intel]
virustotal_api_key = YOUR_KEY
abuseipdb_api_key = YOUR_KEY
```

The system works without API keys but provides richer threat data with them.

### Database

Connections are stored in SQLite at `database/cobaltgraph.db` for historical analysis.

---

## Export

Data can be exported in two formats:
- **JSON Lines**: Full enrichment data with audit trail
- **CSV**: Analyst-ready summary for spreadsheet tools

---

## Project Structure

```
src/
├── core/           # Launcher and data pipeline orchestration
├── ui/             # Terminal dashboard components
├── capture/        # Network/device packet capture
├── consensus/      # BFT threat scoring system
├── services/       # Threat intelligence API integrations
├── storage/        # SQLite database operations
├── analytics/      # Threat analytics and anomaly detection
└── export/         # JSON/CSV export functionality
```

---

## Security Design

- **No Web Server**: Pure terminal operation, zero HTTP attack surface
- **Passive Monitoring**: Never injects packets into the network
- **Local Processing**: All threat scoring done locally
- **Minimal Permissions**: Device mode requires no special privileges

---

## Requirements

- Python 3.8+
- Linux, macOS, or Windows (WSL recommended)
- Root/sudo for network-wide monitoring mode

### Dependencies

Core: `requests`, `scapy`, `numpy`, `textual`, `rich`

Optional: `scipy`, `networkx`, `pandas` for advanced analytics

---

## Use Cases

1. **Home Network Monitoring**: Understand what devices are connecting where
2. **SOC Triage**: Prioritize alerts with multi-agent consensus confidence
3. **Incident Investigation**: Historical connection analysis
4. **Security Research**: Study network traffic patterns and threat indicators

---

## License

MIT License

---

## Contributing

Contributions welcome for:
- Additional threat intelligence scorers
- Dashboard visualization improvements
- Platform compatibility enhancements

**Guidelines:**
- Maintain terminal-first design
- No hardcoded credentials
- All tests must pass
