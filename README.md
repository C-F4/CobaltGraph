# CobaltGraph

<img width="924" height="436" alt="cobalt_001" src="https://github.com/user-attachments/assets/20180fe3-1db9-4898-b888-1fb76b42dbcd" />


**Blue-Team Network Intelligence Platform**

A terminal-native passive network monitoring system with multi-agent consensus threat scoring, real-time geospatial visualization, and a structured threat intelligence export.

---

## Modes of Operation

| Mode | Focus | Requirements |
|------|-------|--------------|
| **Device** | Monitors THIS machine's outbound connections — shows external destinations, orgs, and threat levels | No root required |
| **Network** | Discovers ALL devices on the LAN via passive ARP/broadcast — shows MAC, vendor, hostname, and per-device flows | Root + promiscuous capture |

```bash
# Device mode (no root)
./cobaltgraph --mode device

# Network-wide capture (requires root)
sudo ./cobaltgraph --mode network

# Interactive mode selector
./cobaltgraph
```

---

## Quick Start

```bash
git clone https://github.com/C-F4/CobaltGraph.git
cd CobaltGraph

# Install dependencies (pure Python, no compiler required)
pip3 install -r requirements.txt

# Run
./cobaltgraph
```

**Requirements:** Python 3.10+, Linux / macOS / WSL

SQLite is included with Python — no external database needed.

---

## Threat Scoring — 5-Agent BFT Consensus

Each connection is independently scored by five engines. Results are combined using Byzantine Fault Tolerant median voting with outlier detection and confidence measurement.

| Scorer | Method |
|--------|--------|
| **Statistical** | Confidence interval analysis and baseline deviation (z-score) |
| **Rule-Based** | Expert heuristics — high-risk ports, known bad patterns, protocol anomalies |
| **Heuristic (ML)** | Feature-weighted deterministic scoring with trained coefficient sets |
| **Organization** | ASN/org trust scoring with hop-count analysis and ISP reputation |
| **Neural (GRU)** | Lightweight recurrent neural network with online learning via backpropagation |

**Consensus logic:**
- Outlier removal: scorers deviating >30% from median are flagged
- Uncertainty flag: raised when inter-scorer variance exceeds 25%
- Final score: `0.0` (benign) → `1.0` (critical threat)
- Alert threshold: configurable, default `0.7`

---

## Threat Intelligence Integrations

| Service | Type | Notes |
|---------|------|-------|
| ip-api.com | Geolocation | Free tier, 45 req/min |
| Team Cymru | ASN lookup | DNS-based, no key required |
| VirusTotal | IP reputation | Requires API key |
| AbuseIPDB | IP reputation | Requires API key |
| AlienVault OTX | Threat feeds | Requires API key |
| GreyNoise | Noise filtering | Community API (no key) or paid |
| Local IOC | Custom indicators | File-based, no external dependency |

API keys are optional. The system operates without them — external lookups are enrichment layers, not dependencies.

Configure keys in `config/threat_intel.conf` (gitignored, never committed):

```ini
[virustotal]
api_key = YOUR_KEY

[abuseipdb]
api_key = YOUR_KEY

[alienvault_otx]
api_key = YOUR_KEY

[greynoise]
api_key = YOUR_KEY
```

---

## Dashboard

Terminal UI built on [Textual](https://textual.textualize.io/) — no web server, no open ports.

**Panels:**
- **Threat Posture** — current threat level gauge with top-threat radar
- **Intel Map** — switchable flat map / rotating globe with connection overlays (geographic dots, threat coloring)
- **Connection Table** — live feed with IP, port, protocol, org, ASN, threat score, confidence, hops
- **LAN Discovery** *(network mode)* — device tree: MAC → vendor → hostname → top destinations → aggregate threat
- **Destinations** *(device mode)* — external connection targets with org, threat level, connection counts
- **Analytics Graphs** — connection volume timeline, geo-threat chart, port distribution, threat distribution

**Visualization modes** (cycling with keybind):
- Flat ASCII world map with geo-plotted dots
- Simple globe
- Rotating animated globe

---

## Analytics & Detection

- **Beaconing detection** — identifies C2-style periodic connections by timing regularity and jitter analysis
- **JA3 TLS fingerprinting** — passive SSL/TLS client fingerprinting from ClientHello parameters
- **Connection state tracking** — bidirectional flow analysis with hop estimation from passive TTL
- **Protocol enrichment** — service identification from port/behavior
- **Passive subnet intelligence** — ARP, DHCP, and IPv6 RA analysis for device discovery
- **OUI MAC vendor lookup** — vendor identification from MAC OUI prefix

---

## Export

| Format | Content |
|--------|---------|
| **JSON Lines** | Full enrichment record per connection — IP, geo, ASN, all scorer outputs, consensus result |
| **CSV** | Analyst-ready summary for spreadsheet tools |
| **STIX 2.1** | Structured threat intelligence bundles — Indicators, Observed Data, Relationships |

---

## Configuration

`config/cobaltgraph.conf` controls all runtime behavior. Key sections:

```ini
[General]
log_level = INFO
retention_days = 30

[Network]
monitor_mode = auto          # auto, device, network
capture_interface =          # leave blank for auto-detect

[ThreatScoring]
alert_threshold = 0.7
enable_ip_reputation = true
enable_ml_detection = true

[TerminalDashboard]
dashboard_mode = auto
globe_fps = 10
```

Sensitive files (`config/auth.conf`, `config/threat_intel.conf`) are gitignored and never committed.

---

## Project Structure

```
cobaltgraph              ← Single-file executable (self-bootstrapping venv)
src/
├── core/                ← DataPipeline orchestrator, config loader, system check
├── capture/             ← Device monitor (ss/netstat), network monitor (promiscuous), passive discovery
├── consensus/           ← BFT engine, 5 scorer implementations, metrics
├── services/            ← Geo, ASN, IP reputation, OTX, GreyNoise, OUI, IOC
├── pipeline/            ← Staged async processing (validation → enrichment → scoring → storage)
├── analytics/           ← Beaconing detector, JA3 fingerprinting, threat analytics, aggregator
├── storage/             ← SQLite (WAL mode), batch inserts, connection/device models
├── export/              ← JSON Lines, CSV, STIX 2.1
├── ui/                  ← Textual dashboard, maps, graphs, panels
└── utils/               ← Logging, error types, heartbeat, platform utilities
config/
├── cobaltgraph.conf     ← Main settings (committed — no secrets)
├── threat_intel.conf    ← API keys (gitignored)
└── auth.conf            ← HMAC secrets (gitignored)
```

---

## Security Design

- **Passive only** — never injects packets; reads kernel state (`ss`, `ip neigh`, ARP cache) or captures in promiscuous mode
- **No web server** — pure terminal operation, zero HTTP attack surface
- **Local processing** — all scoring and enrichment runs on-device
- **Minimal privilege** — device mode requires no root; only network-wide capture needs promiscuous access
- **BFT consensus** — HMAC-signed scorer assessments prevent spoofed scores
- **Pure Python** — no compiled extensions; installable anywhere Python 3.10+ runs

---

## Use Cases

- **Personal security** — understand what your machine is connecting to and why
- **Home network monitoring** — discover all LAN devices and their outbound flows
- **SOC triage** — consensus confidence scores help prioritize alerts
- **Incident investigation** — historical connection database with full enrichment
- **Threat hunting** — beaconing detection, JA3 fingerprints, IOC correlation
- **CTF / lab environments** — offline-capable, no cloud dependencies required

---

## License

MIT
