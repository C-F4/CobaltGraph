# CobaltGraph

**Blue-Team Network Intelligence Platform**

A terminal-native passive network monitoring system with multi-scorer consensus threat scoring, real-time geospatial visualization, a SOC-style detection queue, and structured threat intelligence export — no web server, no C dependencies, no root required for device-level monitoring.

---

## Overview

CobaltGraph passively observes network traffic and scores connections using five independent threat assessment engines. Their scores are combined by median voting with outlier rejection. Detections are recorded in a local database and shown in the terminal. All processing runs locally. No packets are injected onto the network.

Scores are heuristic risk estimates. They are not verified malware or attack detections. See [Known Limitations](#known-limitations).

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

## Threat Scoring — 5-Scorer Median Consensus

Each connection is independently scored by five engines. Results are combined by median voting with outlier rejection and a spread-based uncertainty flag.

| Scorer | Method |
|--------|--------|
| **Statistical** | Confidence interval analysis, baseline deviation (z-score), and inter-arrival regularity over new flows |
| **Rule-Based** | Expert heuristics — high-risk ports, known bad patterns, DGA-like name heuristics |
| **Heuristic** | Logistic-style scoring with hand-tuned feature weights. No training data. |
| **Organization** | ASN/org-type risk weights (org-name and ASN heuristics), hop-count analysis |
| **Neural (GRU)** | Pure-Python GRU network with online-learning code paths. The shipped model is untrained and receives no feedback in the running app (see Known Limitations). |

**Consensus logic** (`src/consensus/bft_consensus.py`):
- Outlier rejection: a scorer whose score differs from the median by more than `0.30` (absolute, 0–1 scale) is excluded. If fewer than two scorers remain, all scores are used.
- Uncertainty flag: raised when the spread (max − min) of non-outlier scores exceeds `0.25`. Confidence is multiplied by `0.7` when the flag is raised.
- Final score: `0.0` (lowest risk) → `1.0` (highest risk)
- Malicious and alert decisions use `alert_threshold` (default `0.7`), read through one shared accessor. Colour bands for display (for example the score bars) are fixed.

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

Configure keys in `config/threat_intel.conf` (gitignored, never committed). Section names are not case-sensitive:

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
- **Threat Posture** — threat level gauge, top-threat radar, elevated-risk org type counts, a **DETECTIONS (1h)** block (destinations per detection type), and the top three flagged destinations
- **Intel Map** — switchable flat map / rotating globe with connection overlays (geographic dots, threat coloring)
- **Connection Table** — live feed with IP, port, protocol, org, ASN, threat score, confidence, hops, and a **Flags** column
- **Detection Queue** (`a`) — recorded detections grouped by destination, most urgent first, with type badges (`BCN` beaconing, `DGA` DGA-like name, `UNC` uncertain consensus, `HIGH` high threat, `ANM` anomaly)
- **LAN Discovery** *(network mode)* — device tree: MAC → vendor → hostname → top destinations → aggregate threat
- **Destinations** *(device mode)* — external connection targets with org, threat level, connection counts
- **Analytics Graphs** — connection volume timeline, geo-threat chart, port distribution, threat distribution

**Flags column:** `B` regular-interval timing, `D` DGA-like name, `S` scan pattern, `M` domain/ASN mismatch.

**Keys:**

| Key | Action |
|-----|--------|
| `a` | Show or hide the Detection Queue |
| `r` | Refresh now |
| `q` | Quit |
| `i` | Cycle the map: flat map, globe, rotating globe |
| `Esc` | Close the open view or log |
| `o` | Org intelligence panel |
| `m` | Mode panel (topology / devices) |
| `c` | Graph analytics (cycles on repeat) |
| `n` | Keyboard-scroll the network panel |
| `k` | Metric key |
| `v` | Cycle the verification filter |
| `p` | Pivot on the selected IP |
| `l` | Detections Log — full-screen, filterable list of recorded detections |
| `s` | Sort the connection table by time (newest first) or by risk |
| `Enter` on a row | Open the full intelligence view for that connection |
| `ctrl+p` / `?` | Command palette (lists every command) |

**Detections Log** (`l`): `s` minimum severity, `t` type filter, `o` sort by time or severity, `/` destination filter, `Enter` drills into the newest connection for that destination, `e` exports JSON Lines, `c` exports CSV. Exports go to the configured `export_directory`, or `data/exports` if that is not writable.

**Map modes** (press `i` to cycle):
- Flat ASCII world map with geo-plotted dots
- Simple globe
- Rotating animated globe

---

## Analytics & Detection

- **Regular-interval (possible beaconing) timing** — the pipeline records the timing of each new flow to a destination before deduplication. A destination whose connection intervals are regular with low jitter is flagged. Regular polling can match this too, so the flag is a lead to verify, not a verdict. Infrastructure organizations are excluded.
- **Recorded detections** — high threat, uncertain consensus, regular-interval timing, DGA-like names, and anomalies are written to the events table, at most once per destination per detection type every five minutes.
- **JA3 TLS fingerprinting** — passive SSL/TLS client fingerprinting from ClientHello parameters
- **Connection state tracking** — bidirectional flow analysis with hop estimation from passive TTL
- **Protocol enrichment** — service identification from port/behavior, DNS and TLS SNI capture
- **Passive subnet intelligence** — ARP, DHCP, and IPv6 RA analysis for device discovery
- **OUI MAC vendor lookup** — vendor identification from MAC OUI prefix

---

## Export

| Format | Content |
|--------|---------|
| **JSON Lines** | Full enrichment record per connection — IP, geo, ASN, all scorer outputs, consensus result |
| **CSV** | Analyst-ready summary for spreadsheet tools |
| **STIX 2.1** | Structured threat intelligence bundles — Indicators, Observed Data, Relationships |
| **Detections** | Recorded detections from the Detections Log (`e` JSON Lines, `c` CSV) |

---

## Configuration

`config/cobaltgraph.conf` is loaded at startup. Settings the application reads:

Comments go on their own lines. An inline `#` becomes part of the value and the setting fails to load.

```ini
[General]
# Rows older than this are deleted in the background (0 = keep)
retention_days = 30

[ThreatScoring]
# Malicious flag, alert rules, and high-threat events
alert_threshold = 0.7

[Export]
# Used by the Detections Log and the scorer exports
export_directory = ./exports
```

Sensitive files (`config/auth.conf`, `config/threat_intel.conf`) are gitignored and never committed.

**Database maintenance** (`tools/db_utils.py`). Operates on `database/cobaltgraph.db` unless `--db PATH` is given. Stop the application first for `prune` and `vacuum`.

```bash
python3 tools/db_utils.py list                       # size, counts, time range
python3 tools/db_utils.py prune --days 30 --dry-run  # how many rows would be deleted
python3 tools/db_utils.py prune --days 30            # delete them, in batches
python3 tools/db_utils.py vacuum                     # dry run: free-space check only
python3 tools/db_utils.py vacuum --yes               # rewrite the file to reclaim space
```

---

## Project Structure

```
cobaltgraph              ← Single-file executable (self-bootstrapping venv)
src/
├── core/                ← DataPipeline (live pipeline), config loader, system check
├── capture/             ← Device monitor (ss/netstat), network monitor (promiscuous), passive discovery
├── consensus/           ← Median consensus engine, 5 scorers, metrics
├── services/            ← Geo, ASN, IP reputation, OTX, GreyNoise, OUI, IOC
├── pipeline/            ← Connection correlator and shared config/event types
├── analytics/           ← Regular-interval timing detector, JA3 fingerprinting, threat analytics, aggregator
├── storage/             ← SQLite (WAL mode), batch inserts, retention, connection/device models
├── export/              ← JSON Lines, CSV, STIX 2.1, detections export
├── ui/                  ← Textual dashboard, detection queue, detections log, theme, maps, graphs, panels
└── utils/               ← Logging, error types, heartbeat, thresholds, platform utilities
config/
├── cobaltgraph.conf     ← Main settings (committed — no secrets)
├── threat_intel.conf    ← API keys (gitignored)
└── auth.conf            ← HMAC secrets (gitignored)
tools/                   ← db_utils (list, prune, vacuum), seed_demo_db (synthetic data for trying the UI)
```

---

## Security Design

- **Passive only** — never injects packets; reads kernel state (`ss`, `ip neigh`, ARP cache) or captures in promiscuous mode
- **No web server** — pure terminal operation, zero HTTP attack surface
- **Local processing** — all scoring and enrichment runs on-device
- **Minimal privilege** — device mode requires no root; only network-wide capture needs promiscuous access
- **Assessment integrity checks** — each scorer's assessment is HMAC-SHA256 signed with a random per-run key held in memory. This catches corrupted or mismatched assessments inside the process. It does not authenticate scorers against code running in the same process.
- **Pure Python** — no compiled extensions; installable anywhere Python 3.10+ runs

---

## Use Cases

- **Personal security** — understand what your machine is connecting to and why
- **Home network monitoring** — discover all LAN devices and their outbound flows
- **SOC triage** — the detection queue and log show what was recorded, grouped by destination
- **Incident investigation** — historical connection and detection database, exportable
- **Threat hunting** — timing-regularity review, JA3 fingerprints, IOC correlation
- **CTF / lab environments** — offline-capable, no cloud dependencies required

---

## Known Limitations

Verified against the code. These are open issues, not design choices.

**Detection**
- **Timing is per new flow.** Device mode sees sockets through a 2-second poll, so connections shorter than one poll are missed. A long-lived socket that re-sends on one connection is seen once, not as a series of intervals. Network mode sees each 4-tuple (local and remote address and port) once, which is the closer match for beaconing.
- **Neural scorer is untrained and not learning.** The shipped model records `trained_samples: 0`. No code path in the running app calls `provide_ground_truth`, so online learning never runs.
- **Scoring failures return 0.5.** If fewer than two scorers respond, or signatures fail, the consensus returns `0.5` with an `error` field. That value appears as a score in the UI.
- **Assessment persistence is a stub.** `ConsensusThreatScorer._flush_to_disk()` only logs. Per-assessment history is not stored.
- **Cached consensus verdicts.** Scoring results are cached for 60 seconds per destination, so a changed verdict can lag by up to a minute.

**Storage and configuration**
- **Retention deletes rows but does not shrink the file.** Deleted space is reused by SQLite; run `tools/db_utils.py vacuum --yes` to return it to the filesystem (needs about the database's size free and the app stopped).
- **Two `ConnectionEvent` classes.** `core/orchestrator.py` and `pipeline/events.py` each define one. The live pipeline uses the orchestrator's.

**Display**
- **Toasts cover recorded detections only.** New HIGH and CRITICAL detections raise a toast while the dashboard runs. Lower-severity detections appear in the queue and log only.
- **No blocklist, whitelist, or STIX action in the intelligence view.** Those were placeholders and have been removed; the view is read-only.
- **Some panels show estimated values** (for example the reputation panel in the full intelligence view). Those values are labeled as estimates.

---

## License

MIT
