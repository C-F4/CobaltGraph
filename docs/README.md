# CobaltGraph Documentation

See the [project README](../README.md) for the full overview, quick start, architecture, and capability reference.

---

## Index

- **Quick Start** → `docs/START_HERE.md`
- **Configuration reference** → `config/cobaltgraph.conf` (inline comments)
- **API keys setup** → `config/threat_intel.conf` (gitignored template)
- **Tests** → `pytest tests/`

---

## Architecture Summary

```
Network Traffic (passive)
        │
        ▼
┌─────────────────────────────┐
│     Capture Layer           │
│  device_monitor  │          │
│  network_monitor │          │
│  passive_discovery          │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│     Pipeline Stages         │
│  validation → enrichment    │
│  → scoring → storage        │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  5-Agent BFT Consensus      │
│  Statistical │ Rule         │
│  Heuristic   │ Organization │
│  Neural (GRU)               │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Storage + Export           │
│  SQLite (WAL) │ JSON Lines  │
│  CSV          │ STIX 2.1    │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Terminal Dashboard         │
│  Textual TUI │ Globe/Map    │
│  Analytics Graphs           │
└─────────────────────────────┘
```
