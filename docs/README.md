# CobaltGraph Documentation

See the [project README](../README.md) for the full overview, quick start, architecture, detection logic, and known limitations.

---

## Index

- **Quick Start** → `docs/START_HERE.md`
- **Configuration reference** → `config/cobaltgraph.conf` (comments on their own lines)
- **API keys setup** → `config/threat_intel.conf` (gitignored; format in the README)
- **Tests** → `pytest src/`

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
│  DataPipeline (core/)       │
│  dedup → enrichment →       │
│  consensus scoring → storage│
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  5-Scorer Median Consensus  │
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

**Notes**
- The live pipeline is `DataPipeline` in `src/core/orchestrator.py`. `src/pipeline/stages/` holds only the correlator and base classes it imports.
- Consensus combines scorer outputs by median voting with outlier rejection. It is not a full Byzantine agreement protocol.
