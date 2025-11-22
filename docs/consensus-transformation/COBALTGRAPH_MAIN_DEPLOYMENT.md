# CobaltGraph Main - Full Observatory Deployment Guide

## 🎉 System Complete - Multi-Agent Consensus Threat Intelligence

---

## Overview

CobaltGraph Main is the next-generation passive network intelligence platform with **multi-agent consensus-based threat assessment**. This document provides complete deployment and operational guidance.

### Key Features

✅ **Multi-Scorer Consensus** - 3 independent threat scorers (Statistical, Rule-Based, ML)
✅ **Byzantine Fault Tolerant** - 2/3 majority voting with outlier detection
✅ **Lightweight Export** - Hybrid JSON+CSV for research analysis
✅ **Observatory Metrics** - Real-time monitoring of consensus process
✅ **Graceful Degradation** - Falls back to legacy scoring if consensus unavailable
✅ **Zero Database Overhead** - Exports to files, not heavy DB tables

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    CobaltGraph Main                          │
│            Full Observatory Architecture                     │
└──────────────────────────────────────────────────────────────┘

Network Traffic
    ↓
network_monitor.py (packet capture)
    ↓
Queue (1000 entries)
    ↓
Connection Processor Thread
    │
    ├─→ GeoEnrichment (ip-api.com)
    │
    ├─→ ConsensusThreatScorer ← ═══ CORE INNOVATION ═══
    │      │
    │      ├─ Statistical Scorer (confidence intervals)
    │      ├─ Rule-Based Scorer (expert heuristics)
    │      └─ ML Scorer (feature-based prediction)
    │           ↓
    │      BFT Consensus (median + outlier detection)
    │           ↓
    │      HMAC-SHA256 signatures
    │
    ├─→ ConsensusExporter
    │      ├─ JSON Lines: exports/consensus_detailed_YYYYMMDD.jsonl
    │      └─ CSV Summary: exports/consensus_summary.csv
    │
    └─→ Database (SQLite)
         └─ Dashboard API
```

---

## Installation & Deployment

### Prerequisites

✅ Python 3.8+
✅ All dependencies: `pip install -r requirements.txt`
✅ For network-wide mode: root/sudo access

### Quick Start

```bash
# 1. Test the system (recommended first step)
python3 test_cobaltgraph_main.py

# 2. Start CobaltGraph Main (device mode - no root required)
python3 start.py --mode device

# 3. Access dashboard
#    http://localhost:8080

# 4. Check exports
ls -lh exports/
```

### Production Deployment

```bash
# Network-wide monitoring (requires root)
sudo python3 start.py --mode network --port 8080

# With auto-restart supervision
sudo python3 start.py --mode network --supervised

# Background daemon mode
sudo python3 start.py --mode network > logs/cobaltgraph.log 2>&1 &
```

---

## File Structure

### New Files Created

```
src/
├── consensus/               ← Multi-agent consensus system
│   ├── __init__.py
│   ├── scorer_base.py       # Abstract scorer interface
│   ├── statistical_scorer.py
│   ├── rule_scorer.py
│   ├── ml_scorer.py
│   ├── bft_consensus.py     # Byzantine fault tolerant voting
│   └── threat_scorer.py     # Main consensus orchestrator
│
├── export/                  ← Lightweight export system
│   ├── __init__.py
│   └── consensus_exporter.py
│
└── core/
    ├── main.py              ← NEW: CobaltGraph Main (replaces orchestrator)
    └── orchestrator_legacy.py ← Backup of original orchestrator

exports/                     ← Export directory (auto-created)
├── consensus_detailed_YYYYMMDD.jsonl  # Full data
└── consensus_summary.csv               # Quick analysis

tests/
├── test_consensus_integration.py  # Unit tests for consensus
└── test_cobaltgraph_main.py      # Full system integration test
```

### Modified Files

- `src/core/launcher.py` - Updated to use CobaltGraphMain instead of orchestrator
- `requirements.txt` - No changes needed (no new dependencies!)

---

## Configuration

### Consensus Configuration (Optional)

Create `config/consensus.conf`:

```ini
[consensus]
# Enable/disable consensus (graceful degradation if disabled)
enabled = true

# Cache size (in-memory)
cache_size = 1000

# BFT consensus parameters
min_scorers = 2
outlier_threshold = 0.3
uncertainty_threshold = 0.25

# Export settings
export_directory = exports
csv_max_size_mb = 10
buffer_size = 100
```

### Environment Variables

```bash
# Export directory
export COBALTGRAPH_EXPORT_DIR=/var/log/cobaltgraph/exports

# Disable consensus (force legacy mode)
export COBALTGRAPH_CONSENSUS_DISABLED=1
```

---

## Understanding the Output

### Console Output

```
🎯 Using CobaltGraph Main (Full Observatory)
🔬 Multi-Agent Consensus Threat Intelligence

📁 Initializing database...
✅ Database ready: data/device.db

🤝 Initializing consensus threat scoring...
✅ Consensus threat scoring ENABLED
   Scorers: ['statistical', 'rule_based', 'ml_based']

✅ Consensus exporter ready: exports

🚀 Starting CobaltGraph Main...
✅ CobaltGraph Main ACTIVE
🔬 Observatory Mode ENABLED
👁️  All systems operational
```

### Consensus Assessment Logs

```
🔄 Processing: 192.168.1.100 → 8.8.8.8:443

🤝 Consensus: 8.8.8.8 score=0.048, confidence=0.660, uncertainty=LOW

✅ Processed: 192.168.1.100 → 8.8.8.8:443 (score=0.05, method=consensus)
```

### High Uncertainty Detection

```
⚠️  High uncertainty for 185.220.101.1: spread=0.478

🤝 Consensus: 185.220.101.1 score=0.288, confidence=0.349, uncertainty=HIGH
```

This indicates scorers disagreed significantly - valuable for investigation!

---

## Export Data Analysis

### CSV Summary (Quick Analysis)

```bash
# View recent assessments
tail -20 exports/consensus_summary.csv

# Find high-threat IPs
awk -F',' '$5 > 0.7' exports/consensus_summary.csv

# Count high uncertainty cases
awk -F',' '$7 == "True"' exports/consensus_summary.csv | wc -l
```

### JSON Detailed Data (Research)

```bash
# View full consensus details
jq . exports/consensus_detailed_20251122.jsonl | head -50

# Extract all scorer votes
jq '.consensus.votes[]' exports/consensus_detailed_20251122.jsonl

# Find outlier detections
jq 'select(.consensus.outliers | length > 0)' exports/consensus_detailed_*.jsonl
```

### Example CSV Record

```csv
timestamp,iso_time,dst_ip,dst_port,consensus_score,confidence,high_uncertainty,num_scorers,num_outliers,method,is_malicious
1763794237.29,2025-11-22T01:50:37.287224,192.0.2.1,8080,0.750,0.850,False,3,0,median_bft,True
```

### Example JSON Record

```json
{
  "timestamp": 1763794237.29,
  "iso_time": "2025-11-22T01:50:37.287224",
  "dst_ip": "192.0.2.1",
  "dst_port": 8080,
  "protocol": "TCP",
  "consensus": {
    "consensus_score": 0.75,
    "confidence": 0.85,
    "high_uncertainty": false,
    "method": "median_bft",
    "votes": [
      {
        "scorer_id": "statistical",
        "score": 0.78,
        "confidence": 0.82,
        "reasoning": "Statistical analysis: VT: 5/84 vendors flagged; AbuseIPDB: 75% confidence, 12 reports; Port 8080: uncommon",
        "timestamp": 1763794237.28
      },
      {
        "scorer_id": "rule_based",
        "score": 0.70,
        "confidence": 0.90,
        "reasoning": "Rules triggered: VT_MED_THREAT(5 vendors), ABUSEIPDB_HIGH(75%), MED_RISK_PORT(8080)",
        "timestamp": 1763794237.28
      },
      {
        "scorer_id": "ml_based",
        "score": 0.77,
        "confidence": 0.84,
        "reasoning": "ML prediction: 0.772 (key features: abuseipdb_conf=0.75, vt_ratio=0.06, port_entropy=0.60)",
        "timestamp": 1763794237.28
      }
    ],
    "outliers": [],
    "metadata": {
      "num_scorers": 3,
      "num_outliers": 0,
      "score_spread": 0.08,
      "median_score": 0.77,
      "min_score": 0.70,
      "max_score": 0.78
    },
    "is_malicious": true
  }
}
```

---

## Observatory Metrics

### Real-Time Metrics

Access via dashboard or programmatically:

```python
from src.core.main import CobaltGraphMain

main = CobaltGraphMain(mode='device')
metrics = main.get_metrics()

print(metrics['observatory'])
# Output:
{
  'consensus_assessments': 1247,
  'legacy_fallbacks': 3,
  'high_uncertainty_count': 89,
  'export_count': 1247,
  'ground_truth_labels': 0
}

print(metrics['consensus'])
# Output:
{
  'total_assessments': 1247,
  'consensus_failures': 0,
  'high_uncertainty_count': 89,
  'failure_rate': 0.0,
  'uncertainty_rate': 0.071,
  'scorers': {
    'statistical': {
      'assessments_made': 1247,
      'avg_confidence': 0.742,
      'accuracy': 0.0,
      'ground_truth_total': 0
    },
    ...
  }
}
```

### Key Metrics Explained

| Metric | Description | Healthy Range |
|--------|-------------|---------------|
| `consensus_assessments` | Total consensus-based scores | Increasing |
| `legacy_fallbacks` | Times consensus failed, used legacy | < 1% of total |
| `high_uncertainty_count` | Scorers disagreed significantly | 5-15% normal |
| `failure_rate` | Consensus failures | < 0.01 (1%) |
| `uncertainty_rate` | % with high uncertainty | 0.05-0.15 (5-15%) |

---

## Troubleshooting

### Issue: "Consensus module unavailable"

**Symptoms:**
```
⚠️  Consensus unavailable: No module named 'src.consensus'
⚠️  Legacy Mode (no consensus)
```

**Solution:**
```bash
# Check imports
python3 -c "from src.consensus import ConsensusThreatScorer"

# If fails, verify file structure
ls -la src/consensus/
```

### Issue: High uncertainty rate (>30%)

**Symptoms:**
```
⚠️  High uncertainty for 1.2.3.4: spread=0.823
```

**Analysis:**
- Check `exports/consensus_detailed_*.jsonl` for scorer votes
- Look for consistent outlier scorer (may need tuning)
- This is EXPECTED behavior for ambiguous IPs

**Action:**
- If ML scorer is always outlier: Tune weights in `ml_scorer.py`
- If rule scorer too aggressive: Adjust thresholds in `rule_scorer.py`

### Issue: Export files not created

**Symptoms:**
```
# Empty exports/ directory
ls exports/
# No output
```

**Solution:**
```bash
# Check export initialization
python3 test_cobaltgraph_main.py

# Verify permissions
mkdir -p exports
chmod 755 exports

# Check config
grep export_directory config/*.conf
```

### Issue: Performance degradation

**Symptoms:**
```
⚠️  Slow consensus scoring: 1.234s
```

**Analysis:**
- Consensus should be < 100ms per assessment
- Check if external APIs timing out (VT, AbuseIPDB)

**Solution:**
```python
# Disable external lookups temporarily
# In ip_reputation.py, set:
config['virustotal_enabled'] = False
config['abuseipdb_enabled'] = False

# Consensus will use local heuristics only (faster)
```

---

## Research Use Cases

### 1. Analyzing Scorer Agreement

```bash
# Find cases where all scorers agreed
jq 'select(.consensus.outliers | length == 0)' exports/consensus_detailed_*.jsonl | wc -l

# Find cases with outliers
jq 'select(.consensus.outliers | length > 0)' exports/consensus_detailed_*.jsonl
```

### 2. Comparing Scoring Methods

```python
import json
import pandas as pd

# Load JSON data
data = []
with open('exports/consensus_detailed_20251122.jsonl') as f:
    for line in f:
        data.append(json.loads(line))

df = pd.DataFrame(data)

# Compare individual scorer performance
for record in data:
    votes = record['consensus']['votes']
    for vote in votes:
        print(f"{vote['scorer_id']}: {vote['score']:.3f} (confidence: {vote['confidence']:.3f})")
```

### 3. Ground Truth Labeling (Future)

```python
# Manual labeling workflow
from src.consensus import ConsensusThreatScorer

scorer = ConsensusThreatScorer()

# After incident investigation, label assessment
scorer.scorers[0].update_accuracy(
    predicted_score=0.85,
    actual_outcome=True  # Confirmed malicious
)

# Check updated accuracy
print(scorer.scorers[0].get_accuracy())
```

---

## Blue-Team Network Checkpoint

### Deployment Checklist

- [ ] All tests passed (`python3 test_cobaltgraph_main.py`)
- [ ] Exports directory created and writable
- [ ] Network capture working (test with `--mode device` first)
- [ ] Dashboard accessible (http://localhost:8080)
- [ ] Consensus scoring enabled (check logs for "Observatory Mode ENABLED")
- [ ] Export files being created (check `exports/` after 5 minutes)
- [ ] No high failure rate (< 1%)

### Security Considerations

✅ **Passive Monitoring** - No active scanning, zero network impact
✅ **Local Processing** - All consensus logic runs locally
✅ **Minimal API Calls** - Only geo lookups (ip-api.com, rate-limited)
✅ **Cryptographic Signatures** - HMAC-SHA256 on all scorer votes
✅ **No Outbound Connections** - Except geo/threat intel APIs (configurable)

### Operational Monitoring

```bash
# Monitor in real-time
tail -f logs/cobaltgraph.log | grep "Consensus:"

# Check metrics every hour
watch -n 3600 'curl -s http://localhost:8080/api/metrics | jq .observatory'

# Alert on high uncertainty
grep "High uncertainty" logs/cobaltgraph.log | wc -l
```

---

## What's Next?

### Phase 2 Enhancements (Future)

1. **Recursive Improvement** - Scorers update based on ground truth
2. **Automated Labeling** - Incident correlation for ground truth
3. **Additional Scorers** - External APIs (GreyNoise, Shodan, etc.)
4. **Real-time Dashboard** - Live consensus visualization
5. **A/B Testing Framework** - Compare scorer configurations

### Research Applications

- **Multi-Agent Alignment** - Study emergent disagreement patterns
- **Consensus Dynamics** - Analyze when/why scorers disagree
- **Byzantine Behavior** - Test resilience to compromised scorers
- **Ground Truth Feedback** - Recursive self-improvement experiments

---

## Support & Documentation

- **Full Architecture**: See `CONSENSUS_INTEGRATION_ANALYSIS.md`
- **Test Suite**: Run `python3 test_consensus_integration.py`
- **Source Code**: `src/core/main.py` (well-commented)
- **Issue Tracking**: Check logs in `logs/cobaltgraph.log`

---

**Status**: ✅ **PRODUCTION READY**
**Version**: CobaltGraph Main v1.0 (Observatory)
**Date**: 2025-11-22
**Architecture**: Multi-Agent Consensus Threat Intelligence

**🔬 Blue-Team Network Intelligence - Full Observatory Mode** 🔬
