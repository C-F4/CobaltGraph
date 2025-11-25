# Consensus System Integration Analysis
## Orchestrator.py Integration Plan & Risk Assessment

---

## Current State Analysis

### Existing Code Path (orchestrator.py)
```python
# Line 318-322: Current threat scoring
threat_score = 0.0
threat_details = {}
if self.ip_reputation:
    threat_score, threat_details = self.ip_reputation.check_ip(dst_ip)
```

**Current Behavior:**
- `ip_reputation` is `IPReputationManager` instance (from `src/intelligence/ip_reputation.py`)
- Returns tuple: `(float, Dict)`
- Fallback chain: VirusTotal → AbuseIPDB → local (returns 0.2)
- All 140 existing connections have `threat_score=0.2` (fallback mode)

---

## Proposed Integration

### Modified Code Path
```python
# Line 318-327: NEW consensus-based threat scoring
threat_score = 0.0
threat_details = {}

if self.consensus_scorer:
    # Pass full context to consensus system
    threat_score, threat_details = self.consensus_scorer.check_ip(
        dst_ip=dst_ip,
        threat_intel=threat_details if self.ip_reputation else {},
        geo_data=geo_data or {},
        connection_metadata={
            'dst_port': dst_port,
            'protocol': conn_data.get('protocol', 'TCP'),
            'src_ip': src_ip,
        }
    )
elif self.ip_reputation:
    # Fallback to legacy if consensus disabled
    threat_score, threat_details = self.ip_reputation.check_ip(dst_ip)
```

**Changes Required in orchestrator.py:**
1. **Line 35**: Add import: `from src.consensus import ConsensusThreatScorer`
2. **Line 72**: Add attribute: `self.consensus_scorer = None`
3. **Line 104-140**: Add consensus initialization in `_init_components()`
4. **Line 318-322**: Replace single call with consensus call (shown above)
5. **Line 495-528**: Add cleanup in `shutdown()`

---

## Potential Failures & Mitigations

### 1. Import Failures

**Risk:** Missing dependencies or circular imports

**Symptoms:**
```
ImportError: cannot import name 'ConsensusThreatScorer'
ModuleNotFoundError: No module named 'src.consensus'
```

**Mitigation:**
```python
# Safe import with fallback
try:
    from src.consensus import ConsensusThreatScorer
    CONSENSUS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Consensus module unavailable: {e}")
    CONSENSUS_AVAILABLE = False
    ConsensusThreatScorer = None
```

**Proactive Fix:**
- Test imports before integration: `python -c "from src.consensus import ConsensusThreatScorer"`
- Check `__init__.py` files exist in all new directories

---

### 2. Signature Mismatch

**Risk:** ConsensusThreatScorer.check_ip() signature doesn't match IPReputationManager.check_ip()

**Current Signature:**
```python
# IPReputationManager
def check_ip(self, ip: str) -> Tuple[float, Dict]

# ConsensusThreatScorer (NEW)
def check_ip(
    self,
    dst_ip: str,
    threat_intel: Optional[Dict] = None,
    geo_data: Optional[Dict] = None,
    connection_metadata: Optional[Dict] = None
) -> Tuple[float, Dict]
```

**Issue:** Extra parameters will cause errors if called the old way

**Mitigation:**
- All extra parameters are **optional with defaults**
- Can be called as: `scorer.check_ip(dst_ip)` (backwards compatible)
- OR with full context: `scorer.check_ip(dst_ip, threat_intel, geo_data, metadata)`

**Test:**
```python
# Both should work
score1, details1 = scorer.check_ip("8.8.8.8")  # Minimal
score2, details2 = scorer.check_ip("8.8.8.8", {}, {}, {})  # Full
```

---

### 3. Performance Impact

**Risk:** Consensus scoring is slower than single scorer

**Analysis:**
- **Old:** 1 API call (or local fallback) → ~100ms
- **New:** 3 scorers (same data) → ~10ms each → ~30ms total
- **Benefit:** NO additional API calls (synthetic diversity reuses same threat intel)

**Mitigation:**
- In-memory caching (deque with 1000 entries)
- Async potential (future optimization)
- Configurable: can disable consensus per config

**Monitoring:**
```python
import time
start = time.time()
score, details = self.consensus_scorer.check_ip(dst_ip, ...)
elapsed = time.time() - start
if elapsed > 0.5:
    logger.warning(f"Slow consensus: {elapsed:.3f}s for {dst_ip}")
```

---

### 4. Memory Usage

**Risk:** In-memory cache grows too large

**Current Design:**
- `deque(maxlen=1000)` → automatically drops oldest
- Each entry ~1-2KB → max 2MB for cache
- Periodic flush to disk every 100 assessments

**Mitigation:**
- Configurable cache size: `config.get('consensus_cache_size', 1000)`
- Monitor memory: `len(assessment_cache) * avg_entry_size`
- Force flush on memory pressure

**Monitoring:**
```python
cache_mb = len(self.assessment_cache) * 2 / 1024  # Rough estimate
if cache_mb > 10:
    logger.warning(f"High cache usage: {cache_mb:.1f}MB")
    self._flush_to_disk()
```

---

### 5. Database Schema Conflicts

**Risk:** New tables conflict with existing schema

**Current Tables:**
- `connections` (id, timestamp, src_ip, dst_ip, threat_score, ...)
- `sqlite_sequence`

**New Tables Needed:**
```sql
CREATE TABLE IF NOT EXISTS consensus_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    dst_ip TEXT,
    consensus_score REAL,
    confidence REAL,
    high_uncertainty BOOLEAN,
    votes_json TEXT,  -- JSON blob with all scorer votes
    ground_truth BOOLEAN,  -- NULL initially, updated later
    incident_detected BOOLEAN DEFAULT 0
);

CREATE INDEX idx_consensus_ip ON consensus_assessments(dst_ip);
CREATE INDEX idx_consensus_timestamp ON consensus_assessments(timestamp DESC);
```

**Mitigation:**
- Use `IF NOT EXISTS` to avoid errors
- Separate table namespace (no conflicts)
- Can use separate database file if needed: `data/consensus.db`

---

### 6. Config Loading Issues

**Risk:** Missing config causes initialization to fail

**Issue:**
```python
# orchestrator.py line 99: load_config() might fail
self.config = config or self._load_config()
```

**Mitigation:**
```python
# Safe consensus initialization
try:
    consensus_config = self.config.get('consensus', {})
    self.consensus_scorer = ConsensusThreatScorer(
        config=consensus_config,
        enable_persistence=consensus_config.get('enable_persistence', True)
    )
    logger.info("✅ Consensus threat scoring enabled")
except Exception as e:
    logger.warning(f"⚠️  Consensus scorer unavailable: {e}")
    self.consensus_scorer = None
```

**Config Schema:**
```yaml
# config/consensus.conf
[consensus]
enable = true
cache_size = 1000
enable_persistence = true
min_scorers = 2
outlier_threshold = 0.3
uncertainty_threshold = 0.25
```

---

### 7. Backwards Compatibility

**Risk:** Existing databases/exports break

**Concerns:**
- Old connections with `threat_score=0.2` from single scorer
- New connections with consensus scores (potentially different)
- Mixed data in same database

**Mitigation:**
- **No schema changes to `connections` table** - still stores single `threat_score` field
- Consensus details stored in separate `consensus_assessments` table
- Can query both: `SELECT * FROM connections c LEFT JOIN consensus_assessments ca ON c.dst_ip = ca.dst_ip`

**Data Continuity:**
```python
# Old behavior preserved
enriched = {
    'threat_score': threat_score,  # Still a single float
    # ... other fields
}
self.db.add_connection(enriched)  # Unchanged!
```

---

### 8. Error Handling Cascade

**Risk:** Consensus failure crashes entire pipeline

**Scenario:**
```python
# If consensus.check_ip() raises exception:
threat_score, threat_details = self.consensus_scorer.check_ip(dst_ip)
# → orchestrator crashes → pipeline stops
```

**Mitigation:**
```python
# Defensive error handling in orchestrator.py
try:
    if self.consensus_scorer:
        threat_score, threat_details = self.consensus_scorer.check_ip(
            dst_ip=dst_ip,
            threat_intel=existing_threat_intel,
            geo_data=geo_data,
            connection_metadata={'dst_port': dst_port, 'protocol': protocol}
        )
    elif self.ip_reputation:
        threat_score, threat_details = self.ip_reputation.check_ip(dst_ip)
    else:
        # Ultimate fallback
        threat_score, threat_details = 0.2, {'source': 'fallback'}

except Exception as e:
    logger.error(f"Threat scoring failed for {dst_ip}: {e}", exc_info=True)
    # Safe fallback - don't crash
    threat_score, threat_details = 0.5, {'error': str(e)}
```

---

## Integration Sequence (Safe Rollout)

### Phase 1: Isolated Testing
```bash
# Test consensus module independently
cd /home/tachyon/CobaltGraph
python3 -c "from src.consensus import ConsensusThreatScorer; \
            scorer = ConsensusThreatScorer(); \
            print(scorer.check_ip('8.8.8.8'))"
```

### Phase 2: Mock Integration
Create test harness that simulates orchestrator environment:
```python
# test_consensus_integration.py
from src.consensus import ConsensusThreatScorer

scorer = ConsensusThreatScorer()

# Simulate real data from orchestrator
test_cases = [
    {'dst_ip': '8.8.8.8', 'dst_port': 443},
    {'dst_ip': '1.1.1.1', 'dst_port': 80},
]

for case in test_cases:
    score, details = scorer.check_ip(
        dst_ip=case['dst_ip'],
        connection_metadata={'dst_port': case['dst_port']}
    )
    print(f"{case['dst_ip']}: score={score:.3f}, uncertainty={details['high_uncertainty']}")
```

### Phase 3: Parallel Running
Run both old and new in parallel, log differences:
```python
# In orchestrator.py (temporary comparison mode)
if self.consensus_scorer and self.ip_reputation:
    # Get both scores
    old_score, old_details = self.ip_reputation.check_ip(dst_ip)
    new_score, new_details = self.consensus_scorer.check_ip(dst_ip, ...)

    # Log differences
    diff = abs(new_score - old_score)
    if diff > 0.2:
        logger.warning(f"Score divergence for {dst_ip}: old={old_score:.3f}, new={new_score:.3f}")

    # Use new score but keep monitoring
    threat_score = new_score
```

### Phase 4: Full Cutover
Replace old scorer completely:
```python
# Final production code
if self.consensus_scorer:
    threat_score, threat_details = self.consensus_scorer.check_ip(dst_ip, ...)
elif self.ip_reputation:
    threat_score, threat_details = self.ip_reputation.check_ip(dst_ip)
```

---

## Proactive Monitoring

### Key Metrics to Track

1. **Consensus Health**
   ```python
   stats = self.consensus_scorer.get_statistics()
   if stats['failure_rate'] > 0.05:
       logger.error(f"High consensus failure rate: {stats['failure_rate']*100:.1f}%")
   ```

2. **Score Distribution**
   ```python
   # Track if consensus is too conservative/aggressive
   scores = [entry['consensus']['consensus_score'] for entry in cache]
   avg_score = sum(scores) / len(scores)
   if avg_score < 0.1:
       logger.warning("Consensus may be too lenient (avg score very low)")
   elif avg_score > 0.8:
       logger.warning("Consensus may be too aggressive (avg score very high)")
   ```

3. **Uncertainty Tracking**
   ```python
   uncertainty_rate = stats['uncertainty_rate']
   if uncertainty_rate > 0.3:
       logger.warning(f"High uncertainty rate: {uncertainty_rate*100:.1f}% of assessments")
   ```

4. **Performance**
   ```python
   # Add timing to orchestrator._connection_processor_thread
   scoring_start = time.time()
   threat_score, threat_details = self.consensus_scorer.check_ip(...)
   scoring_time = time.time() - scoring_start

   if scoring_time > 1.0:
       logger.warning(f"Slow consensus scoring: {scoring_time:.3f}s")
   ```

---

## Rollback Plan

If consensus causes issues, easy rollback:

1. **Config-based disable:**
   ```python
   # config/consensus.conf
   [consensus]
   enable = false  # Falls back to old ip_reputation
   ```

2. **Code revert:**
   ```python
   # Simply comment out consensus initialization
   # self.consensus_scorer = ConsensusThreatScorer(...)
   self.consensus_scorer = None  # Forces fallback to ip_reputation
   ```

3. **No data loss:**
   - Old `connections` table unchanged
   - `consensus_assessments` table preserved for analysis
   - Can switch back and forth without corruption

---

## Success Criteria

Consensus integration is successful if:

1. **✓ Functional**: All 3 scorers produce assessments
2. **✓ Accurate**: Consensus scores align with threat intel (when available)
3. **✓ Resilient**: System handles scorer failures gracefully
4. **✓ Performant**: <100ms per assessment (no API bottleneck)
5. **✓ Observable**: Statistics available for monitoring
6. **✓ Reversible**: Can disable without data loss

---

## Next Steps

1. **Create integration test suite**
2. **Add consensus config to config/consensus.conf**
3. **Implement storage schema for consensus_assessments table**
4. **Modify orchestrator.py with defensive error handling**
5. **Run parallel comparison for 24 hours**
6. **Full cutover after validation**

---

**Status**: Consensus module COMPLETE, ready for integration testing
**Risk Level**: LOW (backward compatible, defensive design)
**Estimated Integration Time**: 2-4 hours with testing
