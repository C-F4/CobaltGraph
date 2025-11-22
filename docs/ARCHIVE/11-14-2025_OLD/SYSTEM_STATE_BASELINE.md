# CobaltGraph - System State Baseline & Development Roadmap

**Date**: November 11, 2025
**Status**: PARTIAL IMPLEMENTATION - Core infrastructure exists, critical gaps identified
**Honesty Level**: MAXIMUM - No bullshit

---

## 🚨 **CRITICAL REALITY CHECK**

### **What We Said We Had:**
- ✅ "Full system orchestrator"
- ✅ "Threat intelligence integration"
- ✅ "Anomaly detection"
- ✅ "Production-ready"

### **What Actually Works:**
- ✅ System starts without errors
- ✅ Dashboard loads and displays
- ⚠️ Capture pipeline starts BUT may not be feeding data
- ⚠️ Threat scoring exists BUT is mostly a stub (returns 0.2 for everything)
- ❌ NO real anomaly detection implemented
- ❌ Data may not be flowing end-to-end

**Brutal Truth**: We have a FRAMEWORK, not a working system.

---

## ✅ **WHAT ACTUALLY WORKS** (Verified)

### **1. Infrastructure Layer** ✅
**Status**: SOLID - Core plumbing is good

- ✅ **Orchestrator** (`src/core/orchestrator.py`)
  - Starts capture subprocess
  - Creates processing threads
  - Manages lifecycle
  - Handles shutdown gracefully

- ✅ **Platform Detection** (`src/utils/platform.py`)
  - OS detection (Linux, WSL, macOS, Windows)
  - Root privilege checking
  - Capability detection
  - **Actually integrated and working**

- ✅ **Database** (`src/storage/database.py`)
  - SQLite connection
  - Schema creation
  - Thread-safe operations
  - Connection storage

- ✅ **Dashboard Server** (`src/dashboard/server.py`)
  - HTTP server on port 8080
  - Serves dashboard HTML
  - API endpoints (/api/data, /api/health)
  - Authentication support

- ✅ **Configuration** (`src/core/config.py`)
  - Loads config files
  - Environment variable overrides
  - Validation and defaults

- ✅ **Supervisor** (`src/core/supervisor.py`)
  - Auto-restart on crash
  - Exponential backoff
  - Crash vs clean shutdown detection
  - **Fully implemented**

---

## ⚠️ **WHAT PARTIALLY WORKS** (Has Issues)

### **2. Capture Pipeline** ⚠️
**Status**: QUESTIONABLE - Code exists, data flow unverified

#### **Capture Tools** (2/5 available)
- ✅ `tools/grey_man.py` - Raw packet capture
  - **Status**: Code exists
  - **Issue**: Not tested if actually outputting data
  - **Requires**: Root privileges, Linux AF_PACKET

- ✅ `tools/network_capture.py` - ss-based capture
  - **Status**: Code exists
  - **Issue**: May not be detecting new connections
  - **Requires**: ss command (device mode)

#### **Data Flow** ⚠️
```
Capture Tool (subprocess)
    ↓ [stdout JSON]
Orchestrator._capture_reader_thread()
    ↓ [Queue]
Orchestrator._connection_processor_thread()
    ↓ [Enrichment]
Database
    ↓ [Buffer]
Dashboard API
```

**Issues Identified:**
1. ❓ Capture may not be outputting JSON correctly
2. ❓ stdin reader may not be triggering
3. ❓ No verification that data reaches database
4. ❓ Dashboard shows "No connections" - is this normal or broken?

---

## ❌ **WHAT DOESN'T WORK** (Critical Gaps)

### **3. Threat Intelligence** ❌
**Status**: STUB - Exists but useless without API keys

#### **IP Reputation** (`src/intelligence/ip_reputation.py`)
```python
def check_ip(self, ip: str) -> Tuple[float, Dict]:
    # Tries VirusTotal API → Needs API key ❌
    # Tries AbuseIPDB API → Needs API key ❌
    # Falls back to local → Returns 0.2 (hardcoded) ❌
```

**Reality:**
- ✅ Code structure is good
- ❌ No API keys configured
- ❌ "Local threat scoring" is just `return 0.2`
- ❌ No actual heuristic logic

**What This Means:**
- EVERY IP gets threat_score = 0.2
- No differentiation between Google DNS and malware C2
- Completely useless in current state

---

### **4. Anomaly Detection** ❌
**Status**: DOES NOT EXIST

#### **What We Claimed:**
- ML-based anomaly detection
- Neural network integration
- Behavioral analysis

#### **What Actually Exists:**
- ❌ `tools/neural_client.py` - Just an IPC wrapper for non-existent Rust engine
- ❌ No Python ML implementation
- ❌ No sklearn, tensorflow, pytorch
- ❌ No training data
- ❌ No baseline behavior tracking
- ❌ No statistical analysis

**Reality Check:**
There is ZERO anomaly detection. Not even basic rules.

---

### **5. Geo Enrichment** ⚠️
**Status**: EXISTS - But rate-limited and slow

#### **GeoEnrichment** (`src/intelligence/geo_enrichment.py`)
- ✅ Uses ip-api.com (free, no key)
- ⚠️ Rate limited: 45 requests/minute
- ⚠️ Synchronous (blocks on each lookup)
- ⚠️ No batching
- ⚠️ No caching

**Impact:**
- Slow processing if many connections
- May hit rate limits quickly
- No offline database (MaxMind GeoLite2)

---

### **6. Data Models** ⚠️
**Status**: INTEGRATED but not fully utilized

#### **Connection Model** (`src/storage/models.py`)
- ✅ Dataclass defined
- ✅ Integrated in orchestrator
- ⚠️ Not used consistently everywhere
- ⚠️ Dashboard still uses dicts

**Minor Issue** - Easy to fix

---

## 📊 **MODULE INTEGRATION STATUS**

### **Integrated** (13/25 modules = 52%)
1. ✅ src/core/orchestrator.py - Main coordinator
2. ✅ src/core/launcher.py - CLI entry
3. ✅ src/core/config.py - Configuration
4. ✅ src/core/supervisor.py - Auto-restart
5. ✅ src/storage/database.py - SQLite
6. ✅ src/storage/models.py - Data models
7. ✅ src/intelligence/geo_enrichment.py - Geolocation
8. ✅ src/intelligence/ip_reputation.py - Threat intel (stub)
9. ✅ src/dashboard/server.py - HTTP server
10. ✅ src/utils/heartbeat.py - Health monitoring
11. ✅ src/utils/errors.py - Exceptions
12. ✅ src/utils/platform.py - Platform detection
13. ✅ tools/grey_man.py - Network capture
14. ✅ tools/network_capture.py - Device capture

### **Not Integrated** (12/25 modules = 48%)
- ❌ src/core/watchfloor.py - Old system (superseded)
- ❌ src/storage/migrations.py - Not needed yet
- ❌ src/dashboard/api.py - Stub only
- ❌ src/dashboard/handlers.py - Unclear purpose
- ❌ src/dashboard/templates.py - Unused
- ❌ src/utils/logging.py - Not using
- ❌ src/utils/logging_config.py - Not using
- ❌ tools/neural_client.py - No Rust engine
- ❌ tools/wsl_recon.py - Not integrated
- ❌ tools/ultrathink_modified.py - Not integrated
- ❌ src/terminal/ultrathink.py - Not integrated
- ❌ src/capture/* - Legacy/fallback

---

## 🎯 **DEVELOPMENT ROADMAP**

### **PHASE 1: MAKE IT ACTUALLY WORK** (Critical - 1 week)
**Goal**: End-to-end data flow with basic threat detection

#### **Priority 1.1: Fix Data Flow** 🔥
**Status**: CRITICAL
**Effort**: 1-2 days

**Tasks:**
1. ✅ Verify capture tools output JSON correctly
   ```bash
   # Test directly:
   sudo python3 tools/grey_man.py | head -5
   # Should see JSON lines
   ```

2. ✅ Add debugging to orchestrator
   ```python
   # In _capture_reader_thread:
   logger.info(f"📥 Received line: {line[:100]}")

   # In _connection_processor_thread:
   logger.info(f"🔄 Processing connection: {src_ip} -> {dst_ip}:{dst_port}")

   # After database insert:
   logger.info(f"💾 Stored in database (ID: {id})")
   ```

3. ✅ Add real-time monitoring
   ```bash
   # Watch database grow:
   watch -n 1 'sqlite3 data/cobaltgraph.db "SELECT COUNT(*) FROM connections"'

   # Watch recent connections:
   watch -n 5 'sqlite3 data/cobaltgraph.db "SELECT src_ip, dst_ip, dst_port, timestamp FROM connections ORDER BY timestamp DESC LIMIT 5"'
   ```

4. ✅ Fix stdin piping if broken
   - Check if stdin.isatty() is working correctly
   - May need to explicitly set stdin to non-blocking

**Success Criteria:**
- ✅ Capture outputs JSON
- ✅ Orchestrator logs "Processing connection"
- ✅ Database row count increases
- ✅ Dashboard shows real connections
- ✅ Can verify with `curl http://localhost:8080/api/data`

---

#### **Priority 1.2: Implement Real Threat Scoring** 🔥
**Status**: CRITICAL
**Effort**: 1 day

**Current State:**
```python
def _local_threat_score(self, ip: str) -> float:
    return 0.2  # ❌ USELESS
```

**Replacement: Rule-Based Threat Scoring**
```python
class LocalThreatScorer:
    """Heuristic-based threat scoring (no API required)"""

    def __init__(self):
        # Known malicious port patterns
        self.suspicious_ports = {
            3389: 0.4,   # RDP (often attacked)
            445: 0.5,    # SMB (WannaCry, ransomware)
            22: 0.3,     # SSH (brute force target)
            23: 0.6,     # Telnet (insecure, IoT malware)
            135: 0.4,    # MS-RPC (exploited)
            139: 0.4,    # NetBIOS
            1433: 0.4,   # MS-SQL (data theft)
            3306: 0.4,   # MySQL (data theft)
            5900: 0.4,   # VNC (remote access)
            6379: 0.5,   # Redis (often unsecured)
            27017: 0.5,  # MongoDB (data leaks)
        }

        # High-risk countries (geopolitical threat sources)
        self.threat_countries = {
            'Russia': 0.3,
            'China': 0.2,
            'North Korea': 0.6,
            'Iran': 0.3,
        }

        # Known malicious IP ranges (example)
        self.malicious_ranges = [
            # Add known botnet C2 ranges
            # Add tor exit nodes if policy requires
        ]

        # Connection pattern tracking
        self.baseline = {}  # IP -> {'count': N, 'first_seen': timestamp}

    def score_connection(self, connection: Dict) -> float:
        """
        Calculate threat score (0.0-1.0)

        Factors:
        - Destination port
        - Geographic location
        - Connection patterns
        - Time of day
        - Frequency
        """
        score = 0.0

        # 1. Port-based scoring
        dst_port = connection.get('dst_port', 0)
        score += self.suspicious_ports.get(dst_port, 0.0)

        # 2. Country-based scoring
        country = connection.get('country', '')
        score += self.threat_countries.get(country, 0.0)

        # 3. First-time connection penalty
        dst_ip = connection['dst_ip']
        if dst_ip not in self.baseline:
            self.baseline[dst_ip] = {
                'count': 0,
                'first_seen': time.time()
            }
            score += 0.1  # New destination

        # 4. Connection frequency
        self.baseline[dst_ip]['count'] += 1
        count = self.baseline[dst_ip]['count']

        if count > 100:  # Very frequent
            score -= 0.1  # Likely legitimate (Google, CDN, etc.)
        elif count == 1:  # Very first time
            score += 0.05  # Slightly suspicious

        # 5. Time-based heuristics
        hour = datetime.now().hour
        if 2 <= hour <= 5:  # 2-5 AM
            score += 0.1  # Unusual time for legit traffic

        # 6. Port in ephemeral range for destination
        if 49152 <= dst_port <= 65535:
            score -= 0.05  # Less suspicious (client port)

        # 7. Common services (reduce score)
        common_ports = {80, 443, 53, 853, 8080, 8443}
        if dst_port in common_ports:
            score -= 0.1

        # Normalize to 0.0-1.0
        return max(0.0, min(1.0, score))
```

**Implementation Plan:**
1. Create `src/intelligence/local_threat_scorer.py`
2. Integrate into `IPReputationManager._local_threat_score()`
3. Add configuration for thresholds
4. Test with known good/bad IPs

**Expected Results:**
- Google DNS (8.8.8.8:443) → 0.0-0.1 (clean)
- Random IP on RDP → 0.4-0.5 (suspicious)
- China IP on telnet → 0.6-0.8 (high threat)

---

#### **Priority 1.3: Add Connection Pattern Tracking** 🔥
**Status**: CRITICAL for useful anomaly detection
**Effort**: 1 day

**Implement:**
```python
class ConnectionPatternTracker:
    """Track connection patterns for anomaly detection"""

    def __init__(self):
        self.ip_profiles = {}  # IP -> profile
        self.port_profiles = defaultdict(set)  # Port -> set of IPs
        self.time_profiles = {}  # Hour -> connection count

    def update(self, connection):
        """Update profiles with new connection"""
        dst_ip = connection['dst_ip']
        dst_port = connection['dst_port']
        hour = datetime.now().hour

        # Build IP profile
        if dst_ip not in self.ip_profiles:
            self.ip_profiles[dst_ip] = {
                'ports': set(),
                'count': 0,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'avg_interval': 0,
            }

        profile = self.ip_profiles[dst_ip]
        profile['ports'].add(dst_port)
        profile['count'] += 1
        profile['last_seen'] = time.time()

        # Update port profile
        self.port_profiles[dst_port].add(dst_ip)

        # Update time profile
        self.time_profiles[hour] = self.time_profiles.get(hour, 0) + 1

    def detect_anomalies(self, connection) -> List[str]:
        """Detect anomalies in connection pattern"""
        anomalies = []

        dst_ip = connection['dst_ip']
        dst_port = connection['dst_port']

        # Anomaly 1: Port scanning (many ports, same IP)
        if dst_ip in self.ip_profiles:
            ports = self.ip_profiles[dst_ip]['ports']
            if len(ports) > 10:  # Accessing > 10 different ports
                anomalies.append('port_scanning')

        # Anomaly 2: New service (rare port)
        if dst_port > 1024 and dst_port not in self.port_profiles:
            anomalies.append('uncommon_port')

        # Anomaly 3: Burst activity (many connections in short time)
        if dst_ip in self.ip_profiles:
            profile = self.ip_profiles[dst_ip]
            age = time.time() - profile['first_seen']
            rate = profile['count'] / max(age, 1)
            if rate > 10:  # >10 connections per second
                anomalies.append('high_frequency')

        return anomalies
```

**Integration:**
- Add to orchestrator
- Update threat score based on anomalies
- Log anomalies to database
- Show in dashboard

---

### **PHASE 2: ENHANCE & POLISH** (Important - 2 weeks)
**Goal**: Production-ready monitoring with useful features

#### **Priority 2.1: WSL Integration** ⭐⭐⭐
**Effort**: 4 hours

- Integrate `tools/wsl_recon.py`
- Detect WSL environment automatically
- Use Windows tools (Wireshark, Nmap) from WSL
- Enhanced capture capabilities

#### **Priority 2.2: Offline Geo Database** ⭐⭐⭐
**Effort**: 2 hours

- Download MaxMind GeoLite2 (free)
- Replace ip-api.com for lookups
- No rate limits
- Instant lookups
- Privacy-friendly (no external calls)

#### **Priority 2.3: Caching Layer** ⭐⭐
**Effort**: 4 hours

- Cache geo lookups (TTL: 24h)
- Cache threat scores (TTL: 1h)
- Reduce API calls by 90%
- Faster processing

#### **Priority 2.4: Better Logging** ⭐⭐
**Effort**: 2 hours

- Integrate `src/utils/logging_config.py`
- Structured logging (JSON)
- Log rotation
- Separate log files (capture, threats, errors)

---

### **PHASE 3: ADVANCED FEATURES** (Optional - 1 month)
**Goal**: Enterprise-grade monitoring with ML

#### **Priority 3.1: Simple Python ML** ⭐⭐⭐⭐
**Effort**: 1 week

**Implement sklearn-based anomaly detection:**
```python
from sklearn.ensemble import IsolationForest

class MLAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05)
        self.fitted = False

    def train(self, connections):
        """Train on historical data"""
        features = self._extract_features(connections)
        self.model.fit(features)
        self.fitted = True

    def predict(self, connection):
        """Predict anomaly score"""
        if not self.fitted:
            return 0.0
        features = self._extract_features([connection])
        score = self.model.decision_function(features)[0]
        return 1.0 - normalize(score)  # 0=normal, 1=anomaly

    def _extract_features(self, connections):
        """Extract numerical features"""
        features = []
        for conn in connections:
            features.append([
                conn['dst_port'],
                conn.get('dst_lat', 0),
                conn.get('dst_lon', 0),
                datetime.now().hour,
                # ... more features
            ])
        return np.array(features)
```

**Benefits:**
- Real ML-based anomaly detection
- Auto-adapts to normal behavior
- No manual rule tuning

**Requirements:**
- Install: `pip install scikit-learn numpy`
- Training data: Need 1000+ connections
- Periodic retraining

#### **Priority 3.2: Terminal UI** ⭐⭐
**Effort**: 1 week

- Integrate `src/terminal/ultrathink.py`
- Ncurses-based TUI
- Alternative to web dashboard
- Real-time updates

#### **Priority 3.3: Export & Reporting** ⭐⭐⭐
**Effort**: 3 days

- CSV export
- JSON export
- Automated reports
- Email alerts on high threats

#### **Priority 3.4: API Enhancements** ⭐⭐
**Effort**: 2 days

- REST API for external tools
- GraphQL endpoint
- Webhooks
- Real-time WebSocket stream

---

## 🎯 **REALISTIC MILESTONES**

### **Milestone 1: Basic Working System** (1 week)
**Deliverables:**
- ✅ Data flows end-to-end
- ✅ Dashboard shows real connections
- ✅ Basic threat scoring works
- ✅ Can detect suspicious ports/countries
- ✅ Database populates
- ✅ Verified with test traffic

**Success Metric:**
- Generate traffic → See it in dashboard within 5 seconds
- Threat score > 0.5 for known bad IPs/ports
- Database has > 100 connections

---

### **Milestone 2: Production-Ready** (2 weeks)
**Deliverables:**
- ✅ All Phase 1 complete
- ✅ WSL integration (if on WSL)
- ✅ Offline geo database
- ✅ Caching implemented
- ✅ Proper logging
- ✅ Auto-restart tested
- ✅ Documentation complete

**Success Metric:**
- Runs for 24 hours without crash
- Processes 10,000+ connections
- Threat detection accuracy > 80%
- No false positives on Google/Cloudflare

---

### **Milestone 3: Advanced Features** (1 month)
**Deliverables:**
- ✅ ML anomaly detection
- ✅ Terminal UI
- ✅ Export functionality
- ✅ API endpoints
- ✅ Comprehensive testing

**Success Metric:**
- ML model achieves > 90% accuracy
- Can detect zero-day patterns
- Full API documentation
- Production deployment guide

---

## 🚨 **CRITICAL ACTIONS - NEXT 24 HOURS**

### **IMMEDIATE PRIORITY:**

1. **Verify Data Flow** 🔥
   ```bash
   # Test capture directly:
   sudo timeout 10s python3 tools/network_capture.py
   # Should see JSON output

   # Test orchestrator:
   sudo python3 start.py --mode device
   # Open dashboard, generate traffic (curl google.com)
   # Should see connections appear
   ```

2. **Add Debugging** 🔥
   ```python
   # Edit orchestrator.py, add:
   logger.setLevel(logging.DEBUG)

   # Add logging at each stage:
   # - Capture read
   # - Queue put
   # - Queue get
   # - Processing start
   # - Database insert
   # - Buffer add
   ```

3. **Implement Real Threat Scoring** 🔥
   - Create `src/intelligence/local_threat_scorer.py`
   - Replace hardcoded 0.2
   - Test with known IPs

---

## 📈 **METRICS TO TRACK**

### **System Health:**
- Uptime
- Connections processed
- Processing rate (conn/sec)
- Database size
- Memory usage
- CPU usage

### **Threat Detection:**
- Total threats detected
- High-threat IPs (score > 0.7)
- Most common threat types
- False positive rate
- Geographic threat distribution

### **Performance:**
- Capture lag
- Processing latency (capture → dashboard)
- API response time
- Geo lookup time
- Database query time

---

## 💡 **LESSONS LEARNED**

### **What Went Right:**
- ✅ Modular architecture is solid
- ✅ Clean separation of concerns
- ✅ Good foundation for expansion
- ✅ Documentation is thorough

### **What Went Wrong:**
- ❌ Claimed features that don't exist
- ❌ Didn't verify end-to-end data flow
- ❌ Threat scoring is a stub
- ❌ No real anomaly detection
- ❌ Over-optimistic about completion

### **What To Do Differently:**
- ✅ Test data flow FIRST
- ✅ Implement core features before polish
- ✅ Verify claims with actual tests
- ✅ Set realistic expectations
- ✅ Focus on working system > fancy features

---

## 🎯 **FINAL ASSESSMENT**

### **Current State:**
**Grade: C+ (Framework exists, functionality unverified)**

**Strengths:**
- Good architecture
- Clean code
- Modular design
- Comprehensive planning

**Weaknesses:**
- Unverified data flow
- Stub implementations
- No real anomaly detection
- Unclear if actually working

### **Potential:**
**Grade: A (Can become excellent system)**

With 1-2 weeks of focused work on Phase 1, this can become a genuinely impressive network monitoring system.

---

## 📋 **NEXT SESSION AGENDA**

1. **Test data flow** (30 min)
   - Run capture manually
   - Verify JSON output
   - Check database

2. **Fix any data flow issues** (1-2 hours)
   - Debug capture
   - Fix stdin piping
   - Verify end-to-end

3. **Implement real threat scoring** (2-3 hours)
   - Create LocalThreatScorer
   - Port-based rules
   - Country-based rules
   - Test with real traffic

4. **Add pattern tracking** (2 hours)
   - Connection profiles
   - Anomaly detection
   - Alert generation

**Total Time: 1 day of focused work to get to "actually working"**

---

## 🎉 **CONCLUSION**

**Honest Assessment:**
- We have a GOOD FOUNDATION
- But NOT a working system yet
- Critical gaps in implementation
- 1 week away from "actually impressive"

**Recommended Action:**
Focus on Phase 1 (Make It Work) before adding features.

**The Good News:**
The architecture is solid. Once data flows and threat scoring works, the rest is easy.

---

**END OF BASELINE DOCUMENT**
**Next Review: After Phase 1 completion**
