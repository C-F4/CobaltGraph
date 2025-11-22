# CobaltGraph Strategic Analysis & Implementation Roadmap
**Passive Edge Device Monitoring Architecture**

**Date:** 2025-11-17 (Corrected Architecture)
**Status:** Ready for Development
**Total Timeline:** 30-45 weeks | Resources: 1-2 engineers

---

## 🎯 VISION: Passive Network Intelligence Platform

**CobaltGraph for Edge Devices** is a passive network monitoring platform deployed on edge routers/firewalls that:
1. **Discovers all devices** on network segment via passive ARP monitoring
2. **Monitors all connections** they make via passive traffic capture
3. **Enriches with intelligence** - geolocation, threat scoring, origin analysis
4. **Scales to enterprise** - aggregates from multiple sites to central dashboard

**Key Principle:** Completely passive. No active scanning. Just listen to what's already broadcast.

---

## ⚡ THE KEY INSIGHT: ARP is Broadcast

**Why this works:**

When a device joins the network and sends an ARP request ("Who has 192.168.1.1?"), this is **broadcast on L2** - all devices on the segment hear it (including CobaltGraph).

**Passive Discovery = Zero Scanning Signatures**

```
Traditional active scanning:
  CobaltGraph → nmap -sP 192.168.1.0/24  (loud, detectable)

Passive ARP monitoring:
  Device sends: "Who has 192.168.1.1?"
  CobaltGraph hears it: Extract MAC, IP, Vendor
  No scanning tools, no traffic signatures
```

**This solves the network-wide visibility problem at the edge.**

---

## 🏗️ ARCHITECTURE: Two-Layer Monitoring

### **Layer 1: ARP Device Discovery (Passive)**
```
┌─────────────────────────────────────┐
│  ARP Broadcast (all devices hear)   │
│  "Who has 192.168.1.1?"             │
│         ↓                            │
│  CobaltGraph captures ARP packet         │
│  Extracts:                          │
│    - MAC address                    │
│    - IP address                     │
│    - Vendor (OUI lookup)            │
│    - Activity timestamp             │
│         ↓                            │
│  Stores in Device Inventory         │
│  ✓ No scanning, completely passive │
└─────────────────────────────────────┘
```

**What you get:** All devices on your LAN segment automatically

---

### **Layer 2: Traffic Analysis (Passive)**
```
┌─────────────────────────────────────┐
│  Device A → 8.8.8.8:53 (DNS query) │
│  Packet flows through edge router   │
│         ↓                            │
│  CobaltGraph captures packet headers     │
│  Extracts:                          │
│    - Source IP (192.168.1.50)      │
│    - Destination IP (8.8.8.8)      │
│    - Port (53)                      │
│    - Protocol (UDP)                 │
│    - Timestamp                      │
│         ↓                            │
│  Enriches:                          │
│    - GeoIP: 8.8.8.8 → Mountain View|
│    - Reputation: Google (trusted)  │
│    - Device: Apple (from ARP)      │
│         ↓                            │
│  Stores enriched connection        │
│  ✓ Knows which device, where, threat
└─────────────────────────────────────┘
```

**What you get:** Complete visibility of device connections + threat context

---

## 📊 DEPLOYMENT MODEL

### **Single Site**
```
┌──────────────────────────────────┐
│   LAN (192.168.1.0/24)           │
│                                   │
│  Device A ──┐                    │
│             ├─ Switch ─ CobaltGraph  │
│  Device B ──┤                (Edge) ├─→ Internet
│             │                    │
│  Device N ──┘                    │
│                                   │
│  CobaltGraph captures:                │
│  ✓ All ARP broadcasts (devices) │
│  ✓ All traffic (connections)    │
│  ✓ No active scanning            │
└──────────────────────────────────┘
```

### **Multi-Site Enterprise**
```
Site A              Site B              Central Dashboard
┌─────────────┐    ┌─────────────┐    ┌──────────────┐
│ Edge Router │    │ Edge Router │    │  Master UI   │
│ + CobaltGraph    ├───→│ + CobaltGraph    ├───→│ + Database   │
│ (Passive)   │    │ (Passive)   │    │ + Aggregation
└─────────────┘    └─────────────┘    └──────────────┘

Each edge sees local devices + all their connections
Central aggregates and correlates across all sites
```

---

## 📈 IMPLEMENTATION ROADMAP

### **Phase 0: Passive Device Discovery (2-3 weeks)**

**Goal:** Detect all devices on network segment without scanning

**Implementation:**
- Add ARP monitoring thread to `tools/grey_man.py`
- Listen on ARP socket (0x0806)
- Parse ARP packets: extract MAC, IP, vendor
- Store devices in database with timestamps
- Orchestrator handles device events

**Deliverables:**
- [ ] ARP monitoring in grey_man.py
- [ ] Device database schema (MAC, IP, vendor, first_seen, last_seen, activity_status)
- [ ] OUI vendor lookup database
- [ ] Device events: discovery, timeout, activity
- [ ] `/api/devices` endpoint for dashboard

**Code Changes:**
```
tools/grey_man.py
  + listen_for_arp()
  + parse_arp_packet()
  - emit device_discovery events

src/storage/models.py
  + Device dataclass (MAC, IP, vendor, timestamps, status)

src/storage/database.py
  + devices table
  + devices indexes (MAC, IP, last_seen)
  + device CRUD methods

src/core/orchestrator.py
  + handle device_discovery events
  + device lifecycle management

src/dashboard/server.py
  + GET /api/devices
  + GET /api/devices/{mac}
```

**Effort:** 2 engineers × 2-3 weeks

---

### **Phase 1: Device-Aware Dashboard (3-4 weeks)**

**Goal:** Visualize devices and their connections together

**Features:**
- Device inventory view (list all MACs, IPs, vendors)
- Per-device threat summary (which device connects to threats)
- Device activity timeline
- Device details panel (first seen, last seen, activity level)
- Connection history per device
- Filter connections by device

**Deliverables:**
- [ ] Device inventory page in dashboard
- [ ] Device detail view
- [ ] Per-device connection list
- [ ] Device threat summary cards
- [ ] Timeline of device activity

**Code Changes:**
```
src/dashboard/templates/
  + devices_inventory.html
  + device_detail.html

src/dashboard/server.py
  + GET /api/devices - list all devices
  + GET /api/devices/{mac}/connections - device connections
  + GET /api/devices/{mac}/stats - device statistics

src/storage/database.py
  + Query optimization for device filtering
```

**Effort:** 1 engineer × 3-4 weeks

---

### **Phase 2: Forensic Intelligence & Search (4-6 weeks)**

**Goal:** Deep investigation capabilities for incident response

**Features:**
- Search connections by date range, IP, country, threat level
- Full connection history (not just recent buffer)
- Timeline visualization
- Advanced filtering (protocol, port, vendor)
- Export to CSV/JSON for incident reports
- Threat drill-down (which service flagged it, details)

**Deliverables:**
- [ ] Advanced search interface
- [ ] Query builder UI
- [ ] Connection timeline view
- [ ] Export functionality (CSV, JSON)
- [ ] Threat drill-down details
- [ ] Database query optimization

**Effort:** 1-2 engineers × 4-6 weeks

---

### **Phase 3: Origin Tracing & DNS Correlation (5-8 weeks)**

**Goal:** Trace connections to true origins, resolve hostnames

**Features:**
- Reverse DNS lookup (IP → hostname)
- Hostname display in all views
- DNS query correlation (link domains to IPs over time)
- Passive DNS feed integration (optional, paid service)
- Proxy/CDN detection (flag CloudFlare, Akamai, etc.)
- VPN service detection
- Geographic hop mapping (optional, traceroute-based)

**Deliverables:**
- [ ] Reverse DNS integration
- [ ] DNS correlation module
- [ ] Hostname cache database
- [ ] Proxy/VPN detection logic
- [ ] Hostname display in UI
- [ ] DNS query timeline

**Effort:** 1-2 engineers × 5-8 weeks

---

### **Phase 4: Multi-Site Enterprise & Aggregation (8-12 weeks)**

**Goal:** Scale to enterprise with multiple edge devices reporting to central dashboard

**Features:**
- Central CobaltGraph master server (aggregate data from multiple edges)
- Agent mode for edge devices (report to central)
- Multi-tenant support (per-site views)
- Cross-site threat correlation (same IP seen at multiple sites)
- Central threat timeline across all sites
- Site-to-site suspicious patterns (compromised device in Site A talking to Site B)
- SIEM integration (push to Splunk, ELK, ArcSight)
- Alert rules engine (automatic threat detection)
- Webhook/REST API for automation
- Role-based access control (RBAC)

**Deliverables:**
- [ ] Central dashboard server
- [ ] Agent reporting API
- [ ] Multi-site aggregation database
- [ ] Cross-site correlation logic
- [ ] SIEM export modules
- [ ] Alert rules engine
- [ ] API documentation

**Effort:** 2 engineers × 8-12 weeks

---

### **Phase 5: Security Hardening & Production Ready (3-5 weeks)**

**Goal:** Production-grade system with security, performance, reliability

**Deliverables:**
- [ ] Apply all SEC patches (SEC-001 through SEC-008)
- [ ] External security audit
- [ ] Performance testing (throughput, latency, memory)
- [ ] High availability setup (redundant servers)
- [ ] Backup/disaster recovery procedures
- [ ] Docker containerization
- [ ] Kubernetes deployment manifests
- [ ] Terraform infrastructure as code
- [ ] Operational runbooks
- [ ] Security documentation
- [ ] Compliance mapping (SOC 2, NIST, CIS)

**Effort:** 1 security engineer + 1 DevOps × 3-5 weeks

---

## 📊 TIMELINE & RESOURCES

| Phase | Duration | Engineers | Key Deliverable |
|-------|----------|-----------|-----------------|
| **0** | 2-3 wks | 2 | Passive device discovery |
| **1** | 3-4 wks | 1 | Device-aware dashboard |
| **2** | 4-6 wks | 1-2 | Forensic search/export |
| **3** | 5-8 wks | 1-2 | Origin tracing |
| **4** | 8-12 wks | 2 | Multi-site enterprise |
| **5** | 3-5 wks | 1 + 1 | Production hardening |
| **TOTAL** | **25-38 wks** | **1-2 FTE** | **Working system** |

**Calendar:** 6-9 months from kickoff to full production system

---

## 🚀 MVP STRATEGY (Fastest Path to Value)

**Want a working system in 8-10 weeks?**

**Include:** Phases 0 + 1 + partial Phase 2
- ✅ Passive device discovery
- ✅ Device inventory dashboard
- ✅ Connection history per device
- ✅ Basic search/filtering
- ✅ CSV export

**Skip:** Advanced forensics, multi-site, DNS, enterprise features

**Then iterate:** Add enterprise features in subsequent releases

**Benefits:**
- Fast time to value (2 months)
- Validate architecture with real traffic
- Identify missing features from actual use
- Plan remaining phases with user feedback

---

## 🎯 KEY DECISIONS BEFORE STARTING

**1. Deployment Target**
- Single site or multiple sites?
- How many edge devices?
- Geographic distribution?

**2. Timeline Pressure**
- Need MVP in 8 weeks or can wait for 6-9 months?
- Affects phasing strategy

**3. Integration Requirements**
- Must integrate with existing SIEM now or later?
- Need alerting immediately or can add in Phase 4?
- Any compliance requirements (SOC 2, NIST)?

**4. Resource Availability**
- Can commit 1-2 full-time engineers?
- Do you have DevOps support for containerization?
- Can security team help with Phase 5?

**5. Budget**
- Any constraints on cloud infrastructure (central dashboard)?
- Will you use paid passive DNS feed (Phase 3) or open source?
- Third-party threat intel services already contracted?

---

## 💡 WHY THIS APPROACH WORKS

**Original Assumption:** Need active scanning for network-wide visibility
**New Reality:** Passive ARP monitoring discovers devices automatically

**Benefits of This Architecture:**
1. ✅ **Completely passive** - No scanning tools, no signatures, undetectable
2. ✅ **Works on any network** - Doesn't require special router capabilities
3. ✅ **Scales naturally** - Multiple sites → aggregate to central
4. ✅ **Faster to implement** - No complex multi-agent infrastructure
5. ✅ **More secure** - Can't be fingerprinted/detected by intruders
6. ✅ **Works with existing routers** - Any Linux-based firewall/router works

---

## 🔐 SECURITY TIMELINE

**Before production, must:**
- Phase 5: Apply all SEC patches (SEC-001 through SEC-008)
- Phase 4: Begin security hardening across modules
- Phase 3: Engage external firm for penetration testing
- Phases 0-2: Follow secure coding practices

**Pre-production acceptable during Phases 0-2** - vulnerabilities don't matter in testing

---

## 📚 DOCUMENTATION TO PRODUCE

For implementation, you'll need:

```
docs/next-steps_11-25-25/
├── INDEX.md (this overview)
├── PHASE0_ARP_MONITORING.md
│   ├── Technical implementation
│   ├── Code changes required
│   └── Database schema design
├── PHASE1_DASHBOARD.md
│   ├── UI mockups
│   ├── API endpoints
│   └── Database queries
├── MULTI_SITE_ARCHITECTURE.md
│   ├── Agent/central design
│   └── Data replication
├── DEPLOYMENT_GUIDE.md
│   ├── Edge router setup
│   ├── Docker deployment
│   └── Production checklist
└── SECURITY_IMPLEMENTATION.md
    ├── Patch application
    └── Hardening guide
```

---

## ✅ WHAT YOU GET AT EACH MILESTONE

**After Phase 0 (3 weeks):**
- ✅ Passive device detection works
- ✅ Device inventory in database
- ✅ Basic device list in dashboard

**After Phase 1 (7 weeks):**
- ✅ Device inventory UI complete
- ✅ Can see which device connects where
- ✅ Per-device threat summary
- ✅ MVP deployable for testing

**After Phase 2 (13 weeks):**
- ✅ Full connection history searchable
- ✅ Advanced filtering works
- ✅ Can investigate incidents
- ✅ Export capabilities

**After Phase 3 (21 weeks):**
- ✅ Hostnames resolved
- ✅ Origin tracing works
- ✅ Deep forensic investigation possible
- ✅ Ready for SOC analysts

**After Phase 4 (33 weeks):**
- ✅ Multi-site monitoring
- ✅ Enterprise threat correlation
- ✅ SIEM integration
- ✅ Scalable architecture

**After Phase 5 (38 weeks):**
- ✅ Production-ready
- ✅ Hardened for security
- ✅ High availability
- ✅ Enterprise compliance ready

---

## 🎯 NEXT IMMEDIATE ACTIONS

**This Week:**
- [ ] Review this roadmap with stakeholders
- [ ] Confirm Phases 0-1 priority
- [ ] Identify engineering resources
- [ ] Schedule kickoff meeting

**Next Week:**
- [ ] Create detailed Phase 0 technical spec
- [ ] Design device database schema
- [ ] Prototype ARP packet parsing
- [ ] Mock up device inventory UI

**Week 3:**
- [ ] Begin Phase 0 implementation
- [ ] Establish sprint rhythm (2-week sprints)
- [ ] Set up dev/test environment
- [ ] First ARP packets captured

---

## 📞 ARCHITECTURE VALIDATION QUESTIONS

Before you commit resources:

1. **Is edge router/firewall the right deployment location?**
   - Can we install Python + CobaltGraph there?
   - Does it have internet access?
   - What's the Linux OS (OpenWrt, Ubuntu, custom)?

2. **What's the local network size?**
   - 10 devices or 1000 devices?
   - Affects database size + query performance

3. **What threats are you trying to detect?**
   - Compromised devices calling to C2?
   - Lateral movement between sites?
   - Exfiltration to unexpected locations?
   - This shapes intelligence integration

4. **Existing infrastructure?**
   - Do you have SIEM already?
   - Can you host central dashboard (cloud or on-prem)?
   - Existing threat feeds or APIs?

---

**This roadmap is ready for engineering kickoff.**

**Next: Create detailed Phase 0 technical specification document.**

---

*Passive network intelligence via ARP monitoring. Zero scanning. Complete visibility.*
