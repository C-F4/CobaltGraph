# CobaltGraph Implementation Plan - Phase-by-Phase Execution
**Date:** 2025-11-19
**Status:** Ready for Development Kickoff
**Total Duration:** 30-45 weeks | Resources: 1-2 engineers full-time
**MVP Milestone:** Week 10 (Phases 0-1 complete)

---

## 📋 EXECUTIVE SUMMARY

CobaltGraph is transitioning from architectural planning (complete) to development execution. This plan organizes the 5-phase roadmap into specific, actionable tasks for a cyber-security engineering team.

**Current State:**
- ✅ Architecture validated (edge router deployment with passive ARP)
- ✅ High-level roadmap created (Phases 0-5)
- ✅ Strategic requirements documented
- ⏳ **NEXT:** Detailed technical specifications needed
- ⏳ **NEXT:** Team assignments and sprint planning
- ⏳ **NEXT:** Development kickoff with Phase 0

---

## 🎯 IMPLEMENTATION OBJECTIVES

### Primary Goals
1. **Phase 0 Complete (Weeks 1-3):** Passive device discovery operational
2. **Phase 1 Complete (Weeks 4-7):** MVP dashboard with device inventory
3. **MVP Validated (Week 10):** Ready for production testing environment
4. **Phases 2-3 (Weeks 11-21):** Advanced forensics and origin tracing
5. **Phase 4 (Weeks 22-33):** Multi-site enterprise aggregation
6. **Phase 5 (Weeks 34-38):** Production security hardening

### Success Criteria
- All passive monitoring working without false positives
- Dashboard responsive with <500ms query times
- 99% availability in test environment
- All security patches applied before production
- Documentation complete for operations team

---

## 📊 PHASE 0: PASSIVE DEVICE DISCOVERY (Weeks 1-3)

### Overview
Implement automatic device detection via passive ARP monitoring on network segment.

### High-Level Goals
- [ ] ARP packet capture in grey_man.py
- [ ] Device inventory database schema
- [ ] OUI vendor lookup integration
- [ ] Dashboard device list API endpoint

### Structurable Tasks

#### Task 0.1: Database Schema Design
**Duration:** 2-3 days | **Owner:** Lead Engineer
**Prerequisites:** None

**Deliverables:**
- [ ] Database migration for `devices` table
- [ ] Schema includes: MAC, IP, hostname, vendor, device_type, first_seen, last_seen, last_activity, status (online/offline), confidence_score
- [ ] Indexes on MAC (primary), IP, last_seen
- [ ] Device state machine (discovered → active → idle → offline)

**Implementation Checklist:**
```
[ ] Create migration file: src/storage/migrations/001_device_inventory.sql
[ ] Define Device dataclass in src/storage/models.py
[ ] Add CRUD methods to src/storage/database.py
[ ] Add device lifecycle management to orchestrator
[ ] Write unit tests for database operations (target: >95% coverage)
```

**Dependencies:**
- Current database structure (review existing schema)
- Python dataclass patterns used in codebase

**Related Files:**
- `src/storage/models.py` - Add Device dataclass
- `src/storage/database.py` - Add device table + methods
- `src/core/orchestrator.py` - Device lifecycle handler

---

#### Task 0.2: ARP Monitoring Implementation
**Duration:** 4-5 days | **Owner:** Lead Engineer + Junior
**Prerequisites:** Task 0.1 (database schema)

**Deliverables:**
- [ ] ARP packet listener thread in grey_man.py
- [ ] ARP packet parser (extract MAC, IP, vendor OUI)
- [ ] Device discovery event emitter
- [ ] Handles ARP requests and replies

**Implementation Checklist:**
```
[ ] Implement listen_for_arp() in tools/grey_man.py
[ ] Create parse_arp_packet(raw_packet) function
[ ] Add ARP event handler to orchestrator
[ ] Implement device_discovered event emission
[ ] Add OUI lookup using existing vendor database
[ ] Handle duplicate/updated ARP entries
[ ] Add logging for ARP packet processing
[ ] Write integration tests for ARP capture
```

**Key Code Patterns:**
```python
# Expected structure
class ARPMonitor:
    def listen_for_arp(self):
        """Capture ARP packets on socket 0x0806"""

    def parse_arp_packet(self, raw_packet):
        """Extract MAC, IP, vendor from ARP packet"""
        return {
            'mac': '00:11:22:33:44:55',
            'ip': '192.168.1.50',
            'vendor': 'Apple Inc.',
            'timestamp': <epoch>,
            'arp_type': 'request|reply'
        }
```

**Dependencies:**
- scapy or raw socket handling (review existing network code)
- OUI database (MAC vendor lookup)
- Event system in orchestrator

**Related Files:**
- `tools/grey_man.py` - Main implementation
- `src/core/orchestrator.py` - Event handling
- `src/utils/oui_lookup.py` - Vendor database (create if needed)

---

#### Task 0.3: OUI Vendor Lookup Database
**Duration:** 2 days | **Owner:** Junior Engineer
**Prerequisites:** Task 0.1

**Deliverables:**
- [ ] OUI database integration
- [ ] Fast lookup by MAC prefix (O(1) via hash)
- [ ] Fallback for unknown vendors
- [ ] Regular update mechanism (quarterly)

**Implementation Checklist:**
```
[ ] Integrate IEEE OUI database (public source)
[ ] Load OUI data into in-memory cache or database table
[ ] Implement MAC-to-vendor lookup function
[ ] Add caching layer for lookups
[ ] Write function to refresh OUI database quarterly
[ ] Handle edge cases (locally administered MACs, etc.)
[ ] Unit tests for lookup accuracy
```

**Sources:**
- IEEE OUI database: https://standards-oui.ieee.org/oui/oui.csv
- Alternative: Python `mac_vendor_lookup` library (evaluate licensing)

**Related Files:**
- `src/utils/oui_lookup.py` - Create new file
- Database table for OUI (if not using external library)

---

#### Task 0.4: Device Event System
**Duration:** 3 days | **Owner:** Lead Engineer
**Prerequisites:** Tasks 0.1, 0.2

**Deliverables:**
- [ ] Device discovery event type
- [ ] Device activity event type
- [ ] Device timeout/offline event type
- [ ] Event handlers in orchestrator
- [ ] Event logging/audit trail

**Implementation Checklist:**
```
[ ] Define device_discovered event schema
[ ] Define device_activity event schema
[ ] Define device_offline event schema
[ ] Add event handlers to orchestrator.py
[ ] Implement device timeout logic (30 min no activity = offline)
[ ] Add device state transitions
[ ] Create audit log for device changes
[ ] Write tests for event ordering
```

**Event Schema Example:**
```python
DeviceDiscoveredEvent = {
    'event_type': 'device_discovered',
    'mac': '00:11:22:33:44:55',
    'ip': '192.168.1.50',
    'vendor': 'Apple Inc.',
    'timestamp': <iso8601>,
    'source': 'arp_monitor'
}
```

**Related Files:**
- `src/core/orchestrator.py` - Event handlers
- `src/storage/models.py` - Event dataclasses
- `src/storage/database.py` - Audit trail table

---

#### Task 0.5: API Endpoint for Device List
**Duration:** 2 days | **Owner:** Junior Engineer
**Prerequisites:** Tasks 0.1, 0.4

**Deliverables:**
- [ ] GET `/api/devices` - List all devices
- [ ] GET `/api/devices/{mac}` - Device details
- [ ] Query parameters: filter by vendor, status, activity
- [ ] Response format includes all device fields

**Implementation Checklist:**
```
[ ] Create device routes in src/dashboard/server.py
[ ] Implement /api/devices endpoint (paginated, sortable)
[ ] Implement /api/devices/{mac} endpoint
[ ] Add filtering parameters (vendor, status, last_seen)
[ ] Add error handling and validation
[ ] Write API documentation
[ ] Create unit tests for endpoints (>90% coverage)
[ ] Load test for 1000+ devices
```

**Expected Response Format:**
```json
{
  "devices": [
    {
      "mac": "00:11:22:33:44:55",
      "ip": "192.168.1.50",
      "vendor": "Apple Inc.",
      "status": "online",
      "first_seen": "2025-11-19T10:00:00Z",
      "last_seen": "2025-11-19T10:45:30Z",
      "activity_level": "high",
      "connection_count": 42
    }
  ],
  "total": 47,
  "page": 1
}
```

**Related Files:**
- `src/dashboard/server.py` - API endpoints
- `src/dashboard/templates/` - Dashboard update

---

#### Task 0.6: Dashboard Device List UI
**Duration:** 2 days | **Owner:** Frontend/UI Engineer
**Prerequisites:** Task 0.5

**Deliverables:**
- [ ] Device list table in dashboard
- [ ] Sorting by MAC, IP, vendor, status
- [ ] Filtering by vendor, status
- [ ] Search by IP or MAC
- [ ] Color coding: online (green), idle (yellow), offline (gray)
- [ ] Real-time updates (auto-refresh every 30 seconds)

**Implementation Checklist:**
```
[ ] Create devices_inventory.html template
[ ] Add CSS for device list table
[ ] Implement sorting (client-side for <1000 devices)
[ ] Add search bar for MAC/IP filtering
[ ] Add vendor filter dropdown
[ ] Add status filter (online/offline)
[ ] Implement auto-refresh (30 sec interval)
[ ] Add click-to-details functionality
[ ] Write frontend tests
[ ] Mobile responsive design
```

**UI Mockup Structure:**
```
┌─ Devices Inventory ─────────────────────┐
│ 🔍 Search  [Filter: Vendor] [Status: All] │
├─────────────────────────────────────────┤
│ MAC         IP           Vendor    Status│
├─────────────────────────────────────────┤
│ AA:BB...    192.168.1.5  Apple     ● Online
│ CC:DD...    192.168.1.10 Samsung   ● Online
│ EE:FF...    192.168.1.15 Unknown   ◐ Idle
│ 11:22...    192.168.1.20 Cisco     ○ Offline
└─────────────────────────────────────────┘
```

**Related Files:**
- `src/dashboard/templates/devices_inventory.html` - Create
- `src/dashboard/static/css/devices.css` - Create
- `src/dashboard/static/js/devices.js` - Create

---

#### Task 0.7: Testing & Validation
**Duration:** 2-3 days | **Owner:** QA/Test Engineer
**Prerequisites:** All other Phase 0 tasks

**Deliverables:**
- [ ] Integration test suite (device discovery to API)
- [ ] ARP packet capture validation
- [ ] Database consistency checks
- [ ] API endpoint tests
- [ ] Load test with 100+ devices
- [ ] Edge cases (duplicate MACs, rapid changes, network flapping)

**Test Plan:**
```
[ ] Unit tests for each component (target: >90% coverage)
[ ] Integration test: ARP packet → database → API → UI
[ ] Load test: 100 devices, 1000+ daily ARP packets
[ ] Stress test: Rapid device activity, timeouts
[ ] Edge cases:
    - Duplicate MAC addresses (shouldn't happen, log it)
    - Device IP changes
    - ARP spoofing attempts (log, don't break)
[ ] Performance test: <100ms for device list query
[ ] Documentation: Test results, performance metrics
```

**Related Files:**
- `tests/test_device_discovery.py` - Create
- `tests/integration/test_phase0.py` - Create
- `tests/load/test_device_load.py` - Create

---

### Phase 0 Success Criteria
- [ ] All 7 tasks completed and merged to main
- [ ] Device list API returning all discovered devices
- [ ] Dashboard shows live device inventory
- [ ] Database schema stable and tested
- [ ] ARP monitoring capturing 100% of LAN devices
- [ ] Performance: <100ms query time for 1000+ devices
- [ ] Code review approved by 2+ reviewers
- [ ] >90% test coverage
- [ ] Documentation written for operations team

---

## 📊 PHASE 1: DEVICE-AWARE DASHBOARD (Weeks 4-7)

### Overview
Create dashboard views linking device inventory to network connections and threats.

### High-Level Goals
- [ ] Per-device connection view
- [ ] Device-centric threat summary
- [ ] Device activity timeline
- [ ] Connection filtering by device
- [ ] **MVP Launch Ready**

### Structurable Tasks

#### Task 1.1: Connection-to-Device Linking
**Duration:** 2 days | **Owner:** Lead Engineer
**Prerequisites:** Phase 0 complete

**Deliverables:**
- [ ] Link connection records to device (by source IP)
- [ ] Update connection schema to include source device MAC
- [ ] API to get all connections for a device

**Implementation Checklist:**
```
[ ] Create connection lookup by source IP
[ ] Add device_mac field to connection records
[ ] Create index: (source_ip, device_mac)
[ ] Implement get_connections_by_device(mac) method
[ ] Handle IP address reuse/DHCP scenarios
[ ] Write tests for connection lookup accuracy
```

**Related Files:**
- `src/storage/models.py` - Update connection model
- `src/storage/database.py` - Add connection-device queries

---

#### Task 1.2: Device Detail View API
**Duration:** 2 days | **Owner:** Junior Engineer
**Prerequisites:** Task 1.1

**Deliverables:**
- [ ] GET `/api/devices/{mac}` endpoint with full details
- [ ] All connections for the device
- [ ] Threat summary (count of suspicious connections)
- [ ] Activity timeline (first/last seen, activity level)

**Implementation Checklist:**
```
[ ] Implement /api/devices/{mac}/connections endpoint
[ ] Implement /api/devices/{mac}/stats endpoint
[ ] Include connection count, threat count, geographic spread
[ ] Add date range filtering for connections
[ ] Implement pagination for large connection lists
[ ] Write endpoint tests
```

**Expected Response Format:**
```json
{
  "device": {
    "mac": "00:11:22:33:44:55",
    "ip": "192.168.1.50",
    "vendor": "Apple Inc.",
    "first_seen": "2025-11-01T08:00:00Z",
    "last_seen": "2025-11-19T16:30:00Z",
    "activity_level": "high",
    "is_online": true
  },
  "stats": {
    "total_connections": 127,
    "unique_destinations": 42,
    "threat_connections": 3,
    "countries": ["US", "JP", "CN"],
    "top_ports": [443, 80, 53]
  },
  "connections": [
    {
      "destination_ip": "8.8.8.8",
      "destination_port": 53,
      "protocol": "UDP",
      "threat_level": "safe",
      "timestamp": "2025-11-19T16:30:00Z"
    }
  ]
}
```

**Related Files:**
- `src/dashboard/server.py` - Add new endpoints

---

#### Task 1.3: Device Detail UI Template
**Duration:** 3 days | **Owner:** Frontend Engineer
**Prerequisites:** Task 1.2

**Deliverables:**
- [ ] Device detail page showing all info
- [ ] Connections table for device
- [ ] Threat summary cards
- [ ] Activity timeline visualization
- [ ] Filter by date range, threat level

**Implementation Checklist:**
```
[ ] Create device_detail.html template
[ ] Add device summary section (MAC, IP, vendor, status)
[ ] Add threat summary cards (total, suspicious, safe)
[ ] Implement connections table with sorting
[ ] Add connection threat indicators (color coding)
[ ] Implement date range picker
[ ] Add connection details modal (click to expand)
[ ] Create activity timeline view
[ ] Write frontend tests
```

**UI Layout:**
```
┌─ Device: AA:BB:CC:DD:EE:FF ──────────────────┐
│ Vendor: Apple Inc.                           │
│ IP: 192.168.1.50 | Online | High Activity   │
├──────────────────────────────────────────────┤
│ THREAT SUMMARY      │ ACTIVITY           │
│ ├─ Total: 127      │ First seen: 11/1   │
│ ├─ Safe: 124       │ Last seen: Now     │
│ └─ Suspicious: 3   │ Status: Online     │
├──────────────────────────────────────────────┤
│ CONNECTIONS (showing 127 total)              │
│ 🔽 Destination    Port  Threat      Time    │
│ 8.8.8.8           53    ✓ Safe      16:30   │
│ 1.1.1.1           443   ✓ Safe      16:28   │
│ 10.0.0.15         2049  ⚠ Unknown   16:25   │
└──────────────────────────────────────────────┘
```

**Related Files:**
- `src/dashboard/templates/device_detail.html` - Create
- `src/dashboard/static/js/device_detail.js` - Create

---

#### Task 1.4: Threat Summary Per Device
**Duration:** 2 days | **Owner:** Junior Engineer
**Prerequisites:** Task 1.1

**Deliverables:**
- [ ] Calculate threat score per device
- [ ] Count suspicious connections (malware, C2, etc.)
- [ ] Identify high-risk devices
- [ ] Flag devices connecting to known threats

**Implementation Checklist:**
```
[ ] Implement threat_score(device_mac) calculation
[ ] Define suspicious categories (malware, C2, proxy, etc.)
[ ] Count connections in each category per device
[ ] Create device_threats table or view
[ ] Implement high-risk device detection (score > threshold)
[ ] Add threat level badge to device list
[ ] Write tests for threat scoring logic
```

**Threat Scoring Logic:**
```
threat_score = (
    malware_connections * 10 +
    c2_connections * 10 +
    suspicious_geo_connections * 5 +
    proxy_connections * 3
)

threat_level = {
  0-5: 'Low',
  5-20: 'Medium',
  20+: 'High'
}
```

**Related Files:**
- `src/core/threat_scoring.py` - Create new module
- `src/storage/database.py` - Add threat queries

---

#### Task 1.5: Connection Filtering by Device
**Duration:** 1 day | **Owner:** Junior Engineer
**Prerequisites:** Tasks 1.2, 1.4

**Deliverables:**
- [ ] Filter connections by source device
- [ ] Filter by threat level + device
- [ ] Filter by device + destination country
- [ ] Multi-device comparison

**Implementation Checklist:**
```
[ ] Add device filter to /api/connections
[ ] Implement multi-device filter (show all suspicious across devices)
[ ] Add device + threat level filter
[ ] Implement device + geographic filter
[ ] Update dashboard UI with filter controls
[ ] Write API tests for filtering
```

**Related Files:**
- `src/dashboard/server.py` - Update connection endpoints
- Dashboard UI - Add filter controls

---

#### Task 1.6: Activity Timeline View
**Duration:** 2 days | **Owner:** Frontend Engineer
**Prerequisites:** Task 1.3

**Deliverables:**
- [ ] Timeline visualization of device activity
- [ ] First seen, last seen, offline periods
- [ ] Threat events highlighted on timeline
- [ ] Hoverable tooltips for details

**Implementation Checklist:**
```
[ ] Create timeline data structure
[ ] Fetch device activity history
[ ] Implement timeline visualization (D3.js or Chart.js)
[ ] Color code: green (online), gray (offline), red (threat)
[ ] Add interactive tooltips
[ ] Implement zoom/pan on timeline
[ ] Write frontend tests
```

**Timeline Data Format:**
```json
{
  "timeline": [
    {"timestamp": "2025-11-01T08:00:00Z", "event": "discovered", "status": "online"},
    {"timestamp": "2025-11-10T12:00:00Z", "event": "threat_detected", "level": "high"},
    {"timestamp": "2025-11-15T06:00:00Z", "event": "offline"}
  ]
}
```

**Related Files:**
- `src/dashboard/templates/device_timeline.html` - Create
- `src/dashboard/static/js/timeline.js` - Create

---

#### Task 1.7: MVP Testing & Documentation
**Duration:** 3 days | **Owner:** QA/Docs Engineer
**Prerequisites:** All Phase 1 tasks

**Deliverables:**
- [ ] End-to-end testing (device → connections → threats)
- [ ] Performance testing (device detail with 1000+ connections)
- [ ] User acceptance testing scenarios
- [ ] Operations runbook for Phase 0-1
- [ ] API documentation

**Test Scenarios:**
```
[ ] Scenario 1: Detect new device, see all its connections
[ ] Scenario 2: Identify suspicious device via threat summary
[ ] Scenario 3: Filter connections by device and threat level
[ ] Scenario 4: Export device report
[ ] Scenario 5: Track device activity over 2-week period
[ ] Performance: Load device with 1000+ connections <2 seconds
[ ] Concurrent users: 5 simultaneous dashboard users
```

**Documentation:**
```
[ ] Operations Guide: How to deploy Phase 0-1
[ ] User Guide: Using device inventory and threat view
[ ] API Documentation: All endpoints with examples
[ ] Troubleshooting: Common issues and solutions
[ ] Performance baseline: Query times, resource usage
```

**Related Files:**
- `docs/PHASE0_1_OPERATIONS_GUIDE.md` - Create
- `docs/API_REFERENCE_DEVICES.md` - Create
- Test reports in `tests/reports/`

---

### Phase 1 Success Criteria (MVP Ready)
- [ ] All 7 tasks completed and tested
- [ ] Device inventory dashboard fully functional
- [ ] Per-device threat summary visible
- [ ] Connection history linked to devices
- [ ] <2 second load time for device details
- [ ] 100+ device support verified
- [ ] All API endpoints documented
- [ ] Operations runbook complete
- [ ] Ready for production test deployment
- [ ] User acceptance testing passed

---

## 📊 PHASE 2: FORENSIC INTELLIGENCE & SEARCH (Weeks 8-13)

### Overview
Advanced investigation tools for incident response and threat analysis.

### High-Level Goals
- [ ] Full connection history search
- [ ] Advanced filtering (date, IP, country, threat)
- [ ] Timeline visualization
- [ ] CSV/JSON export
- [ ] Threat drill-down details

### Key Tasks (Summary Level)

**Task 2.1:** Database optimization for historical queries
- Add time-series indexes (connection date, threat timestamp)
- Implement query caching for repeated searches
- Optimize for 1-year retention

**Task 2.2:** Advanced search API
- GET /api/search/connections - Full-text and filter search
- Parameters: date_range, src_ip, dst_ip, country, threat_level, port
- Results sorted by relevance/date

**Task 2.3:** Timeline visualization component
- Interactive timeline showing connections over time
- Zoom by day/week/month
- Threat events highlighted

**Task 2.4:** Export functionality
- Export connections to CSV (spreadsheet)
- Export to JSON (external systems)
- Include device info + threat data
- Batch export (multiple devices)

**Task 2.5:** Threat drill-down
- Click threat → see details (which service flagged it, reputation score)
- Integration with threat intelligence database
- Malware/C2 signature matches

**Task 2.6:** Search UI
- Advanced query builder (date range, filters)
- Saved search functionality
- Search history
- Results pagination

**Task 2.7:** Performance testing & optimization
- Load test: 1M+ connections searchable
- Query time target: <1 second for any search
- Memory optimization

---

## 📊 PHASE 3: ORIGIN TRACING & DNS (Weeks 14-21)

### Overview
Resolve hostnames, trace true origins, detect proxies/VPNs.

### Key Tasks (Summary Level)

**Task 3.1:** Reverse DNS integration
- Call reverse DNS on connection IPs
- Cache results (DNS changes slowly)
- TTL management

**Task 3.2:** DNS query correlation
- Capture DNS queries from devices
- Link domains to IPs over time
- Show DNS resolution path

**Task 3.3:** Proxy/VPN detection
- Flag CloudFlare, Akamai, Fastly IPs
- VPN service detection
- Identify devices using VPN

**Task 3.4:** Hostname display in UI
- Show resolved hostnames in all views
- Display DNS chain (A record → CNAME → IP)
- Warning for DNS anomalies

**Task 3.5:** Passive DNS feed (optional)
- Integration with passive DNS service (paid)
- Historical domain-to-IP mappings
- Identify suspicious domains

**Task 3.6:** Geographic hop mapping (optional)
- Show path from device to destination
- Identifies VPN hops
- Detects routing anomalies

---

## 📊 PHASE 4: MULTI-SITE ENTERPRISE (Weeks 22-33)

### Overview
Scale to enterprise with multiple edge devices and central aggregation.

### Key Tasks (Summary Level)

**Task 4.1:** Central dashboard server
- Master CobaltGraph instance for aggregation
- Database for multi-site data
- User authentication/RBAC

**Task 4.2:** Agent mode for edges
- Edge devices report to central (not standalone)
- Compressed data transmission
- Automatic sync

**Task 4.3:** Multi-tenant/multi-site views
- Per-site dashboard
- Site-to-site comparison
- Cross-site device tracking

**Task 4.4:** Cross-site threat correlation
- Same IP seen at multiple sites → alert
- Compromised device pattern detection
- Lateral movement detection

**Task 4.5:** SIEM integration
- Export to Splunk, ELK, ArcSight
- REST API for SIEM pull
- Webhook for SIEM push

**Task 4.6:** Alert rules engine
- Rule builder for threat detection
- Automatic alerts on suspicious patterns
- Notification delivery (email, Slack, webhook)

**Task 4.7:** API for automation
- REST API for external tools
- Webhook delivery to automation systems
- Bulk operations (export, archive)

---

## 📊 PHASE 5: SECURITY HARDENING (Weeks 34-38)

### Overview
Production-ready system with security patches and high availability.

### Key Tasks (Summary Level)

**Task 5.1:** Security patch application
- Apply all SEC-001 through SEC-008 patches
- External security audit
- Vulnerability remediation

**Task 5.2:** Performance hardening
- Load testing (10k devices, 1M connections)
- Database optimization
- Caching strategies
- Async processing where needed

**Task 5.3:** High availability setup
- Redundant central servers
- Database replication
- Failover mechanisms

**Task 5.4:** Docker containerization
- Container images for all components
- Docker Compose for local dev
- Container security hardening

**Task 5.5:** Kubernetes deployment
- K8s manifests for central dashboard
- StatefulSet for database
- ConfigMaps for configuration

**Task 5.6:** Infrastructure as Code
- Terraform for AWS/GCP/Azure
- Infrastructure documentation
- Automated deployment pipeline

**Task 5.7:** Operations & compliance
- Runbooks for common scenarios
- Disaster recovery procedures
- Backup/restore testing
- Compliance mapping (SOC 2, NIST, CIS)

---

## 📚 DOCUMENTATION ARTIFACTS TO CREATE

### By Phase

**During Phase 0-1 (Weeks 1-7):**
```
docs/
├── PHASE0_ARP_MONITORING_SPEC.md
│   ├── Detailed ARP packet structure
│   ├── Device state machine
│   └── Database schema (with migrations)
├── PHASE1_DASHBOARD_DESIGN.md
│   ├── UI mockups (all screens)
│   ├── API endpoint reference
│   └── Database query patterns
└── PHASE01_OPERATIONS_GUIDE.md
    ├── Deployment instructions
    ├── Configuration options
    └── Troubleshooting guide
```

**During Phase 2 (Weeks 8-13):**
```
docs/
├── PHASE2_FORENSICS_DESIGN.md
├── SEARCH_QUERY_LANGUAGE.md
└── EXPORT_FORMAT_SPECIFICATION.md
```

**During Phase 3 (Weeks 14-21):**
```
docs/
├── PHASE3_DNS_ARCHITECTURE.md
├── ORIGIN_TRACING_IMPLEMENTATION.md
└── THREAT_INTELLIGENCE_INTEGRATION.md
```

**During Phase 4 (Weeks 22-33):**
```
docs/
├── MULTI_SITE_ARCHITECTURE.md
├── AGENT_DEPLOYMENT_GUIDE.md
├── SIEM_INTEGRATION_REFERENCE.md
├── ALERT_RULES_SPECIFICATION.md
└── API_REFERENCE_COMPLETE.md
```

**During Phase 5 (Weeks 34-38):**
```
docs/
├── SECURITY_HARDENING_CHECKLIST.md
├── DEPLOYMENT_RUNBOOK.md
├── HIGH_AVAILABILITY_GUIDE.md
├── COMPLIANCE_MAPPING.md
└── OPERATIONS_MANUAL.md
```

### By Audience

**For Developers:**
- Technical specs for each phase
- Architecture decision records (ADRs)
- Code contribution guidelines
- Database schema documentation
- API design specifications

**For Operations:**
- Deployment guides
- Configuration reference
- Troubleshooting guides
- Performance tuning
- Backup/restore procedures

**For Security:**
- Security audit findings (from Nov 14)
- Patch status tracking
- Vulnerability assessment
- Compliance mappings
- Security hardening checklist

**For Management:**
- Timeline tracking (Gantt chart)
- Milestone status
- Resource utilization
- Risk assessment
- Budget tracking

---

## 🗓️ TIMELINE OVERVIEW

### Calendar Milestones

| Week | Phase | Milestone | Deliverable |
|------|-------|-----------|-------------|
| 1-3 | 0 | ARP Monitoring | Passive device discovery |
| 4-7 | 1 | MVP Dashboard | Device inventory + connections |
| 8 | — | MVP LAUNCH | Ready for test environment |
| 8-13 | 2 | Forensics | Full search + export |
| 14-21 | 3 | Origin Tracing | DNS resolution + hostname |
| 22-33 | 4 | Enterprise | Multi-site + SIEM |
| 34-38 | 5 | Production | Security hardening |
| 39+ | — | Ongoing | Monitoring, updates, features |

### Resource Allocation

**Weeks 1-7 (Phases 0-1):**
- 2 full-time engineers (lead + junior)
- 1 frontend engineer
- 1 QA engineer (part-time)
- Total: ~1.75 FTE

**Weeks 8-13 (Phase 2):**
- 1-2 engineers
- 1 QA engineer
- Total: ~1.5 FTE

**Weeks 14-21 (Phase 3):**
- 1-2 engineers
- 1 QA engineer
- Total: ~1.5 FTE

**Weeks 22-33 (Phase 4):**
- 2 engineers
- 1 QA engineer
- 1 DevOps engineer (part-time)
- Total: ~2.25 FTE

**Weeks 34-38 (Phase 5):**
- 1 security engineer
- 1 DevOps engineer
- 1 ops engineer
- Total: ~1.5 FTE

---

## 👥 TEAM ROLES & RESPONSIBILITIES

### Lead Engineer (Full-time, Weeks 1-38)
- **Phase 0-1:** Database design, ARP implementation, architecture decisions
- **Phase 2-3:** Search optimization, DNS integration
- **Phase 4:** Enterprise architecture, multi-site coordination
- **Phase 5:** Security hardening, performance optimization

**Skills Required:** Python, networking (ARP/packets), database design, system architecture

### Junior Engineer (Full-time, Weeks 1-7; Part-time after)
- **Phase 0:** Database schema, OUI lookup, event system
- **Phase 1:** API endpoints, threat scoring
- **Phase 2-3:** Search implementation, DNS queries
- **Phase 4:** Agent mode, reporting API
- **Phase 5:** Security patches, testing

**Skills Required:** Python, SQL, API development, testing

### Frontend Engineer (Weeks 4-38)
- **Phase 1:** Device inventory UI, device detail view
- **Phase 2:** Search UI, timeline visualization
- **Phase 3:** Hostname display across UI
- **Phase 4:** Multi-site dashboard
- **Phase 5:** Production UI polish

**Skills Required:** HTML/CSS/JavaScript, React or Vue, responsive design, UX

### QA Engineer (Weeks 2-38, varying intensity)
- Integration testing for each phase
- Load testing and performance benchmarking
- Regression testing between phases
- Production readiness validation

**Skills Required:** Test automation, performance testing, SQL

### DevOps Engineer (Weeks 22-38)
- **Phase 4:** Infrastructure planning for multi-site
- **Phase 5:** Docker, Kubernetes, Terraform
- **Phase 5:** CI/CD pipeline, deployment automation

**Skills Required:** Docker, Kubernetes, Terraform, AWS/GCP/Azure

### Security Engineer (Week 34-38)
- Security audit of implementation
- Patch verification
- Compliance validation
- Security documentation

**Skills Required:** Security auditing, compliance, Python code review

---

## 🎯 SUCCESS METRICS & KPIs

### Functional Metrics
- Device discovery accuracy (% of LAN devices found)
- Connection capture completeness (% of traffic captured)
- Query response time (<1 second target)
- Database growth rate (bytes/device/day)

### Quality Metrics
- Test coverage (>90% target)
- Bug escape rate (defects in production)
- Performance SLA (99% uptime, <2sec queries)

### Delivery Metrics
- On-time milestone completion (Phases 0-1 by week 7)
- Code review turnaround (<24 hours)
- Documentation completeness (all phases documented)

### Security Metrics
- Vulnerability discovery rate (post-launch)
- Security patch application time (within 48 hours)
- Compliance gap closure (all mapped by Phase 5)

---

## ⚠️ RISKS & MITIGATION

### Risk 1: ARP spoofing on untrusted networks
**Impact:** Device discovery becomes unreliable
**Mitigation:**
- Add ARP spoofing detection (monitor for suspicious patterns)
- Validate MAC-IP consistency over time
- Document limitations for untrusted networks

### Risk 2: Performance degradation with 10k+ devices
**Impact:** Dashboard becomes slow, queries timeout
**Mitigation:**
- Early load testing (Phase 1, not Phase 5)
- Database indexing strategy (Phase 0)
- Query optimization continuous process
- Caching layer (Phase 2)

### Risk 3: DHCP lease reuse conflicts
**Impact:** Device misidentification when IPs change
**Mitigation:**
- Track MAC + IP pairs together
- Detect rapid IP changes (alert on them)
- Merge device records intelligently
- Logging for audit trail

### Risk 4: Resource constraints (not enough engineers)
**Impact:** Phases slip, MVP delayed
**Mitigation:**
- Prioritize MVP (Phases 0-1) ruthlessly
- Cut Phase 4-5 features if needed
- Outsource non-core tasks (security audit, load testing)
- Hire/contract as needed

### Risk 5: Threat intelligence integration challenges
**Impact:** Phase 3 delays from API changes
**Mitigation:**
- Phase 3 is weeks 14-21 (not critical path)
- Design API abstraction layer for threat feeds
- Plan for multiple threat intel sources

---

## 🚀 IMMEDIATE NEXT STEPS (This Week)

### TODAY (2025-11-19)
- [ ] Review this plan with engineering team
- [ ] Confirm resource availability
- [ ] Identify lead engineer for Phases 0-1
- [ ] Schedule kickoff meeting

### THIS WEEK (by 2025-11-21)
- [ ] Assign all Phase 0 task owners
- [ ] Create GitHub project with Phase 0 tasks
- [ ] Schedule daily standup (10 AM)
- [ ] Review existing codebase for Phase 0 dependencies

### NEXT WEEK (2025-11-24)
- [ ] Create detailed Phase 0 technical spec
- [ ] Design database schema (Task 0.1)
- [ ] Prototype ARP packet parsing (Task 0.2)
- [ ] Set up dev/test environment

### WEEK 3 (2025-12-01)
- [ ] Phase 0 implementation begins
- [ ] First ARP packets captured
- [ ] Device database populated
- [ ] First code commit to GitHub

---

## 📞 ESCALATION & DECISION POINTS

### Decision Points

**Week 1:** Database platform choice
- PostgreSQL vs MySQL vs SQLite for device inventory
- Impact: Query performance, scaling options
- **Owner:** Lead engineer + DevOps
- **Decision by:** 2025-11-21

**Week 3:** Real-time update strategy
- Polling (30s) vs WebSocket vs Server-Sent Events
- Impact: Dashboard latency, server load
- **Owner:** Frontend engineer + lead
- **Decision by:** 2025-12-01

**Week 7:** MVP feature cut/expand
- Do we add Phase 2 features before production?
- Impact: Launch date, MVP scope
- **Owner:** Product + engineering
- **Decision by:** 2025-12-15

**Week 13:** Multi-site requirements clarity
- Phase 4 scope: 2 sites vs 10+ sites?
- Impact: Architecture decisions
- **Owner:** Product + security team
- **Decision by:** 2026-01-20

---

## 📚 REFERENCED DOCUMENTS

### Existing Documentation
- `INDEX_STRATEGIC_ANALYSIS.md` - Overall vision and roadmap
- `README.md` - Project overview
- `security/FINAL_SECURITY_AUDIT_20251114.md` - Security findings

### To Be Created
- Phase 0 technical specification
- Phase 1 UI/API design document
- Phase 0-1 operations guide
- API reference documentation

---

## ✅ APPROVAL & SIGN-OFF

**Prepared by:** Architecture Team
**Date:** 2025-11-19
**Version:** 1.0

**Approvals Required:**
- [ ] Engineering Lead
- [ ] Product Manager
- [ ] Security Officer
- [ ] DevOps Lead

---

**This implementation plan is ready for team review and development kickoff.**

**Next Action: Schedule team meeting to review plan and assign Phase 0 task owners.**

---

*For questions or updates, contact the CobaltGraph project lead.*
