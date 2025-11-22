# CobaltGraph Development Checklists
**Date:** 2025-11-19
**Purpose:** Day-to-day task tracking for engineering team

---

## 🎯 PHASE 0: PASSIVE DEVICE DISCOVERY (Weeks 1-3)

### Quick Status
| Task | Owner | Status | Target Date |
|------|-------|--------|------------|
| 0.1: Database Schema | Lead | ⏳ Not Started | 2025-11-21 |
| 0.2: ARP Monitoring | Lead+Junior | ⏳ Not Started | 2025-11-28 |
| 0.3: OUI Lookup | Junior | ⏳ Not Started | 2025-11-21 |
| 0.4: Device Events | Lead | ⏳ Not Started | 2025-11-24 |
| 0.5: Device API | Junior | ⏳ Not Started | 2025-11-26 |
| 0.6: Device UI | Frontend | ⏳ Not Started | 2025-11-28 |
| 0.7: Testing | QA | ⏳ Not Started | 2025-12-01 |

---

### Task 0.1: Database Schema Design
**Target Completion:** 2025-11-21
**Owner:** Lead Engineer

**Checklist:**
- [ ] Review current database structure
- [ ] Design `devices` table schema
  - [ ] MAC address (primary key)
  - [ ] IP address
  - [ ] Vendor/manufacturer
  - [ ] Device type (computed from OUI + behavior)
  - [ ] First seen timestamp
  - [ ] Last seen timestamp
  - [ ] Last activity timestamp
  - [ ] Status (online/offline/idle)
  - [ ] Confidence score
- [ ] Create database indexes
  - [ ] Primary: MAC
  - [ ] Secondary: IP
  - [ ] Secondary: last_seen (for timeouts)
- [ ] Design device state machine
  - [ ] States: discovered → active → idle → offline
  - [ ] Transitions: activity triggers active, timeout triggers idle
- [ ] Create migration file
- [ ] Define Device dataclass
- [ ] Write unit tests for schema
- [ ] Code review by 2+ reviewers
- [ ] Merge to main branch

**Files to Modify/Create:**
```
[ ] src/storage/migrations/001_device_inventory.sql (CREATE)
[ ] src/storage/models.py (UPDATE - add Device dataclass)
[ ] src/storage/database.py (UPDATE - add device table + CRUD)
[ ] tests/test_device_schema.py (CREATE)
```

**Deliverables:**
- [ ] Migration script ready to run
- [ ] Device dataclass documented
- [ ] Database functions tested
- [ ] Schema diagram in PR description

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 0.2: ARP Monitoring Implementation
**Target Completion:** 2025-11-28
**Owner:** Lead Engineer + Junior Engineer

**Checklist:**
- [ ] Study ARP packet structure
  - [ ] Understand Layer 2 broadcast
  - [ ] Parse hardware address
  - [ ] Extract protocol address
  - [ ] Handle ARP request vs reply
- [ ] Implement ARP listener thread
  - [ ] Raw socket on 0x0806 (ARP)
  - [ ] Listen continuously
  - [ ] Handle socket errors gracefully
- [ ] Implement ARP packet parser
  - [ ] Extract source MAC
  - [ ] Extract source IP
  - [ ] Extract operation (request/reply)
  - [ ] Extract hardware type
- [ ] Integrate with OUI lookup
- [ ] Emit device_discovered event
  - [ ] Event schema defined
  - [ ] Event handler in orchestrator
  - [ ] Logging for debugging
- [ ] Handle edge cases
  - [ ] Duplicate MACs (log warning)
  - [ ] Rapid IP changes (log activity)
  - [ ] ARP spoofing patterns (detect and log)
- [ ] Performance optimization
  - [ ] Multi-threaded packet processing
  - [ ] Batch database inserts
  - [ ] Memory efficiency
- [ ] Integration testing
  - [ ] Send test ARP packets
  - [ ] Verify capture and parsing
  - [ ] Verify database insertion
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] tools/grey_man.py (UPDATE - add ARP monitoring)
[ ] src/core/orchestrator.py (UPDATE - event handlers)
[ ] src/utils/arp_parser.py (CREATE)
[ ] tests/test_arp_monitoring.py (CREATE)
[ ] tests/integration/test_phase0_arp.py (CREATE)
```

**Dependencies:**
- [ ] Task 0.1 complete (device schema)
- [ ] Task 0.3 complete (OUI lookup)

**Deliverables:**
- [ ] ARP monitoring captures 100% of LAN traffic
- [ ] Zero false positives in device discovery
- [ ] Performance: <100ms per packet
- [ ] Tested with 10+ devices

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 0.3: OUI Vendor Lookup Database
**Target Completion:** 2025-11-21
**Owner:** Junior Engineer

**Checklist:**
- [ ] Research OUI database sources
  - [ ] IEEE public OUI database
  - [ ] Python libraries (mac_vendor_lookup, etc.)
  - [ ] Licensing compatibility
- [ ] Choose implementation approach
  - [ ] CSV file + in-memory hash (simple)
  - [ ] Database table (scalable)
  - [ ] Python library wrapper (easiest)
- [ ] Implement lookup function
  - [ ] MAC prefix (first 6 chars) to vendor
  - [ ] Case-insensitive matching
  - [ ] Fallback for unknown MACs
- [ ] Add caching layer
  - [ ] Cache hits for repeated lookups
  - [ ] Memory-efficient (LRU cache)
- [ ] Implement update mechanism
  - [ ] Quarterly OUI database refresh
  - [ ] Automatic download of new data
  - [ ] Fallback if download fails
- [ ] Write comprehensive tests
  - [ ] Known vendors (Apple, Samsung, etc.)
  - [ ] Unknown MACs
  - [ ] Edge cases (locally administered, broadcast)
- [ ] Performance test
  - [ ] <1ms lookup for cached entries
  - [ ] <10ms lookup for uncached entries
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/utils/oui_lookup.py (CREATE)
[ ] data/oui.csv (CREATE - or use external)
[ ] tests/test_oui_lookup.py (CREATE)
```

**Dependencies:**
- [ ] None (independent task)

**Deliverables:**
- [ ] Lookup function 99%+ accurate for known vendors
- [ ] Performance <10ms per lookup
- [ ] Update mechanism tested
- [ ] Documentation for adding custom vendors

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 0.4: Device Event System
**Target Completion:** 2025-11-24
**Owner:** Lead Engineer

**Checklist:**
- [ ] Define event types
  - [ ] device_discovered
  - [ ] device_activity
  - [ ] device_offline
  - [ ] device_ip_changed
- [ ] Design event schema
  - [ ] Common fields (type, timestamp, device_mac)
  - [ ] Event-specific fields
  - [ ] Optional metadata
- [ ] Create event dataclasses
  - [ ] Type hints
  - [ ] Validation
  - [ ] Serialization
- [ ] Implement event emitters
  - [ ] In ARP monitor (device_discovered)
  - [ ] In connection handler (device_activity)
  - [ ] In timeout handler (device_offline)
- [ ] Implement event handlers in orchestrator
  - [ ] device_discovered → insert to database
  - [ ] device_activity → update last_seen
  - [ ] device_offline → update status
- [ ] Implement timeout logic
  - [ ] 30 min no activity = offline
  - [ ] Timer per device
  - [ ] Background cleanup thread
- [ ] Add audit trail
  - [ ] Log all device changes
  - [ ] Immutable record of state changes
  - [ ] Queryable via API (Phase 2)
- [ ] Write tests
  - [ ] Event ordering
  - [ ] Concurrent device events
  - [ ] Timeout triggers correctly
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/core/events.py (UPDATE - add device events)
[ ] src/core/orchestrator.py (UPDATE - event handlers)
[ ] src/storage/models.py (UPDATE - event dataclasses)
[ ] src/storage/database.py (UPDATE - audit trail table)
[ ] tests/test_device_events.py (CREATE)
```

**Dependencies:**
- [ ] Task 0.1 complete (database schema)
- [ ] Task 0.2 partial (ARP monitoring exists)

**Deliverables:**
- [ ] Event system fully integrated
- [ ] Device state machine working
- [ ] Audit trail complete
- [ ] All event types tested

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 0.5: API Endpoint for Device List
**Target Completion:** 2025-11-26
**Owner:** Junior Engineer

**Checklist:**
- [ ] Create device routes
  - [ ] GET /api/devices
  - [ ] GET /api/devices/{mac}
  - [ ] POST /api/devices (admin only, later)
- [ ] Implement /api/devices endpoint
  - [ ] List all devices
  - [ ] Pagination (page, per_page)
  - [ ] Sorting (by MAC, IP, vendor, status, activity)
  - [ ] Filtering (by vendor, status, ip_range)
  - [ ] Search by MAC or IP
- [ ] Implement /api/devices/{mac} endpoint
  - [ ] Return all device fields
  - [ ] Include connection count
  - [ ] Include threat count
  - [ ] Include activity timeline summary
- [ ] Add query optimization
  - [ ] Indexes used for fast queries
  - [ ] Explain plan reviewed
  - [ ] <100ms for 1000 devices
- [ ] Error handling
  - [ ] Invalid MAC format
  - [ ] Device not found
  - [ ] Invalid pagination parameters
- [ ] API documentation
  - [ ] Endpoint descriptions
  - [ ] Request/response examples
  - [ ] Error codes
- [ ] Write comprehensive tests
  - [ ] Happy path (list devices)
  - [ ] Filtering accuracy
  - [ ] Pagination correctness
  - [ ] Performance (<100ms)
  - [ ] Edge cases
- [ ] Load test
  - [ ] 1000+ devices
  - [ ] Concurrent requests (5+)
  - [ ] Sustained load (1 min)
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/dashboard/server.py (UPDATE - device routes)
[ ] tests/test_device_api.py (CREATE)
[ ] tests/load/test_device_load.py (CREATE)
[ ] docs/API_REFERENCE_DEVICES.md (CREATE)
```

**Dependencies:**
- [ ] Task 0.1 complete (database schema)
- [ ] Task 0.4 complete (event system)

**Deliverables:**
- [ ] All endpoints working and documented
- [ ] Performance benchmarks met (<100ms)
- [ ] Load test report (1000+ devices)
- [ ] API documentation complete

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 0.6: Dashboard Device List UI
**Target Completion:** 2025-11-28
**Owner:** Frontend Engineer

**Checklist:**
- [ ] Create devices_inventory.html template
  - [ ] Table structure
  - [ ] Bootstrap styling
  - [ ] Responsive design (mobile + desktop)
- [ ] Implement device table
  - [ ] Columns: MAC, IP, Vendor, Status, Activity, Last Seen
  - [ ] Rows clickable (go to device detail)
  - [ ] Scrollable (handle 100+ devices)
- [ ] Add sorting
  - [ ] Click column header to sort
  - [ ] Ascending/descending toggle
  - [ ] Visual indicator (up/down arrow)
- [ ] Add search functionality
  - [ ] Search box for MAC/IP
  - [ ] Real-time filtering
  - [ ] Clear search button
- [ ] Add filters
  - [ ] Vendor dropdown (populated from data)
  - [ ] Status filter (online/offline/idle)
  - [ ] Activity level filter (high/medium/low)
  - [ ] Multi-select support
- [ ] Add auto-refresh
  - [ ] Every 30 seconds by default
  - [ ] Manual refresh button
  - [ ] Option to disable auto-refresh
- [ ] Add visual indicators
  - [ ] Online (green dot)
  - [ ] Offline (gray dot)
  - [ ] Idle (yellow dot)
  - [ ] Threat level color coding
- [ ] Add device detail link
  - [ ] Click row to open device detail (Phase 1)
  - [ ] Load icon while loading
- [ ] Write frontend tests
  - [ ] Table renders correctly
  - [ ] Sorting works
  - [ ] Search filters results
  - [ ] Auto-refresh updates data
- [ ] Performance testing
  - [ ] 100+ devices: <1 second render
  - [ ] Smooth scrolling
  - [ ] Minimal reflow on updates
- [ ] Mobile testing
  - [ ] Responsive on small screens
  - [ ] Touch-friendly controls
  - [ ] Horizontal scroll for table
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/dashboard/templates/devices_inventory.html (CREATE)
[ ] src/dashboard/static/css/devices.css (CREATE)
[ ] src/dashboard/static/js/devices.js (CREATE)
[ ] tests/frontend/test_devices_ui.js (CREATE)
```

**Dependencies:**
- [ ] Task 0.5 complete (device API)

**Deliverables:**
- [ ] Device list table fully functional
- [ ] All filters and sorting working
- [ ] Auto-refresh operational
- [ ] Mobile responsive
- [ ] <1 second render time
- [ ] Frontend tests passing

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 0.7: Testing & Validation
**Target Completion:** 2025-12-01
**Owner:** QA Engineer

**Checklist:**
- [ ] Unit test coverage
  - [ ] Database operations (>95% coverage)
  - [ ] ARP parsing (>95% coverage)
  - [ ] OUI lookup (>95% coverage)
  - [ ] API endpoints (>90% coverage)
- [ ] Integration tests
  - [ ] ARP packet → database → API → UI (full flow)
  - [ ] Multiple devices simultaneously
  - [ ] Event ordering correctness
  - [ ] Timeout logic triggers
- [ ] Load testing
  - [ ] 100 devices: all discovered
  - [ ] 1000 devices: query time <100ms
  - [ ] 10000 ARP packets/minute: captured 100%
- [ ] Stress testing
  - [ ] Rapid IP changes: handled correctly
  - [ ] ARP spoofing patterns: detected and logged
  - [ ] Database full: graceful degradation
- [ ] Edge cases
  - [ ] Duplicate MACs (same device, different location)
  - [ ] DHCP IP reuse
  - [ ] Network flapping (rapid on/offline)
  - [ ] Malformed ARP packets
- [ ] Performance testing
  - [ ] Device list query: <100ms
  - [ ] Device detail query: <200ms
  - [ ] ARP packet processing: <10ms each
  - [ ] Memory usage: <500MB for 1000 devices
- [ ] Regression testing
  - [ ] No breaks to existing features
  - [ ] Database backward compatible
  - [ ] API version stable
- [ ] Documentation
  - [ ] Test results report
  - [ ] Performance baseline measurements
  - [ ] Known limitations documented
  - [ ] Operations runbook draft

**Test Files to Create:**
```
[ ] tests/unit/test_device_schema.py
[ ] tests/unit/test_arp_parser.py
[ ] tests/unit/test_oui_lookup.py
[ ] tests/integration/test_phase0_flow.py
[ ] tests/load/test_device_load.py
[ ] tests/stress/test_network_flapping.py
[ ] docs/PHASE0_TEST_REPORT.md
```

**Deliverables:**
- [ ] All unit tests passing (>90% coverage)
- [ ] Integration tests passing
- [ ] Load test report (1000+ devices)
- [ ] Performance baseline documented
- [ ] Operations runbook draft
- [ ] Test coverage report

**Comments/Notes:**
```
_____________________________________________

```

---

## 🎯 PHASE 1: DEVICE-AWARE DASHBOARD (Weeks 4-7)

### Quick Status
| Task | Owner | Status | Target Date |
|------|-------|--------|------------|
| 1.1: Device Linking | Lead | ⏳ Not Started | 2025-12-02 |
| 1.2: Device Detail API | Junior | ⏳ Not Started | 2025-12-04 |
| 1.3: Device Detail UI | Frontend | ⏳ Not Started | 2025-12-08 |
| 1.4: Threat Summary | Junior | ⏳ Not Started | 2025-12-03 |
| 1.5: Connection Filtering | Junior | ⏳ Not Started | 2025-12-05 |
| 1.6: Activity Timeline | Frontend | ⏳ Not Started | 2025-12-08 |
| 1.7: MVP Testing | QA | ⏳ Not Started | 2025-12-12 |

---

### Task 1.1: Connection-to-Device Linking
**Target Completion:** 2025-12-02
**Owner:** Lead Engineer

**Checklist:**
- [ ] Review connection data model
- [ ] Add device_mac field to connection records
- [ ] Implement IP-to-device lookup
  - [ ] Query device by IP
  - [ ] Handle DHCP IP reuse
  - [ ] Fallback when IP not in device inventory
- [ ] Update connection insertion logic
  - [ ] Look up device_mac from source IP
  - [ ] Store device_mac in connection record
- [ ] Create database index
  - [ ] (source_ip, device_mac)
  - [ ] (device_mac, timestamp)
- [ ] Migration script
  - [ ] Backfill existing connections (if any)
  - [ ] Null handling
- [ ] Write tests
  - [ ] Connection lookup by device
  - [ ] Multiple IPs to same device
  - [ ] DHCP scenarios
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/storage/models.py (UPDATE - add device_mac to connection)
[ ] src/storage/database.py (UPDATE - update connection insertion)
[ ] src/storage/migrations/002_connection_device_link.sql (CREATE)
[ ] tests/test_connection_device_link.py (CREATE)
```

**Dependencies:**
- [ ] Phase 0 complete

**Deliverables:**
- [ ] Connection-to-device linking working
- [ ] Database migration tested
- [ ] Tests passing

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 1.2: Device Detail API
**Target Completion:** 2025-12-04
**Owner:** Junior Engineer

**Checklist:**
- [ ] Create /api/devices/{mac}/connections endpoint
  - [ ] List all connections from device
  - [ ] Pagination
  - [ ] Sorting (by date, threat level)
  - [ ] Filtering (by destination, threat)
  - [ ] Date range filtering
- [ ] Create /api/devices/{mac}/stats endpoint
  - [ ] Total connection count
  - [ ] Unique destinations
  - [ ] Threat connection count
  - [ ] Geographic spread (countries)
  - [ ] Top ports
  - [ ] Top protocols
- [ ] Error handling
  - [ ] Device not found
  - [ ] Invalid date ranges
- [ ] Query optimization
  - [ ] <1 second response for 1000+ connections
- [ ] Write tests
  - [ ] Correct connection list
  - [ ] Correct statistics
  - [ ] Performance <1 second
- [ ] Documentation
  - [ ] API endpoint description
  - [ ] Example requests/responses
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/dashboard/server.py (UPDATE - add device detail endpoints)
[ ] tests/test_device_detail_api.py (CREATE)
```

**Dependencies:**
- [ ] Task 1.1 complete (connection-device linking)

**Deliverables:**
- [ ] Endpoints working and documented
- [ ] Performance benchmarks met (<1s)
- [ ] Tests passing

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 1.3: Device Detail UI Template
**Target Completion:** 2025-12-08
**Owner:** Frontend Engineer

**Checklist:**
- [ ] Create device_detail.html template
- [ ] Device header section
  - [ ] MAC address (formatted)
  - [ ] IP address
  - [ ] Vendor
  - [ ] Online/offline status (with icon)
  - [ ] Activity level indicator
- [ ] Summary cards
  - [ ] Total connections
  - [ ] Suspicious connections (red)
  - [ ] Safe connections (green)
  - [ ] Unknown connections (yellow)
- [ ] Activity information
  - [ ] First seen (date/time)
  - [ ] Last seen (date/time)
  - [ ] Days active
- [ ] Connections table
  - [ ] Destination IP
  - [ ] Destination port
  - [ ] Protocol (TCP/UDP)
  - [ ] Threat level (color coded)
  - [ ] Timestamp
  - [ ] Click for details (modal)
- [ ] Sorting and filtering
  - [ ] Sort by date, threat level, destination
  - [ ] Filter by threat level
  - [ ] Date range picker
  - [ ] Search destination IP/port
- [ ] Pagination
  - [ ] Show 25/50/100 per page
  - [ ] Next/previous buttons
  - [ ] Jump to page
- [ ] Mobile responsive
  - [ ] Stacked layout on small screens
  - [ ] Horizontal scroll for table
- [ ] Performance
  - [ ] <2 seconds initial load
  - [ ] Smooth scrolling
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/dashboard/templates/device_detail.html (CREATE)
[ ] src/dashboard/static/css/device_detail.css (CREATE)
[ ] src/dashboard/static/js/device_detail.js (CREATE)
[ ] tests/frontend/test_device_detail_ui.js (CREATE)
```

**Dependencies:**
- [ ] Task 1.2 complete (device detail API)

**Deliverables:**
- [ ] Device detail page fully functional
- [ ] All information displayed correctly
- [ ] <2 second load time
- [ ] Mobile responsive
- [ ] Frontend tests passing

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 1.4: Threat Summary Per Device
**Target Completion:** 2025-12-03
**Owner:** Junior Engineer

**Checklist:**
- [ ] Define threat scoring algorithm
  - [ ] Malware connections: weight 10
  - [ ] C2 connections: weight 10
  - [ ] Proxy connections: weight 3
  - [ ] Suspicious geo: weight 5
- [ ] Implement threat_score() function
  - [ ] Query connections for device
  - [ ] Calculate scores
  - [ ] Aggregate into device score
- [ ] Implement threat level classification
  - [ ] Low: 0-5
  - [ ] Medium: 5-20
  - [ ] High: 20+
- [ ] Add threat categories
  - [ ] Malware (from threat feed)
  - [ ] C2 (from threat feed)
  - [ ] Proxy/VPN (from IP reputation)
  - [ ] Suspicious geography (anomaly)
- [ ] Update device list API
  - [ ] Include threat_level in device response
  - [ ] Include threat_count
- [ ] Update device detail API
  - [ ] Include breakdown by threat category
  - [ ] Include specific threat indicators
- [ ] Write tests
  - [ ] Scoring accuracy
  - [ ] Category detection
  - [ ] Level classification
- [ ] Documentation
  - [ ] Threat scoring explanation
  - [ ] Calibration notes
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/core/threat_scoring.py (CREATE)
[ ] src/storage/database.py (UPDATE - threat queries)
[ ] tests/test_threat_scoring.py (CREATE)
```

**Dependencies:**
- [ ] Phase 0 complete (connection data)

**Deliverables:**
- [ ] Threat scoring working
- [ ] Tests passing
- [ ] API returning threat scores

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 1.5: Connection Filtering by Device
**Target Completion:** 2025-12-05
**Owner:** Junior Engineer

**Checklist:**
- [ ] Add device filter to /api/connections endpoint
  - [ ] filter[device_mac]=MAC
  - [ ] filter[threat_level]=high|medium|low
  - [ ] filter[country]=CC (2-letter code)
- [ ] Implement multi-device filter
  - [ ] Show connections from multiple devices
  - [ ] Useful for finding coordinated activity
- [ ] Update dashboard filtering UI
  - [ ] Device selector (dropdown or autocomplete)
  - [ ] Threat level filter
  - [ ] Geographic filter
  - [ ] Combined filter visualization
- [ ] Write tests
  - [ ] Single device filter
  - [ ] Multi-device filter
  - [ ] Combined filters accuracy
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/dashboard/server.py (UPDATE - connection filtering)
[ ] src/dashboard/templates/ (UPDATE - add filter controls)
[ ] tests/test_connection_filtering.py (CREATE)
```

**Dependencies:**
- [ ] Task 1.2 complete (device detail API)
- [ ] Task 1.4 complete (threat scoring)

**Deliverables:**
- [ ] Filtering working correctly
- [ ] UI shows filter options
- [ ] Tests passing

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 1.6: Activity Timeline View
**Target Completion:** 2025-12-08
**Owner:** Frontend Engineer

**Checklist:**
- [ ] Fetch device activity history
  - [ ] First seen timestamp
  - [ ] Online/offline periods
  - [ ] Threat events
  - [ ] IP changes
- [ ] Create timeline data structure
  - [ ] Events with timestamps
  - [ ] Event types (discovered, threat, offline)
  - [ ] Event metadata
- [ ] Implement timeline visualization
  - [ ] Use Chart.js or D3.js
  - [ ] Horizontal timeline
  - [ ] Time axis (day/week/month)
- [ ] Color coding
  - [ ] Green: online/active
  - [ ] Gray: offline
  - [ ] Red: threat detected
  - [ ] Yellow: anomaly
- [ ] Interactive features
  - [ ] Hover for details
  - [ ] Click event for more info
  - [ ] Zoom in/out on timeline
  - [ ] Pan left/right
- [ ] Performance
  - [ ] Smooth rendering for 30+ events
  - [ ] Responsive to window resize
- [ ] Mobile support
  - [ ] Responsive on small screens
  - [ ] Touch-friendly zoom/pan
- [ ] Write tests
  - [ ] Data structure correct
  - [ ] Timeline renders
  - [ ] Interactive features work
- [ ] Code review
- [ ] Merge to main

**Files to Modify/Create:**
```
[ ] src/dashboard/templates/device_timeline.html (CREATE)
[ ] src/dashboard/static/js/timeline.js (CREATE)
[ ] src/dashboard/static/css/timeline.css (CREATE)
[ ] tests/frontend/test_timeline.js (CREATE)
```

**Dependencies:**
- [ ] Task 1.3 complete (device detail UI)

**Deliverables:**
- [ ] Timeline visualization working
- [ ] Interactive features functional
- [ ] Mobile responsive
- [ ] Tests passing

**Comments/Notes:**
```
_____________________________________________

```

---

### Task 1.7: MVP Testing & Documentation
**Target Completion:** 2025-12-12
**Owner:** QA/Docs Engineer

**Checklist:**
- [ ] End-to-end testing
  - [ ] Scenario 1: New device appears → see it in inventory
  - [ ] Scenario 2: Click device → see connections
  - [ ] Scenario 3: Identify suspicious device
  - [ ] Scenario 4: Filter connections by device
  - [ ] Scenario 5: Track device activity over time
- [ ] Performance testing
  - [ ] Device list: <500ms for 100 devices
  - [ ] Device detail: <2s for 1000+ connections
  - [ ] Timeline: smooth rendering, <1s load
  - [ ] Concurrent users: 5 simultaneous dashboard users
- [ ] Stress testing
  - [ ] 1000+ devices active
  - [ ] 10000+ connections total
  - [ ] Auto-refresh every 30 seconds
  - [ ] No memory leaks over 1 hour
- [ ] Browser compatibility
  - [ ] Chrome, Firefox, Safari, Edge
  - [ ] Mobile browsers (iOS Safari, Chrome Mobile)
- [ ] Accessibility
  - [ ] Color not only differentiator
  - [ ] Keyboard navigation
  - [ ] Screen reader compatible
- [ ] Data consistency
  - [ ] Device list matches database
  - [ ] Connection counts correct
  - [ ] Threat scores consistent
- [ ] Documentation
  - [ ] Operations Guide (Phase 0-1)
  - [ ] User Guide (using dashboard)
  - [ ] API Reference (all endpoints)
  - [ ] Troubleshooting (common issues)
  - [ ] Performance baseline (query times, resource usage)
- [ ] Sign-off
  - [ ] All tests passing
  - [ ] Performance criteria met
  - [ ] Documentation complete
  - [ ] Ready for production testing

**Documents to Create:**
```
[ ] docs/PHASE01_OPERATIONS_GUIDE.md
[ ] docs/USER_GUIDE_DEVICES.md
[ ] docs/API_REFERENCE_PHASE01.md
[ ] docs/TROUBLESHOOTING_DASHBOARD.md
[ ] docs/PERFORMANCE_BASELINE.md
[ ] Test reports with metrics
```

**Deliverables:**
- [ ] All acceptance tests passing
- [ ] Performance benchmarks met
- [ ] Documentation complete
- [ ] MVP ready for production testing

**Comments/Notes:**
```
_____________________________________________

```

---

## ✅ PHASE 1 SIGN-OFF

**MVP Milestone:** Week 10 (2025-12-15)

**Go/No-Go Checklist:**
- [ ] All Phase 0 tasks complete
- [ ] All Phase 1 tasks complete
- [ ] >90% test coverage
- [ ] Performance benchmarks met
- [ ] Documentation complete
- [ ] Security audit (pre-Phase 5)
- [ ] Operations team trained
- [ ] Stakeholder approval

**Sign-Off:**
- Engineering Lead: _______ Date: _______
- Product Manager: _______ Date: _______
- Security Officer: _______ Date: _______
- Operations Lead: _______ Date: _______

---

## 📊 PHASES 2-5 SUMMARY

### Phase 2: Forensic Intelligence (Weeks 8-13)
- [ ] Advanced search interface
- [ ] Full connection history
- [ ] Timeline visualization
- [ ] CSV/JSON export
- [ ] Threat drill-down

### Phase 3: Origin Tracing (Weeks 14-21)
- [ ] Reverse DNS integration
- [ ] Hostname resolution
- [ ] Proxy/VPN detection
- [ ] DNS correlation

### Phase 4: Multi-Site Enterprise (Weeks 22-33)
- [ ] Central dashboard
- [ ] Agent deployment
- [ ] Cross-site correlation
- [ ] SIEM integration
- [ ] Alert rules engine

### Phase 5: Security Hardening (Weeks 34-38)
- [ ] Security patches
- [ ] Performance optimization
- [ ] High availability
- [ ] Docker/K8s deployment
- [ ] Production readiness

---

## 🎯 WEEKLY STANDUP TEMPLATE

**Week: _______ (2025-____-____)**

### Completed This Week
- [ ] Task: ________________ | Status: ✅
- [ ] Task: ________________ | Status: ✅
- [ ] Task: ________________ | Status: ✅

### In Progress
- [ ] Task: ________________ | Completion: __% | Blocker: _______
- [ ] Task: ________________ | Completion: __% | Blocker: _______

### Blocked/Issues
- [ ] Issue: ________________ | Resolution: _________
- [ ] Issue: ________________ | Resolution: _________

### Next Week Plan
- [ ] Task: ________________ | Owner: _________ | Target: _______
- [ ] Task: ________________ | Owner: _________ | Target: _______

### Metrics
- Lines of code added: ________
- Tests written: ________
- Code coverage: ________%
- Performance regressions: ________

**Notes:**
```
_____________________________________________

```

---

**This checklist is a living document. Update weekly during standups.**

**For questions, contact the CobaltGraph project lead.**
