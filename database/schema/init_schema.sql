-- CobaltGraph Database Schema
-- Optimized for scaling and graphical visualization with all 8 tool integrations
--
-- Components integrated:
-- 1. Database - Core storage with WAL mode
-- 2. Capture - Network packet capture data
-- 3. Pipeline - Data processing pipeline
-- 4. Consensus - BFT threat scoring
-- 5. GeoIP - Geolocation data
-- 6. ASN - ASN/Organization lookup
-- 7. Reputation - IP reputation from threat intel feeds
-- 8. Dashboard - Real-time visualization support
--
-- Performance features:
-- - WAL mode for concurrent reads/writes
-- - Composite indexes for common dashboard queries
-- - Materialized views for aggregations
-- - Partitioned time-series data support
-- - JSON columns for flexible metadata

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Main connections table - the heart of CobaltGraph
-- Optimized for time-series visualization and threat analysis
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,

    -- Source information (capture component)
    src_mac TEXT,
    src_ip TEXT,
    src_port INTEGER,

    -- Destination information
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    dst_hostname TEXT,
    protocol TEXT DEFAULT 'TCP',

    -- GeoIP enrichment (geo_engine component)
    dst_country TEXT,
    dst_country_code TEXT,
    dst_city TEXT,
    dst_lat REAL,
    dst_lon REAL,
    dst_timezone TEXT,

    -- ASN enrichment (asn_lookup component)
    dst_asn INTEGER,
    dst_asn_name TEXT,
    dst_org TEXT,
    dst_org_type TEXT,  -- isp, hosting, enterprise, cloud, tor_proxy, vpn, government, education
    dst_cidr TEXT,
    org_trust_score REAL,  -- 0.0-1.0 trust score

    -- Network path analysis (capture/pipeline)
    ttl_observed INTEGER,
    ttl_initial INTEGER,
    hop_count INTEGER,
    os_fingerprint TEXT,

    -- Threat scoring (consensus component)
    threat_score REAL DEFAULT 0,
    confidence REAL DEFAULT 0,
    high_uncertainty INTEGER DEFAULT 0,
    scoring_method TEXT DEFAULT 'consensus',
    scorer_agreement REAL,  -- How much scorers agreed (0.0-1.0)

    -- Reputation enrichment (reputation component)
    reputation_score REAL,           -- Combined reputation (0.0-1.0, lower is worse)
    virustotal_positives INTEGER,    -- VT positive detections
    virustotal_total INTEGER,        -- VT total scanners
    abuseipdb_score INTEGER,         -- AbuseIPDB confidence score
    is_known_malicious INTEGER DEFAULT 0,
    reputation_tags TEXT,            -- JSON array of tags

    -- Device tracking (dashboard component)
    device_vendor TEXT,
    device_type TEXT,

    -- Pipeline metadata
    enrichment_time_ms INTEGER,      -- How long enrichment took
    created_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Events table for alerts and system events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,        -- CONNECTION, THREAT, ALERT, SYSTEM, DEVICE, ANOMALY
    severity TEXT DEFAULT 'INFO',    -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    message TEXT,

    -- Related connection info
    source_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    threat_score REAL,

    -- Additional context
    org_name TEXT,
    country TEXT,
    rule_matched TEXT,               -- What rule/signature triggered this

    -- Flexible metadata
    metadata TEXT,                   -- JSON blob for additional data

    created_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Discovered devices table (for network mode)
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip_addresses TEXT,               -- JSON array of IPs
    vendor TEXT,
    hostname TEXT,
    device_type TEXT,                -- router, server, workstation, iot, mobile, unknown
    os_family TEXT,                  -- windows, linux, macos, ios, android, unknown

    -- Activity tracking
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    packet_count INTEGER DEFAULT 0,
    connection_count INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,

    -- Threat metrics
    threat_score_sum REAL DEFAULT 0,
    high_threat_count INTEGER DEFAULT 0,

    -- Behavioral metrics
    broadcast_count INTEGER DEFAULT 0,
    arp_count INTEGER DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    unique_ports INTEGER DEFAULT 0,

    -- Status
    is_active INTEGER DEFAULT 1,
    risk_flags TEXT,                 -- JSON array of risk flags
    notes TEXT,

    created_at REAL DEFAULT (strftime('%s', 'now')),
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- ============================================================================
-- AGGREGATION TABLES (for dashboard performance)
-- ============================================================================

-- Hourly aggregations for time-series charts
CREATE TABLE IF NOT EXISTS agg_hourly (
    hour_bucket INTEGER PRIMARY KEY,  -- Unix timestamp truncated to hour
    connection_count INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    unique_asns INTEGER DEFAULT 0,
    avg_threat REAL DEFAULT 0,
    max_threat REAL DEFAULT 0,
    high_threat_count INTEGER DEFAULT 0,
    medium_threat_count INTEGER DEFAULT 0,
    unique_countries INTEGER DEFAULT 0,
    bytes_total INTEGER DEFAULT 0,
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Country aggregations for globe visualization
CREATE TABLE IF NOT EXISTS agg_countries (
    country_code TEXT PRIMARY KEY,
    country_name TEXT,
    connection_count INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    avg_threat REAL DEFAULT 0,
    max_threat REAL DEFAULT 0,
    last_seen REAL,
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- ASN aggregations for network analysis
CREATE TABLE IF NOT EXISTS agg_asns (
    asn INTEGER PRIMARY KEY,
    asn_name TEXT,
    org_type TEXT,
    connection_count INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    avg_threat REAL DEFAULT 0,
    avg_trust REAL DEFAULT 0.5,
    last_seen REAL,
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Organization aggregations
CREATE TABLE IF NOT EXISTS agg_orgs (
    org_name TEXT PRIMARY KEY,
    org_type TEXT,
    asn INTEGER,
    connection_count INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    avg_threat REAL DEFAULT 0,
    trust_score REAL DEFAULT 0.5,
    last_seen REAL,
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- ============================================================================
-- THREAT INTELLIGENCE TABLES
-- ============================================================================

-- IP reputation cache (avoid repeated API calls)
CREATE TABLE IF NOT EXISTS ip_reputation_cache (
    ip TEXT PRIMARY KEY,
    reputation_score REAL,
    virustotal_positives INTEGER,
    virustotal_total INTEGER,
    abuseipdb_score INTEGER,
    is_known_malicious INTEGER DEFAULT 0,
    tags TEXT,                       -- JSON array
    first_seen REAL,
    last_checked REAL,
    check_count INTEGER DEFAULT 1,
    source TEXT,                     -- Which API provided the data
    expires_at REAL                  -- Cache expiration
);

-- Known threat indicators
CREATE TABLE IF NOT EXISTS threat_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,    -- ip, domain, asn, cidr, hash
    indicator_value TEXT NOT NULL,
    threat_type TEXT,                -- malware, c2, phishing, spam, tor, vpn, proxy
    severity TEXT DEFAULT 'MEDIUM',
    confidence REAL DEFAULT 0.5,
    source TEXT,                     -- Where this intel came from
    description TEXT,
    first_seen REAL,
    last_seen REAL,
    expires_at REAL,
    is_active INTEGER DEFAULT 1,
    metadata TEXT,                   -- JSON blob
    UNIQUE(indicator_type, indicator_value)
);

-- ============================================================================
-- SYSTEM TABLES
-- ============================================================================

-- Component health tracking (for dashboard heartbeat display)
CREATE TABLE IF NOT EXISTS component_health (
    component_name TEXT PRIMARY KEY,
    display_name TEXT,
    status TEXT DEFAULT 'DEAD',      -- ACTIVE, DEGRADED, DEAD
    health_percentage INTEGER DEFAULT 0,
    last_heartbeat REAL,
    message TEXT,
    is_critical INTEGER DEFAULT 0,
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Configuration storage
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT,
    value_type TEXT DEFAULT 'string', -- string, int, float, bool, json
    description TEXT,
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Primary time-series access (dashboard live view)
CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connections(timestamp DESC);

-- Threat dashboard queries
CREATE INDEX IF NOT EXISTS idx_conn_threat_time ON connections(threat_score DESC, timestamp DESC);

-- Device tracking
CREATE INDEX IF NOT EXISTS idx_conn_src_mac ON connections(src_mac);

-- IP lookups
CREATE INDEX IF NOT EXISTS idx_conn_dst_ip ON connections(dst_ip);
CREATE INDEX IF NOT EXISTS idx_conn_src_ip ON connections(src_ip);

-- ASN analysis
CREATE INDEX IF NOT EXISTS idx_conn_asn ON connections(dst_asn);

-- Organization analysis
CREATE INDEX IF NOT EXISTS idx_conn_org ON connections(dst_org);
CREATE INDEX IF NOT EXISTS idx_conn_org_type ON connections(dst_org_type);

-- Geographic queries (globe visualization)
CREATE INDEX IF NOT EXISTS idx_conn_country ON connections(dst_country);
CREATE INDEX IF NOT EXISTS idx_conn_geo ON connections(dst_lat, dst_lon);

-- Composite for geo-threat analysis
CREATE INDEX IF NOT EXISTS idx_conn_geo_threat ON connections(dst_country, threat_score DESC);

-- Time-range with filters (dashboard panels)
CREATE INDEX IF NOT EXISTS idx_conn_time_org ON connections(timestamp DESC, dst_org_type);
CREATE INDEX IF NOT EXISTS idx_conn_time_country ON connections(timestamp DESC, dst_country);

-- Reputation lookups
CREATE INDEX IF NOT EXISTS idx_conn_reputation ON connections(reputation_score);
CREATE INDEX IF NOT EXISTS idx_conn_malicious ON connections(is_known_malicious, timestamp DESC);

-- Event indexes
CREATE INDEX IF NOT EXISTS idx_event_time ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_event_severity ON events(severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type, timestamp DESC);

-- Device indexes
CREATE INDEX IF NOT EXISTS idx_device_last_seen ON devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_device_active ON devices(is_active, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_device_vendor ON devices(vendor);

-- Threat indicator indexes
CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threat_indicators(indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_threat_active ON threat_indicators(is_active, indicator_type);

-- IP reputation cache
CREATE INDEX IF NOT EXISTS idx_ip_cache_expires ON ip_reputation_cache(expires_at);

-- ============================================================================
-- VIEWS FOR DASHBOARD
-- ============================================================================

-- Real-time threat posture (last 5 minutes)
CREATE VIEW IF NOT EXISTS v_threat_posture AS
SELECT
    AVG(threat_score) as current_threat,
    COUNT(*) as total_connections,
    COUNT(CASE WHEN threat_score > 0.7 THEN 1 END) as critical_threats,
    COUNT(CASE WHEN threat_score > 0.4 AND threat_score <= 0.7 THEN 1 END) as high_threats,
    COUNT(CASE WHEN threat_score > 0.2 AND threat_score <= 0.4 THEN 1 END) as medium_threats,
    COUNT(DISTINCT dst_ip) as unique_destinations,
    COUNT(DISTINCT dst_asn) as unique_asns,
    COUNT(DISTINCT dst_country) as unique_countries,
    MAX(timestamp) as latest_timestamp
FROM connections
WHERE timestamp > (strftime('%s', 'now') - 300);

-- Geographic distribution (last hour)
CREATE VIEW IF NOT EXISTS v_geo_distribution AS
SELECT
    dst_country,
    dst_country_code,
    COUNT(*) as connection_count,
    AVG(threat_score) as avg_threat,
    MAX(threat_score) as max_threat,
    COUNT(DISTINCT dst_ip) as unique_ips,
    COUNT(DISTINCT dst_asn) as unique_asns
FROM connections
WHERE timestamp > (strftime('%s', 'now') - 3600)
  AND dst_country IS NOT NULL
GROUP BY dst_country, dst_country_code
ORDER BY connection_count DESC;

-- Organization analysis (last hour)
CREATE VIEW IF NOT EXISTS v_org_analysis AS
SELECT
    dst_org,
    dst_org_type,
    dst_asn,
    COUNT(*) as connection_count,
    AVG(threat_score) as avg_threat,
    MAX(threat_score) as max_threat,
    AVG(COALESCE(org_trust_score, 0.5)) as avg_trust,
    COUNT(DISTINCT dst_ip) as unique_ips
FROM connections
WHERE timestamp > (strftime('%s', 'now') - 3600)
  AND dst_org IS NOT NULL
GROUP BY dst_org, dst_org_type
ORDER BY connection_count DESC;

-- Top threats (last hour)
CREATE VIEW IF NOT EXISTS v_top_threats AS
SELECT
    dst_ip,
    dst_port,
    dst_org,
    dst_country,
    threat_score,
    confidence,
    reputation_score,
    timestamp
FROM connections
WHERE timestamp > (strftime('%s', 'now') - 3600)
  AND threat_score > 0.4
ORDER BY threat_score DESC, timestamp DESC
LIMIT 100;

-- Active devices (last 5 minutes)
CREATE VIEW IF NOT EXISTS v_active_devices AS
SELECT
    mac,
    json_extract(ip_addresses, '$[0]') as primary_ip,
    vendor,
    hostname,
    device_type,
    connection_count,
    CASE WHEN connection_count > 0
         THEN threat_score_sum / connection_count
         ELSE 0
    END as avg_threat,
    high_threat_count,
    last_seen,
    (strftime('%s', 'now') - last_seen) as seconds_ago
FROM devices
WHERE last_seen > (strftime('%s', 'now') - 300)
ORDER BY last_seen DESC;

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Initialize component health records
INSERT OR IGNORE INTO component_health (component_name, display_name, is_critical) VALUES
    ('database', 'Database', 1),
    ('capture', 'Capture', 0),
    ('pipeline', 'Pipeline', 1),
    ('consensus', 'Consensus', 0),
    ('geo_engine', 'GeoIP', 0),
    ('asn_lookup', 'ASN', 0),
    ('reputation', 'Reputation', 0),
    ('dashboard', 'Dashboard', 1);

-- Default configuration
INSERT OR IGNORE INTO config (key, value, value_type, description) VALUES
    ('version', '3.0.0', 'string', 'CobaltGraph version'),
    ('threat_threshold_high', '0.7', 'float', 'Threshold for high threat alerts'),
    ('threat_threshold_medium', '0.4', 'float', 'Threshold for medium threat alerts'),
    ('cache_ttl_geo', '86400', 'int', 'GeoIP cache TTL in seconds'),
    ('cache_ttl_asn', '86400', 'int', 'ASN cache TTL in seconds'),
    ('cache_ttl_reputation', '3600', 'int', 'Reputation cache TTL in seconds'),
    ('batch_size', '50', 'int', 'Database batch insert size'),
    ('batch_timeout', '0.5', 'float', 'Database batch timeout in seconds');
