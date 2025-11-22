-- CobaltGraph Phase 0 - Device Inventory Schema
-- Migration 001: Device Discovery and Tracking
-- Date: 2025-11-19
-- PostgreSQL 12+

-- ============================================================================
-- DEVICES TABLE
-- ============================================================================
-- Tracks all discovered network devices via passive ARP monitoring
-- Primary key: MAC address (unique hardware identifier)

CREATE TABLE IF NOT EXISTS devices (
    -- Identity
    mac_address VARCHAR(17) PRIMARY KEY,  -- Format: AA:BB:CC:DD:EE:FF
    ip_address INET,                      -- Current IP address

    -- Device Information
    vendor VARCHAR(255),                  -- Manufacturer from OUI lookup
    device_type VARCHAR(50),              -- Computed: router, desktop, mobile, iot, unknown
    hostname VARCHAR(255),                -- Reverse DNS hostname (Phase 3)

    -- Timestamps (all stored as TIMESTAMP WITH TIME ZONE)
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'discovered',  -- discovered, active, idle, offline
    confidence_score REAL DEFAULT 0.0,   -- 0.0-1.0: confidence in device classification

    -- Metadata (JSONB for flexible storage)
    metadata JSONB DEFAULT '{}'::jsonb,  -- IP history, notes, custom fields

    -- Statistics
    connection_count INTEGER DEFAULT 0,  -- Total connections from this device
    threat_count INTEGER DEFAULT 0,      -- Connections to threat IPs

    -- Indexing
    CONSTRAINT valid_status CHECK (status IN ('discovered', 'active', 'idle', 'offline')),
    CONSTRAINT valid_confidence CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0)
);

-- ============================================================================
-- CONNECTIONS TABLE (Enhanced from existing SQLite schema)
-- ============================================================================
-- Network connections with geolocation and threat intelligence

CREATE TABLE IF NOT EXISTS connections (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,

    -- Timestamps
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Source (local device)
    src_mac VARCHAR(17),                 -- Links to devices table
    src_ip INET,

    -- Destination (remote)
    dst_ip INET NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol VARCHAR(10) DEFAULT 'TCP',  -- TCP, UDP, ICMP, etc.

    -- Geolocation
    dst_country VARCHAR(2),              -- ISO 2-letter country code
    dst_lat REAL,
    dst_lon REAL,
    dst_org VARCHAR(255),
    dst_hostname VARCHAR(255),

    -- Threat Intelligence
    threat_score REAL DEFAULT 0.0,
    threat_category VARCHAR(50),         -- malware, c2, proxy, suspicious_geo, etc.

    -- Metadata (JSONB for flexible threat intel storage)
    metadata JSONB DEFAULT '{}'::jsonb,  -- Threat details, DNS info, etc.

    -- Foreign key to devices
    CONSTRAINT fk_device FOREIGN KEY (src_mac) REFERENCES devices(mac_address) ON DELETE SET NULL,
    CONSTRAINT valid_port CHECK (dst_port >= 0 AND dst_port <= 65535),
    CONSTRAINT valid_threat_score CHECK (threat_score >= 0.0 AND threat_score <= 10.0)
);

-- ============================================================================
-- DEVICE_EVENTS TABLE
-- ============================================================================
-- Audit trail for device lifecycle events

CREATE TABLE IF NOT EXISTS device_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Device reference
    device_mac VARCHAR(17) NOT NULL,

    -- Event details
    event_type VARCHAR(50) NOT NULL,     -- discovered, active, idle, offline, ip_changed
    old_value TEXT,                      -- Previous state (e.g., old IP)
    new_value TEXT,                      -- New state (e.g., new IP)

    -- Context
    metadata JSONB DEFAULT '{}'::jsonb,  -- Additional event context

    CONSTRAINT fk_device_event FOREIGN KEY (device_mac) REFERENCES devices(mac_address) ON DELETE CASCADE,
    CONSTRAINT valid_event_type CHECK (event_type IN (
        'discovered', 'active', 'idle', 'offline', 'ip_changed', 'threat_detected'
    ))
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Devices table indexes
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor);

-- Connections table indexes (optimized for queries)
CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_connections_src_mac ON connections(src_mac);
CREATE INDEX IF NOT EXISTS idx_connections_dst_ip ON connections(dst_ip);
CREATE INDEX IF NOT EXISTS idx_connections_threat_score ON connections(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_connections_device_time ON connections(src_mac, timestamp DESC);

-- Device events indexes
CREATE INDEX IF NOT EXISTS idx_events_device ON device_events(device_mac);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON device_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON device_events(event_type);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_devices_status_last_seen ON devices(status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_connections_mac_threat ON connections(src_mac, threat_score DESC);

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active devices view (seen in last 30 minutes)
CREATE OR REPLACE VIEW active_devices AS
SELECT
    mac_address,
    ip_address,
    vendor,
    device_type,
    hostname,
    last_seen,
    connection_count,
    threat_count,
    status
FROM devices
WHERE last_seen > NOW() - INTERVAL '30 minutes'
ORDER BY last_seen DESC;

-- Device summary with connection stats
CREATE OR REPLACE VIEW device_summary AS
SELECT
    d.mac_address,
    d.ip_address,
    d.vendor,
    d.device_type,
    d.status,
    d.first_seen,
    d.last_seen,
    d.connection_count,
    d.threat_count,
    COUNT(DISTINCT c.dst_ip) AS unique_destinations,
    MAX(c.timestamp) AS last_connection
FROM devices d
LEFT JOIN connections c ON d.mac_address = c.src_mac
GROUP BY d.mac_address, d.ip_address, d.vendor, d.device_type, d.status,
         d.first_seen, d.last_seen, d.connection_count, d.threat_count
ORDER BY d.last_seen DESC;

-- ============================================================================
-- FUNCTIONS FOR DEVICE STATE MANAGEMENT
-- ============================================================================

-- Function to update device status based on activity
CREATE OR REPLACE FUNCTION update_device_status()
RETURNS TRIGGER AS $$
BEGIN
    -- When a new connection is recorded, update device to 'active'
    UPDATE devices
    SET
        status = 'active',
        last_activity = NEW.timestamp,
        connection_count = connection_count + 1
    WHERE mac_address = NEW.src_mac;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update device status on connection
CREATE TRIGGER trigger_update_device_status
AFTER INSERT ON connections
FOR EACH ROW
EXECUTE FUNCTION update_device_status();

-- Function to log device events
CREATE OR REPLACE FUNCTION log_device_event()
RETURNS TRIGGER AS $$
BEGIN
    -- Log status changes
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO device_events (device_mac, event_type, old_value, new_value)
        VALUES (NEW.mac_address, NEW.status, OLD.status, NEW.status);
    END IF;

    -- Log IP changes
    IF OLD.ip_address IS DISTINCT FROM NEW.ip_address THEN
        INSERT INTO device_events (device_mac, event_type, old_value, new_value)
        VALUES (NEW.mac_address, 'ip_changed',
                HOST(OLD.ip_address)::TEXT, HOST(NEW.ip_address)::TEXT);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to log device changes
CREATE TRIGGER trigger_log_device_changes
AFTER UPDATE ON devices
FOR EACH ROW
EXECUTE FUNCTION log_device_event();

-- ============================================================================
-- SEED DATA & COMMENTS
-- ============================================================================

COMMENT ON TABLE devices IS 'Network devices discovered via passive ARP monitoring';
COMMENT ON TABLE connections IS 'Network connections with geolocation and threat intelligence';
COMMENT ON TABLE device_events IS 'Audit trail for device lifecycle events';

COMMENT ON COLUMN devices.mac_address IS 'Unique hardware address (primary key)';
COMMENT ON COLUMN devices.status IS 'Device state: discovered (new), active (<30m), idle (30m-1h), offline (>1h)';
COMMENT ON COLUMN devices.metadata IS 'JSONB field for IP history, custom notes, etc.';

COMMENT ON COLUMN connections.metadata IS 'JSONB field for threat intel details, DNS records, etc.';

-- Migration complete
SELECT 'Migration 001 completed successfully' AS status;
