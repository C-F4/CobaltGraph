# CobaltGraph Configuration Guide

This directory contains all configuration files for the CobaltGraph Geo-Watchfloor system.

## Configuration Files

### 1. `cobaltgraph.conf` - Main Configuration
Primary system settings including:
- Network capture method (auto/grey_man/ss)
- Dashboard settings (port, host, authentication)
- Data retention and database limits
- Feature toggles
- Raspberry Pi optimizations

**Key Settings to Configure:**
- `capture_method`: Set to `auto` for intelligent fallback
- `web_host`: Use `0.0.0.0` to allow remote access (security risk!)
- `enable_auth`: Set to `true` for production deployments
- `retention_days`: Auto-delete old data to save space

### 2. `auth.conf` - Authentication Credentials
Basic HTTP authentication for web dashboard.

**SECURITY CRITICAL:**
```bash
chmod 600 config/auth.conf  # Restrict permissions
```

**Default credentials:**
- Username: `admin`
- Password: `changeme` (CHANGE THIS!)

### 3. `threat_intel.conf` - API Keys
External threat intelligence service configuration.

**Supported Services:**
- **AbuseIPDB** (Free: 1,000 checks/day)
  - Sign up: https://www.abuseipdb.com/api
  - Add key to `[AbuseIPDB] api_key`
  - Set `enabled = true`

- **VirusTotal** (Free: 500 requests/day, 4 req/min)
  - Sign up: https://www.virustotal.com/gui/join-us
  - Add key to `[VirusTotal] api_key`
  - Set `enabled = true`

**SECURITY CRITICAL:**
```bash
chmod 600 config/threat_intel.conf  # Restrict permissions
```

## Quick Start

### 1. First-Time Setup
```bash
# Set secure permissions
chmod 600 config/auth.conf config/threat_intel.conf

# Edit main config
nano config/cobaltgraph.conf

# Change default password
nano config/auth.conf

# Add API keys (optional but recommended)
nano config/threat_intel.conf
```

### 2. Enable Authentication
```bash
# Edit cobaltgraph.conf
[Dashboard]
enable_auth = true

# Edit auth.conf
[BasicAuth]
username = your_username
password = your_strong_password
```

### 3. Enable Threat Intelligence
```bash
# Get free API keys from:
# - AbuseIPDB: https://www.abuseipdb.com/api
# - VirusTotal: https://www.virustotal.com/gui/join-us

# Edit threat_intel.conf
[AbuseIPDB]
api_key = your_abuseipdb_key
enabled = true

[VirusTotal]
api_key = your_virustotal_key
enabled = true
```

### 4. Raspberry Pi Optimization
```bash
# Edit cobaltgraph.conf for low-power mode
[RaspberryPi]
enable_low_power_mode = true
pi_worker_threads = 2

[General]
retention_days = 7  # Delete old data to save space
```

## Configuration Validation

CobaltGraph validates configuration on startup and will show:
- ✅ Valid settings (green)
- ⚠️  Warnings for defaults/missing API keys (yellow)
- ❌ Errors for invalid values (red)

Example startup output:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CobaltGraph Configuration Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Network Capture:
  ✅ Method: auto (grey_man → ss fallback)
  ✅ Interface: auto-detect

Threat Intelligence:
  ✅ VirusTotal: ENABLED (API key configured)
  ✅ AbuseIPDB: ENABLED (API key configured)
  ⚠️  Using fallback priority chain

Dashboard:
  ✅ Web: http://127.0.0.1:8080
  ⚠️  Authentication: DISABLED (enable for production!)

Features:
  ✅ ML Anomaly Detection: ENABLED
  ✅ CSV/JSON Export: ENABLED
  ⚠️  Webhooks: PLANNED (not implemented)
```

## Environment Variables (Alternative to Config Files)

You can also use environment variables (useful for Docker):

```bash
# Main settings
export SUARON_CAPTURE_METHOD=auto
export SUARON_WEB_PORT=8080
export SUARON_ENABLE_AUTH=true

# Authentication
export SUARON_AUTH_USERNAME=admin
export SUARON_AUTH_PASSWORD=secure_password

# API Keys
export SUARON_ABUSEIPDB_KEY=your_key_here
export SUARON_VIRUSTOTAL_KEY=your_key_here
```

Environment variables override config file settings.

## Troubleshooting

### "Permission denied" when reading config
```bash
# Fix: Ensure files are readable
chmod 644 config/cobaltgraph.conf
chmod 600 config/auth.conf config/threat_intel.conf
```

### "API key invalid" errors
```bash
# Verify your API keys are active:
# AbuseIPDB: https://www.abuseipdb.com/account/api
# VirusTotal: https://www.virustotal.com/gui/user/[your-user]/apikey

# Test API key manually:
curl -H "Key: YOUR_KEY" https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8
```

### "Port 8080 already in use"
```bash
# Option 1: Kill existing process
lsof -ti:8080 | xargs kill -9

# Option 2: Change port in config
[Dashboard]
web_port = 8081
```

### Grey Man capture fails
```bash
# Requires sudo/root for raw sockets
sudo ./cobaltgraph_startup.sh

# OR set capture_method to 'ss' in config
[Network]
capture_method = ss
```

## Security Best Practices

1. **Never commit auth.conf or threat_intel.conf to git**
   ```bash
   echo "config/auth.conf" >> .gitignore
   echo "config/threat_intel.conf" >> .gitignore
   ```

2. **Use strong passwords**
   ```bash
   # Generate random password
   openssl rand -base64 32
   ```

3. **Restrict config file permissions**
   ```bash
   chmod 600 config/auth.conf config/threat_intel.conf
   chmod 644 config/cobaltgraph.conf
   ```

4. **Enable authentication for production**
   ```ini
   [Dashboard]
   enable_auth = true
   web_host = 127.0.0.1  # Localhost only
   ```

5. **Rotate API keys regularly**
   - Review API usage monthly
   - Regenerate keys if compromised

## Legal Disclaimer

**IMPORTANT:** Only use CobaltGraph to monitor networks you have explicit legal authorization to monitor. Unauthorized network monitoring may violate:
- Computer Fraud and Abuse Act (CFAA) in the US
- Computer Misuse Act in the UK
- Similar laws in other jurisdictions

Always obtain written permission before deploying on any network you do not own.

## Support

For issues or questions:
- Check logs: `logs/cobaltgraph_YYYYMMDD.log`
- Run health check: `./check_health.sh`
- Review documentation: `docs/` directory
- GitHub issues: [Your GitHub repo]
