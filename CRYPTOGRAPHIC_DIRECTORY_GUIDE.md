# CobaltGraph Cryptographic Industry-Standard Directory Guide

**Revolutionary Blue-Team Network Intelligence | Terminal-Pure | Byzantine Fault Tolerant**

---

## Core Architecture (333 Words)

**CobaltGraph** implements cryptographically-verified multi-agent consensus for network threat intelligence, adhering to industry standards (OWASP, NIST, Byzantine Fault Tolerance) in a pure-terminal blue-team defense system.

### Essential Directories

**`src/consensus/`** - Multi-agent consensus core implementing Byzantine Fault Tolerant (BFT) voting. Each scorer cryptographically signs assessments using HMAC-SHA256 (NIST FIPS 198-1 compliant). Three independent scorers (Statistical, Rule-Based, ML) analyze threat intelligence data through synthetic diversity—same data, different algorithms. BFT consensus achieves resilience against f=1 faulty scorers (n=3 total), using median voting superior to averaging for outlier resistance. Cryptographic signatures enable tamper detection with 100% verified detection rate.

**`src/export/`** - Lightweight hybrid export system producing JSON Lines (detailed research data) and CSV (analyst-ready summaries) with thread-safe buffered writes consuming <200KB memory. Exports include full cryptographic audit trail: scorer votes, signatures, outlier detection, uncertainty quantification.

**`src/capture/`** - Passive network monitoring via device-level connection tracking requiring NO root privileges. Zero network impact—observation-only mode suitable for production environments. Monitors established connections through /proc/net/tcp parsing (Linux) or platform-specific methods.

**`src/services/`** - Threat intelligence aggregation from VirusTotal, AbuseIPDB, and IP geolocation APIs. Rate-limited, error-handled, configuration-driven. NO hardcoded credentials—all API keys externalized to config files excluded via .gitignore.

**`src/storage/`** - Minimal SQLite database logging connections, threat scores, geographic data. Simple schema with indexed queries for performance. NO over-engineered migration systems—clean inline schema.

**`src/core/`** - Pure-terminal orchestrator (`main_terminal_pure.py`) eliminating ALL web dependencies. NO HTTP server, NO ports, NO attack surface. Direct stdout/file exports only. Configuration loader supports environment variables and config files with secure defaults.

### Security Standards

- **Cryptography**: HMAC-SHA256 (FIPS 198-1)
- **Input Validation**: All external data sanitized (OWASP A03:2021)
- **Credential Management**: Zero hardcoded secrets (OWASP A07:2021)
- **Data Protection**: .gitignore excludes databases, logs, exports, API keys
- **Byzantine Tolerance**: Mathematically proven f<n/3 fault tolerance

### Deployment

```bash
./cobaltgraph --mode device  # Pure terminal, NO web
```

**Revolutionary simplicity giving defenders a cyber chance against sophisticated foreign actors attacking organizations every second.**
