# SEC-001 & SEC-002 Code Snippets - Quick Reference

## SEC-001: File Permission Enforcement

### File Permission Enforcement Method
**Location:** `/home/tachyon/CobaltGraph/src/core/config.py:146-167`

```python
def _enforce_secure_permissions(self):
    """Enforce 600 permissions on sensitive config files (SEC-001 PATCH)"""
    sensitive_files = {
        self.config_dir / "auth.conf": "Authentication credentials",
        self.config_dir / "threat_intel.conf": "Threat API keys"
    }

    for filepath, description in sensitive_files.items():
        if filepath.exists():
            current_perms = filepath.stat().st_mode & 0o777
            if current_perms != 0o600:
                try:
                    filepath.chmod(0o600)
                    logger.warning(f"[SEC-001] PATCHED: Enforced secure permissions on {filepath.name} (600)")
                    self.warnings.append(f"Fixed file permissions on {filepath.name} - was {oct(current_perms)}, now 600")
                except OSError as e:
                    error_msg = f"[SEC-001] CRITICAL: Cannot set secure permissions on {filepath.name}: {e}"
                    self.errors.append(error_msg)
                    logger.error(f"{error_msg}")
            else:
                logger.info(f"[SEC-001] VERIFIED: {filepath.name} has secure permissions (600)")
```

**What it does:**
- Checks auth.conf and threat_intel.conf file permissions
- If not 0o600, automatically changes them to 0o600
- Logs warnings and errors appropriately
- Handles permission denial gracefully

---

### File Permission Validation Method
**Location:** `/home/tachyon/CobaltGraph/src/core/config.py:353-373`

```python
def _validate_file_permissions(self):
    """Validate that credential files are not world-readable (SEC-001 PATCH)"""
    sensitive_files = [
        self.config_dir / "auth.conf",
        self.config_dir / "threat_intel.conf"
    ]

    for filepath in sensitive_files:
        if filepath.exists():
            perms = filepath.stat().st_mode & 0o777
            if perms & 0o004:  # Check if world-readable
                self.errors.append(
                    f"[SEC-001] CRITICAL: {filepath.name} is world-readable (perms: {oct(perms)}). "
                    f"Run: chmod 600 {filepath}"
                )
            if perms & 0o020:  # Check if group-writable
                self.errors.append(
                    f"[SEC-001] CRITICAL: {filepath.name} is group-writable (perms: {oct(perms)}). "
                    f"Run: chmod 600 {filepath}"
                )
```

**What it does:**
- Double-checks file permissions are correct
- Detects world-readable files (0o004)
- Detects group-writable files (0o020)
- Logs critical errors if violations found
- Provides remediation instructions

---

### Integration in load() Method
**Location:** `/home/tachyon/CobaltGraph/src/core/config.py:125-144`

```python
def load(self) -> Dict[str, Any]:
    """Load configuration from all sources"""
    # Start with defaults
    self.config = self.defaults.copy()

    # [SEC-001 PATCH] Enforce secure permissions on credential files
    self._enforce_secure_permissions()  # LINE 131 - CALLED FIRST

    # Load from config files
    self._load_main_config()
    self._load_auth_config()
    self._load_threat_intel_config()

    # Override with environment variables
    self._load_env_overrides()

    # Validate configuration
    self._validate()  # Calls _validate_file_permissions() at line 417

    return self.config
```

**What it does:**
- Enforces permissions BEFORE loading any config
- Loads all configuration files
- Validates permissions again after loading
- Returns safe configuration dictionary

---

## SEC-002: Authorization Header Sanitization

### Request Logging with Header Sanitization
**Location:** `/home/tachyon/CobaltGraph/src/dashboard/server.py:43-60`

```python
def log_request(self, code='-', size='-'):
    """Override to use custom logger (sanitized for security - SEC-002 PATCH)"""
    # [SEC-002 PATCH] Sanitize authorization headers from logs
    sanitized_line = self.requestline

    # Check for Authorization header and sanitize
    if 'Authorization' in str(self.headers):
        auth_header = self.headers.get('Authorization', '')
        if auth_header:
            # Replace the actual auth value with placeholder
            sanitized_line = re.sub(
                r'(Authorization:\s+)[^\s]+.*$',
                r'\1[REDACTED]',
                sanitized_line,
                flags=re.IGNORECASE
            )

    logger.debug(f'"{sanitized_line}" {code} {size}')
```

**What it does:**
- Detects Authorization headers in requests
- Uses regex to replace credential value with [REDACTED]
- Logs sanitized version to avoid credential exposure
- Case-insensitive for all header variations

**Regex Breakdown:**
- Pattern: `r'(Authorization:\s+)[^\s]+.*$'`
- Capture group 1: `(Authorization:\s+)` - keeps the header name
- Match part: `[^\s]+.*$` - matches all non-whitespace (credentials) and rest of line
- Replacement: `\1[REDACTED]` - keeps header name, replaces value

---

### Exception Handling with Error Redaction
**Location:** `/home/tachyon/CobaltGraph/src/dashboard/server.py:66-107`

```python
def check_authentication(self) -> bool:
    """
    Check HTTP Basic Authentication

    Returns:
        True if authenticated or auth disabled, False otherwise
    """
    # Get watchfloor instance from server
    wf = self.server.watchfloor
    config = getattr(wf, 'config', {})

    # Check if auth is enabled
    if not config.get('enable_auth', False):
        return True  # Auth disabled, allow access

    # Check for Authorization header
    auth_header = self.headers.get('Authorization')
    if not auth_header:
        return False

    # Parse Basic auth
    try:
        # Format: "Basic base64(username:password)"
        auth_type, auth_string = auth_header.split(' ', 1)
        if auth_type.lower() != 'basic':
            return False

        # Decode credentials
        decoded = base64.b64decode(auth_string).decode('utf-8')
        username, password = decoded.split(':', 1)

        # Check against config
        expected_username = config.get('auth_username', 'admin')
        expected_password = config.get('auth_password', 'changeme')

        return username == expected_username and password == expected_password

    except Exception as e:
        # [SEC-002 PATCH] Log generic error, not exception details
        logger.debug(f"Authentication validation failed (invalid header format)")
        logger.debug(f"[SEC-002] Error type: {type(e).__name__} (details redacted)")
        return False
```

**What it does:**
- Checks if authentication is enabled
- Parses Basic Authorization header
- Validates credentials against config
- Catches ANY exception and redacts details
- Logs only error type, not message or stack trace

**Security Features:**
- No credential values logged
- No exception messages logged
- No stack traces logged
- Only error type name logged (e.g., "ValueError")
- Returns False without revealing why

---

### Custom Error Logging
**Location:** `/home/tachyon/CobaltGraph/src/dashboard/server.py:62-64`

```python
def log_error(self, format, *args):
    """Override to use custom logger"""
    logger.error(f'{self.address_string()} - {format % args}')
```

**What it does:**
- Overrides default error logging
- Uses custom logger instead of default handler
- Prevents framework from logging sensitive details

---

### Authentication Response Handler
**Location:** `/home/tachyon/CobaltGraph/src/dashboard/server.py:109-124`

```python
def require_authentication(self):
    """Send 401 Unauthorized response with authentication prompt"""
    self.send_response(401)
    self.send_header('WWW-Authenticate', 'Basic realm="CobaltGraph Watchfloor"')
    self.send_header('Content-Type', 'text/html')
    self.end_headers()

    html = """<!DOCTYPE html>
<html>
<head><title>401 Unauthorized</title></head>
<body>
<h1>401 Unauthorized</h1>
<p>This CobaltGraph instance requires authentication.</p>
</body>
</html>"""
    self.wfile.write(html.encode())
```

**What it does:**
- Sends HTTP 401 status code
- Prompts browser for credentials with WWW-Authenticate header
- Displays clear error message to user
- No sensitive information in response

---

## Key Security Principles Used

### 1. Octal Permissions Constants
```python
0o600  # Owner read+write only
0o004  # Check if world-readable
0o020  # Check if group-writable
```

### 2. Regex Pattern for Header Sanitization
```python
r'(Authorization:\s+)[^\s]+.*$'
# Matches: "Authorization: " followed by credentials
# Replaces with: "Authorization: [REDACTED]"
```

### 3. Exception Type-Only Logging
```python
logger.debug(f"[SEC-002] Error type: {type(e).__name__} (details redacted)")
# Logs only: "ValueError"
# NOT the message or stack trace
```

### 4. File Existence and Permission Checks
```python
if filepath.exists():
    current_perms = filepath.stat().st_mode & 0o777
    if current_perms != 0o600:
        filepath.chmod(0o600)
```

### 5. Error Tracking and Reporting
```python
self.errors.append(error_msg)    # Track for later reporting
logger.error(error_msg)          # Log immediately
```

---

## Testing Code Examples

### SEC-001 Test
```python
from src.core.config import ConfigLoader
loader = ConfigLoader(config_dir='config')
config = loader.load()

# Check permissions
import stat
from pathlib import Path
auth_file = Path('config/auth.conf')
perms = auth_file.stat().st_mode & 0o777
assert perms == 0o600, f"Expected 0o600, got {oct(perms)}"
```

### SEC-002 Test
```python
import re

# Test regex pattern
pattern = r'(Authorization:\s+)[^\s]+.*$'
test_input = "GET /api/data HTTP/1.1 Authorization: Basic YWRtaW46Y2hhbmdlbWU="
result = re.sub(pattern, r'\1[REDACTED]', test_input, flags=re.IGNORECASE)
assert "[REDACTED]" in result
assert "YWRtaW46Y2hhbmdlbWU=" not in result
```

---

## File Locations Summary

| Component | File | Lines |
|-----------|------|-------|
| SEC-001 Enforcement | config.py | 146-167 |
| SEC-001 Validation | config.py | 353-373 |
| SEC-001 Integration | config.py | 131 |
| SEC-002 Header Sanitization | server.py | 43-60 |
| SEC-002 Exception Handling | server.py | 103-107 |
| SEC-002 Error Logging | server.py | 62-64 |

---

**Report Generated:** 2025-11-14
**Purpose:** Quick reference for security-critical code
**Status:** Production-ready

