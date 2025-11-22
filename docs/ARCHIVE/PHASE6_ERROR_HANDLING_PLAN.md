# PHASE 6: COMPREHENSIVE ERROR HANDLING

**Date**: November 11, 2025
**Status**: 🔄 **IN PROGRESS**
**Goal**: Implement robust error handling across all CobaltGraph modules

---

## 🎯 **OBJECTIVES**

1. **Graceful Degradation**: System continues with reduced features if optional components fail
2. **Comprehensive Logging**: All errors logged with context
3. **User-Friendly Messages**: Clear error messages for users
4. **Proper Cleanup**: Resources released on errors
5. **No Silent Failures**: All errors either handled or logged

---

## 📋 **ERROR HANDLING STRATEGY**

### **Critical vs Optional Components**

#### **Critical (Must Work)**:
- Configuration loading (with defaults as fallback)
- Database connection
- Main watchfloor orchestration
- Web server (if --interface web)

**Strategy**: Fail fast with clear error message if these fail

#### **Optional (Degradable)**:
- Threat intelligence (AbuseIPDB, VirusTotal)
- GeoIP lookups
- Terminal UI
- Network-wide capture (fallback to device-only)

**Strategy**: Log warning, continue without feature

---

## 🏗️ **IMPLEMENTATION PLAN**

### **Step 1: Create Error Handling Utilities**

Create `src/utils/errors.py`:
```python
class SUARONError(Exception):
    """Base exception for CobaltGraph"""
    pass

class ConfigurationError(SUARONError):
    """Configuration-related errors"""
    pass

class DatabaseError(SUARONError):
    """Database-related errors"""
    pass

class CaptureError(SUARONError):
    """Network capture errors"""
    pass

class IntegrationError(SUARONError):
    """Third-party integration errors"""
    pass
```

### **Step 2: Add Error Handling to Core Modules**

#### **A) src/core/config.py**
- Wrap file I/O in try/except
- Return defaults if config missing
- Log warnings for missing keys
- Validate critical settings

#### **B) src/core/watchfloor.py**
- Wrap component initialization
- Graceful degradation for optional features
- Cleanup on shutdown
- Handle SIGTERM/SIGINT properly

#### **C) src/storage/database.py**
- Connection retry logic
- Transaction rollback on errors
- Proper connection cleanup
- Migration error handling

#### **D) src/intelligence/ip_reputation.py**
- API timeout handling
- Rate limit detection
- Fallback to local scoring if APIs fail
- Cache errors to avoid repeated failures

#### **E) src/capture/network_monitor.py**
- Permission errors (not root)
- Interface not found
- Packet parsing errors
- Buffer overflow handling

#### **F) src/dashboard/server.py**
- Port already in use
- Request parsing errors
- Response generation errors
- Static file not found

### **Step 3: Enhanced Logging**

#### **Update logging configuration:**
```python
import logging
import logging.handlers

def setup_logging(log_level=logging.INFO):
    \"\"\"Configure comprehensive logging\"\"\"

    # Console handler (INFO and above)
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    ))

    # File handler (DEBUG and above)
    file_handler = logging.handlers.RotatingFileHandler(
        'logs/cobaltgraph.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s'
    ))

    # Root logger
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(console)
    root.addHandler(file_handler)
```

### **Step 4: Add Context Managers for Resource Cleanup**

```python
from contextlib import contextmanager

@contextmanager
def database_transaction(db):
    \"\"\"Ensure database transaction is committed or rolled back\"\"\"
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Transaction failed: {e}")
        raise
    finally:
        db.close()
```

### **Step 5: Add Retry Logic for Transient Failures**

```python
import time
from functools import wraps

def retry(max_attempts=3, delay=1, backoff=2, exceptions=(Exception,)):
    \"\"\"Retry decorator for transient failures\"\"\"
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay

            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        raise

                    logger.warning(
                        f"{func.__name__} failed (attempt {attempt}/{max_attempts}): {e}. "
                        f"Retrying in {current_delay}s..."
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff

        return wrapper
    return decorator
```

---

## 📝 **MODULES TO UPDATE**

### **Priority 1 (Critical Path)**
1. ✅ `src/core/config.py` - Configuration loading
2. ✅ `src/storage/database.py` - Database operations
3. ✅ `src/core/watchfloor.py` - Main orchestrator
4. ✅ `src/core/launcher.py` - Already has good error handling

### **Priority 2 (Optional Features)**
5. ✅ `src/intelligence/ip_reputation.py` - Threat intel
6. ✅ `src/capture/network_monitor.py` - Network capture
7. ✅ `src/dashboard/server.py` - Web server

### **Priority 3 (Utilities)**
8. ✅ `src/utils/heartbeat.py` - Health monitoring
9. ✅ Create `src/utils/errors.py` - Custom exceptions
10. ✅ Create `src/utils/logging_config.py` - Logging setup

---

## ✅ **SUCCESS CRITERIA**

- [ ] No unhandled exceptions in production
- [ ] All errors logged with sufficient context
- [ ] System continues running when optional features fail
- [ ] Clear error messages for users
- [ ] Proper resource cleanup on errors
- [ ] Retry logic for transient failures
- [ ] Custom exception classes for different error types
- [ ] Comprehensive logging configuration

---

## 🔧 **ERROR HANDLING PATTERNS**

### **Pattern 1: Critical Component**
```python
def start_database():
    try:
        db = Database()
        db.connect()
        return db
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        print("❌ Database connection failed. Cannot continue.")
        print(f"   Error: {e}")
        print("   Please check your database configuration.")
        sys.exit(1)
```

### **Pattern 2: Optional Component**
```python
def load_threat_intel():
    try:
        intel = IPReputationManager()
        logger.info("Threat intelligence loaded successfully")
        return intel
    except Exception as e:
        logger.warning(f"Threat intelligence unavailable: {e}")
        logger.warning("Continuing without threat intelligence")
        return None
```

### **Pattern 3: With Retry Logic**
```python
@retry(max_attempts=3, delay=1, exceptions=(ConnectionError, TimeoutError))
def fetch_reputation(ip):
    response = requests.get(f"https://api.example.com/ip/{ip}", timeout=5)
    response.raise_for_status()
    return response.json()
```

### **Pattern 4: Context Manager**
```python
with database_transaction(db) as conn:
    conn.execute("INSERT INTO connections ...")
    conn.execute("UPDATE devices ...")
    # Auto-commit on success, auto-rollback on exception
```

---

## 📊 **TESTING PLAN**

1. **Unit Tests**: Test error handling in each module
2. **Integration Tests**: Test component failures (e.g., DB offline)
3. **Chaos Testing**: Kill components randomly, ensure graceful degradation
4. **Error Injection**: Inject errors to verify handling

---

**Status**: ⏸️ **READY TO IMPLEMENT**
