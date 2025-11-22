#!/usr/bin/env python3
"""
CobaltGraph Test Runner
Runs all tests without requiring pytest

Tests:
- Error handling (errors.py)
- Logging configuration (logging_config.py)
- Database operations (database.py)
- Configuration loading (config.py)
- Launcher functionality (launcher.py)
"""

import sys
import os
import time
import tempfile
from pathlib import Path

# Add src to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ANSI Colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

class TestRunner:
    """Simple test runner"""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def test(self, name):
        """Decorator for test functions"""
        def decorator(func):
            self.tests.append((name, func))
            return func
        return decorator

    def run_all(self):
        """Run all registered tests"""
        print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
        print(f"{BLUE}  CobaltGraph Test Suite{NC}")
        print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
        print()

        for name, test_func in self.tests:
            try:
                print(f"Testing: {name} ... ", end='', flush=True)
                test_func()
                print(f"{GREEN}✅ PASSED{NC}")
                self.passed += 1
            except AssertionError as e:
                print(f"{RED}❌ FAILED{NC}")
                print(f"  {RED}Assertion: {e}{NC}")
                self.failed += 1
            except Exception as e:
                print(f"{RED}❌ ERROR{NC}")
                print(f"  {RED}Error: {e}{NC}")
                self.failed += 1

        print()
        print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
        print(f"Results:")
        print(f"  {GREEN}Passed: {self.passed}{NC}")
        print(f"  {RED}Failed: {self.failed}{NC}")
        print(f"  Total: {self.passed + self.failed}")
        print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")

        return self.failed == 0


# Create test runner
runner = TestRunner()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ERROR HANDLING TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@runner.test("src.utils.errors - Import exception classes")
def test_error_imports():
    from src.utils.errors import (
        SUARONError,
        ConfigurationError,
        DatabaseError,
        CaptureError,
        IntegrationError,
        DashboardError
    )
    assert SUARONError is not None
    assert ConfigurationError is not None
    assert DatabaseError is not None

@runner.test("src.utils.errors - SUARONError with details")
def test_error_with_details():
    from src.utils.errors import SUARONError

    error = SUARONError("Test error", details={'key': 'value'})
    assert error.message == "Test error"
    assert error.details == {'key': 'value'}
    assert 'key=value' in str(error)

@runner.test("src.utils.errors - Exception inheritance")
def test_error_inheritance():
    from src.utils.errors import SUARONError, DatabaseError

    try:
        raise DatabaseError("DB failed")
    except SUARONError:
        pass  # Should catch as SUARONError
    except Exception:
        raise AssertionError("Should have been caught as SUARONError")

@runner.test("src.utils.errors - create_error helper")
def test_create_error_helper():
    from src.utils.errors import create_error, ConfigurationError

    error = create_error(ConfigurationError, "Config failed", file="test.conf")
    assert isinstance(error, ConfigurationError)
    assert error.details['file'] == "test.conf"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOGGING TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@runner.test("src.utils.logging_config - Import functions")
def test_logging_imports():
    from src.utils.logging_config import (
        setup_logging,
        get_logger,
        ColoredFormatter,
        quick_setup
    )
    assert setup_logging is not None
    assert get_logger is not None
    assert ColoredFormatter is not None

@runner.test("src.utils.logging_config - Setup logging")
def test_logging_setup():
    import logging
    from src.utils.logging_config import setup_logging

    with tempfile.TemporaryDirectory() as tmpdir:
        setup_logging(
            log_level=logging.INFO,
            log_dir=tmpdir,
            log_file='test.log'
        )

        # Verify log file was created
        log_file = Path(tmpdir) / 'test.log'
        assert log_file.exists()

@runner.test("src.utils.logging_config - Get logger")
def test_get_logger():
    from src.utils.logging_config import get_logger

    logger = get_logger("test_module")
    assert logger is not None
    assert logger.name == "test_module"

@runner.test("src.utils.logging_config - ColoredFormatter")
def test_colored_formatter():
    import logging
    from src.utils.logging_config import ColoredFormatter

    formatter = ColoredFormatter(use_color=False)  # Disable color for testing
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Test message",
        args=(),
        exc_info=None
    )
    formatted = formatter.format(record)
    assert "Test message" in formatted


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DATABASE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@runner.test("src.storage.database - Initialize database")
def test_database_init():
    from src.storage.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(str(db_path))

        assert db.conn is not None
        assert db.db_path == str(db_path)

        db.close()

@runner.test("src.storage.database - Add connection")
def test_database_add_connection():
    from src.storage.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(str(db_path))

        conn_data = {
            'dst_ip': '8.8.8.8',
            'dst_port': 443,
            'protocol': 'TCP'
        }
        db.add_connection(conn_data)

        count = db.get_connection_count()
        assert count == 1

        db.close()

@runner.test("src.storage.database - Get recent connections")
def test_database_get_recent():
    from src.storage.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(str(db_path))

        # Add multiple connections
        for i in range(5):
            db.add_connection({
                'dst_ip': f'1.2.3.{i}',
                'dst_port': 443
            })

        connections = db.get_recent_connections(limit=3)
        assert len(connections) == 3

        db.close()

@runner.test("src.storage.database - Validate required fields")
def test_database_validation():
    from src.storage.database import Database
    from src.utils.errors import DatabaseError

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(str(db_path))

        # Missing required fields
        try:
            db.add_connection({'dst_ip': '1.2.3.4'})  # Missing dst_port
            raise AssertionError("Should have raised DatabaseError")
        except DatabaseError:
            pass  # Expected

        db.close()

@runner.test("src.storage.database - Context manager")
def test_database_context_manager():
    from src.storage.database import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"

        with Database(str(db_path)) as db:
            db.add_connection({'dst_ip': '8.8.8.8', 'dst_port': 443})
            count = db.get_connection_count()
            assert count == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIGURATION TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@runner.test("src.core.config - ConfigLoader import")
def test_config_import():
    from src.core.config import ConfigLoader, load_config
    assert ConfigLoader is not None
    assert load_config is not None

@runner.test("src.core.config - Load with defaults")
def test_config_defaults():
    from src.core.config import ConfigLoader

    with tempfile.TemporaryDirectory() as tmpdir:
        loader = ConfigLoader(tmpdir)  # Non-existent config
        config = loader.load()

        # Should have defaults
        assert config['system_name'] == 'CobaltGraph'
        assert config['web_port'] == 8080
        assert config['monitor_mode'] == 'auto'

@runner.test("src.core.config - Validation")
def test_config_validation():
    from src.core.config import ConfigLoader

    with tempfile.TemporaryDirectory() as tmpdir:
        loader = ConfigLoader(tmpdir)
        loader.config = loader.defaults.copy()

        # Valid config
        loader._validate()
        assert len(loader.errors) == 0

        # Invalid port
        loader.config['web_port'] = 99999
        loader._validate()
        assert len(loader.errors) > 0

@runner.test("src.core.config - Threat intel status")
def test_config_threat_intel_status():
    from src.core.config import ConfigLoader

    with tempfile.TemporaryDirectory() as tmpdir:
        loader = ConfigLoader(tmpdir)
        config = loader.load()

        status = loader.get_threat_intel_status()
        assert 'VirusTotal' in status
        assert 'AbuseIPDB' in status


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LAUNCHER TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@runner.test("src.core.launcher - Launcher import")
def test_launcher_import():
    from src.core.launcher import Launcher, create_argument_parser
    assert Launcher is not None
    assert create_argument_parser is not None

@runner.test("src.core.launcher - Argument parser")
def test_launcher_argparser():
    from src.core.launcher import create_argument_parser

    parser = create_argument_parser()

    # Test parsing
    args = parser.parse_args(['--mode', 'device', '--interface', 'web'])
    assert args.mode == 'device'
    assert args.interface == 'web'

@runner.test("src.core.launcher - Platform detection")
def test_launcher_platform_detection():
    from src.core.launcher import Launcher
    import argparse

    args = argparse.Namespace()
    launcher = Launcher(args)

    platform_info = launcher.detect_platform()

    assert 'os' in platform_info
    assert 'is_root' in platform_info
    assert 'can_raw_socket' in platform_info
    assert 'supports_ncurses' in platform_info

@runner.test("src.core.launcher - Mode selection")
def test_launcher_mode_selection():
    from src.core.launcher import Launcher
    import argparse

    args = argparse.Namespace()
    launcher = Launcher(args)
    launcher.detect_platform()

    # Test explicit mode
    mode = launcher.select_mode('device')
    assert mode == 'device'

    mode = launcher.select_mode('network')
    assert mode in ['network', 'device']  # May fallback if no root

@runner.test("src.core.launcher - Interface selection")
def test_launcher_interface_selection():
    from src.core.launcher import Launcher
    import argparse

    args = argparse.Namespace()
    launcher = Launcher(args)
    launcher.detect_platform()

    # Test explicit interface
    interface = launcher.select_interface('web')
    assert interface == 'web'


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RUN ALL TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == '__main__':
    success = runner.run_all()
    sys.exit(0 if success else 1)
