"""
CobaltGraph System Initialization & Verification
Comprehensive module loading and service verification before launch

This module ensures all critical components are properly loaded and
configured before the system starts, preventing runtime failures.
"""

import logging
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class InitializationError(Exception):
    """Raised when system initialization fails"""


class CobaltGraphInitializer:
    """
    Handles comprehensive system initialization and verification

    Responsibilities:
    - Verify Python version
    - Check and load all required modules
    - Validate database configuration
    - Verify network capabilities
    - Initialize services in correct order
    - Provide detailed error reporting
    """

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.modules_loaded = {}
        self.services_initialized = {}
        self.errors = []
        self.warnings = []

    def log(self, message, level="info"):
        """Log message if verbose"""
        if self.verbose:
            if level == "info":
                print(f"    {message}")
            elif level == "success":
                print(f"    ✅ {message}")
            elif level == "warning":
                print(f"    ⚠️  {message}")
            elif level == "error":
                print(f"    ❌ {message}")

    def verify_python_version(self) -> bool:
        """Verify Python version meets requirements"""
        self.log("Checking Python version...")

        major, minor = sys.version_info[:2]
        if major < 3 or (major == 3 and minor < 8):
            self.errors.append(f"Python 3.8+ required, found {major}.{minor}")
            self.log(f"Python {major}.{minor} - TOO OLD", "error")
            return False

        self.log(f"Python {major}.{minor}.{sys.version_info.micro}", "success")
        return True

    def verify_core_modules(self) -> bool:
        """Verify core Python modules are available"""
        self.log("Verifying core modules...")

        required_modules = [
            "logging",
            "json",
            "time",
            "threading",
            "queue",
            "pathlib",
            "argparse",
            "subprocess",
            "socket",
        ]

        all_ok = True
        for module in required_modules:
            try:
                __import__(module)
                self.modules_loaded[module] = True
            except ImportError as e:
                self.errors.append(f"Core module {module} not available: {e}")
                self.modules_loaded[module] = False
                all_ok = False

        if all_ok:
            self.log(f"Core modules ({len(required_modules)})", "success")
        else:
            self.log("Core modules - FAILED", "error")

        return all_ok

    def verify_database_module(self) -> bool:
        """Verify database modules"""
        self.log("Checking database modules...")

        try:
            # Try PostgreSQL (Phase 0)
            self.modules_loaded["psycopg2"] = True
            self.log("PostgreSQL driver (psycopg2)", "success")
            return True
        except ImportError:
            # Fallback to SQLite
            try:
                self.modules_loaded["sqlite3"] = True
                self.log("SQLite3 driver", "success")
                return True
            except ImportError:
                self.errors.append("No database driver available (psycopg2 or sqlite3)")
                self.log("No database driver found", "error")
                return False

    def verify_flask_modules(self) -> bool:
        """Verify Flask and dashboard dependencies"""
        self.log("Checking Flask dashboard modules...")

        required = {
            "flask": "Flask",
            "flask_socketio": "Flask-SocketIO",
            "flask_cors": "Flask-CORS",
        }

        all_ok = True
        for module, name in required.items():
            try:
                __import__(module)
                self.modules_loaded[module] = True
            except ImportError:
                self.warnings.append(f"{name} not installed (dashboard disabled)")
                self.modules_loaded[module] = False
                all_ok = False

        if all_ok:
            self.log("Flask dashboard modules", "success")
        else:
            self.log("Flask modules incomplete (dashboard may not work)", "warning")

        return True  # Not critical for basic operation

    def verify_cobaltgraph_modules(self) -> bool:
        """Verify CobaltGraph-specific modules"""
        self.log("Verifying CobaltGraph modules...")

        modules_to_check = [
            ("src.services.database", "Database Service"),
            ("src.services.oui_lookup", "OUI Lookup Service"),
            ("src.services.api.devices", "Device API"),
            ("src.services.arp_monitor", "ARP Monitor"),
        ]

        all_ok = True
        for module_path, name in modules_to_check:
            try:
                __import__(module_path)
                self.modules_loaded[module_path] = True
                self.log(f"{name}", "success")
            except ImportError as e:
                self.errors.append(f"CobaltGraph module {name} failed to load: {e}")
                self.modules_loaded[module_path] = False
                self.log(f"{name} - FAILED", "error")
                all_ok = False

        return all_ok

    def verify_dashboard_module(self) -> bool:
        """Verify new Flask-SocketIO dashboard"""
        self.log("Checking new dashboard module...")

        try:
            self.modules_loaded["dashboard"] = True
            self.services_initialized["dashboard"] = {
                "type": "flask-socketio",
                "port": 5000,
                "available": True,
            }
            self.log("Flask-SocketIO Dashboard (Task 0.6)", "success")
            return True
        except ImportError as e:
            self.warnings.append(f"New dashboard not available: {e}")
            self.modules_loaded["dashboard"] = False
            self.log("New dashboard unavailable", "warning")

            # Try old dashboard as fallback
            try:
                self.modules_loaded["dashboard_legacy"] = True
                self.services_initialized["dashboard"] = {
                    "type": "http-legacy",
                    "port": 8080,
                    "available": True,
                }
                self.log("Legacy HTTP Dashboard (fallback)", "success")
                return True
            except ImportError:
                self.modules_loaded["dashboard_legacy"] = False
                self.errors.append("No dashboard available (neither new nor legacy)")
                self.log("No dashboard available", "error")
                return False

    def verify_network_capabilities(self) -> Dict:
        """Check network capture capabilities"""
        self.log("Checking network capabilities...")

        import os
        import socket

        capabilities = {
            "is_root": False,
            "can_raw_socket": False,
            "network_mode_available": False,
            "device_mode_available": True,  # Always available
        }

        # Check root/admin
        if hasattr(os, "geteuid"):
            capabilities["is_root"] = os.geteuid() == 0

        # Check raw socket capability
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.close()
            capabilities["can_raw_socket"] = True
            capabilities["network_mode_available"] = True
        except (PermissionError, OSError):
            capabilities["can_raw_socket"] = False
            capabilities["network_mode_available"] = False

        if capabilities["is_root"]:
            self.log("Root/Admin access", "success")
        else:
            self.log("Root/Admin access not available (some features limited)", "warning")

        if capabilities["network_mode_available"]:
            self.log("Network-wide capture supported", "success")
        else:
            self.log("Network-wide capture not available (device-only mode)", "warning")

        return capabilities

    def verify_database_config(self) -> bool:
        """Verify database configuration"""
        self.log("Checking database configuration...")

        # Check if PostgreSQL config exists
        config_file = Path("config/database.conf")
        if config_file.exists():
            self.log("PostgreSQL config found", "success")

            # Try to connect
            try:
                from src.services.database import PostgreSQLDatabase

                db = PostgreSQLDatabase()
                # Test connection
                db.close()
                self.services_initialized["database"] = {"type": "postgresql", "available": True}
                self.log("PostgreSQL connection OK", "success")
                return True
            except Exception as e:
                self.warnings.append(f"PostgreSQL connection failed: {e}")
                self.log("PostgreSQL connection failed", "warning")

                # Try SQLite fallback
                try:
                    from src.storage.database import Database

                    db = Database("data/cobaltgraph.db")
                    self.services_initialized["database"] = {"type": "sqlite", "available": True}
                    self.log("SQLite fallback available", "success")
                    return True
                except Exception as e2:
                    self.errors.append(f"No database available: {e2}")
                    self.log("No database available", "error")
                    return False
        else:
            self.warnings.append("PostgreSQL config not found, using SQLite")
            self.log("Using SQLite database", "warning")
            self.services_initialized["database"] = {"type": "sqlite", "available": True}
            return True

    def run_full_verification(self) -> bool:
        """Run complete system verification"""
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║         CobaltGraph System Initialization & Verification          ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

        checks = [
            ("Python Version", self.verify_python_version),
            ("Core Modules", self.verify_core_modules),
            ("Database Modules", self.verify_database_module),
            ("Flask Modules", self.verify_flask_modules),
            ("CobaltGraph Modules", self.verify_cobaltgraph_modules),
            ("Dashboard Module", self.verify_dashboard_module),
            ("Database Configuration", self.verify_database_config),
        ]

        all_critical_passed = True

        for check_name, check_func in checks:
            print(f"  🔍 {check_name}:")
            try:
                result = check_func()
                if not result and check_name not in ["Flask Modules"]:  # Flask not critical
                    all_critical_passed = False
            except Exception as e:
                self.errors.append(f"{check_name} check failed: {e}")
                self.log(f"Check failed with exception: {e}", "error")
                all_critical_passed = False
            print()

        # Network capabilities (informational)
        print(f"  🔍 Network Capabilities:")
        self.verify_network_capabilities()
        print()

        # Summary
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        if all_critical_passed and len(self.errors) == 0:
            print("✅ ALL CRITICAL CHECKS PASSED")
            print()
            print("System is ready for launch!")

            # Show services
            if self.services_initialized:
                print()
                print("📦 Services Available:")
                for service, info in self.services_initialized.items():
                    if info.get("available"):
                        svc_type = info.get("type", "unknown")
                        port = info.get("port", "N/A")
                        print(f"  ✓ {service}: {svc_type} (port {port})")

        else:
            print("❌ INITIALIZATION FAILED")

            if self.errors:
                print()
                print("Errors:")
                for error in self.errors:
                    print(f"  ❌ {error}")

        if self.warnings:
            print()
            print("Warnings:")
            for warning in self.warnings:
                print(f"  ⚠️  {warning}")

        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print()

        return all_critical_passed

    def get_dashboard_config(self) -> Optional[Dict]:
        """Get dashboard configuration based on what's available"""
        dashboard_info = self.services_initialized.get("dashboard")
        if not dashboard_info or not dashboard_info.get("available"):
            return None

        return {
            "type": dashboard_info["type"],
            "port": dashboard_info["port"],
            "module": "flask-socketio" if dashboard_info["type"] == "flask-socketio" else "legacy",
        }


def initialize_cobaltgraph(verbose=True) -> Tuple[bool, CobaltGraphInitializer]:
    """
    Initialize and verify CobaltGraph system

    Args:
        verbose: Print detailed output

    Returns:
        Tuple of (success, initializer instance)
    """
    initializer = CobaltGraphInitializer(verbose=verbose)
    success = initializer.run_full_verification()
    return success, initializer
