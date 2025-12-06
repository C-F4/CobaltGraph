#!/usr/bin/env python3
"""
CobaltGraph System Checker
Lightweight pre-flight validation for system readiness

Integrates with the global heartbeat monitor to report component status.
"""

import importlib
import os
import platform
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import global heartbeat singleton
from src.utils.heartbeat import heartbeat


@dataclass
class CheckResult:
    """Result of a system check"""
    name: str
    passed: bool
    message: str
    critical: bool = True
    component: str = ""  # Maps to heartbeat component name


class SystemChecker:
    """Lightweight system readiness checker"""

    def __init__(self):
        self.results: List[CheckResult] = []
        self.project_root = Path(__file__).parent.parent.parent

    def check_all(self, mode: str = "device") -> bool:
        """
        Run all system checks

        Args:
            mode: Operating mode (device/network)

        Returns:
            True if all critical checks pass
        """
        self.results.clear()

        # Core checks (always run)
        self._check_python_version()
        self._check_core_modules()
        self._check_cobaltgraph_modules()
        self._check_database()
        self._check_directories()

        # Mode-specific checks
        if mode == "network":
            self._check_network_capabilities()

        # Optional checks (non-critical)
        self._check_optional_services()

        # Return True only if all critical checks passed
        return all(r.passed for r in self.results if r.critical)

    def _check_python_version(self):
        """Verify Python 3.8+"""
        version = sys.version_info
        passed = version >= (3, 8)

        self.results.append(CheckResult(
            name="Python Version",
            passed=passed,
            message=f"Python {version.major}.{version.minor}.{version.micro}" +
                   (" ✓" if passed else " (requires 3.8+)"),
            critical=True
        ))

    def _check_core_modules(self):
        """Check Python standard library and external dependencies"""
        # Standard library modules
        stdlib_modules = [
            "logging", "json", "threading", "queue", "pathlib",
            "argparse", "subprocess", "socket", "sqlite3", "re"
        ]

        for module_name in stdlib_modules:
            try:
                importlib.import_module(module_name)
                self.results.append(CheckResult(
                    name=f"Module: {module_name}",
                    passed=True,
                    message=f"{module_name} available ✓",
                    critical=True
                ))
            except ImportError as e:
                self.results.append(CheckResult(
                    name=f"Module: {module_name}",
                    passed=False,
                    message=f"{module_name} missing: {e}",
                    critical=True
                ))

        # External dependencies (from requirements.txt)
        # Core dependencies (critical)
        core_deps = [
            ("requests", "HTTP library for threat intelligence"),
        ]

        for module_name, description in core_deps:
            try:
                importlib.import_module(module_name)
                self.results.append(CheckResult(
                    name=f"Dependency: {module_name}",
                    passed=True,
                    message=f"{module_name} ({description}) ✓",
                    critical=True
                ))
            except ImportError:
                self.results.append(CheckResult(
                    name=f"Dependency: {module_name}",
                    passed=False,
                    message=f"{module_name} missing - run: pip3 install {module_name}",
                    critical=True
                ))

        # Core dependencies (required for full functionality)
        core_extra_deps = [
            ("scapy", "Network packet capture for network-wide mode", True),
            ("rich", "Terminal formatting and tables", False),
            ("textual", "Reactive Terminal UI framework", True),
            ("numpy", "Consensus calculations and threat vectors", True),
            ("pandas", "Data analysis and export processing", True),
            ("scipy", "Statistical threat scoring", True),
            ("networkx", "Network topology and connection analysis", True),
            ("matplotlib", "Visualization and plotting", False),
        ]

        for module_name, description, is_critical in core_extra_deps:
            try:
                importlib.import_module(module_name)
                self.results.append(CheckResult(
                    name=f"Dependency: {module_name}",
                    passed=True,
                    message=f"{module_name} ({description}) ✓",
                    critical=is_critical
                ))
            except ImportError:
                self.results.append(CheckResult(
                    name=f"Dependency: {module_name}",
                    passed=False,
                    message=f"{module_name} not installed - run: pip3 install {module_name}",
                    critical=is_critical
                ))

    def _check_cobaltgraph_modules(self):
        """Check CobaltGraph components"""
        components = [
            ("src.core.config", "Configuration System"),
            ("src.capture.device_monitor", "Device Monitor"),
            ("src.storage.database", "Database Layer"),
            ("src.services.geo_lookup", "Geolocation Service"),
            ("src.services.ip_reputation", "IP Reputation Service"),
        ]

        for module_path, display_name in components:
            try:
                importlib.import_module(module_path)
                self.results.append(CheckResult(
                    name=display_name,
                    passed=True,
                    message=f"{display_name} ✓",
                    critical=True
                ))
            except ImportError as e:
                self.results.append(CheckResult(
                    name=display_name,
                    passed=False,
                    message=f"{display_name} failed: {e}",
                    critical=True
                ))

        # Check dashboard components (at least one must be available)
        dashboard_modules = [
            ("src.ui.dashboard_enhanced", "CobaltGraph Enhanced Dashboard"),
            ("src.ui.globe_simple", "Simple Threat Globe"),
            ("src.ui.boot_sequence", "Boot Sequence"),
        ]

        dashboard_available = False
        for module_path, display_name in dashboard_modules:
            try:
                importlib.import_module(module_path)
                self.results.append(CheckResult(
                    name=display_name,
                    passed=True,
                    message=f"{display_name} ✓",
                    critical=False
                ))
                dashboard_available = True
            except ImportError as e:
                self.results.append(CheckResult(
                    name=display_name,
                    passed=False,
                    message=f"{display_name} not available",
                    critical=False
                ))

        # At least one dashboard must be available
        if not dashboard_available:
            self.results.append(CheckResult(
                name="Dashboard System",
                passed=False,
                message="No dashboard modules available (device/network/enhanced_lean)",
                critical=True
            ))

    def _check_database(self):
        """Verify SQLite database access"""
        db_dir = self.project_root / "database"
        data_dir = self.project_root / "data"

        try:
            # Test SQLite availability
            conn = sqlite3.connect(":memory:")
            conn.close()

            # Check database directories
            if not db_dir.exists():
                db_dir.mkdir(parents=True, exist_ok=True)
            if not data_dir.exists():
                data_dir.mkdir(parents=True, exist_ok=True)

            self.results.append(CheckResult(
                name="Database",
                passed=True,
                message=f"SQLite available, directory ready ✓",
                critical=True,
                component="database"
            ))
            # Update heartbeat
            heartbeat.beat("database", "SQLite ready")
        except Exception as e:
            self.results.append(CheckResult(
                name="Database",
                passed=False,
                message=f"Database check failed: {e}",
                critical=True,
                component="database"
            ))
            heartbeat.mark_offline("database", f"Check failed: {e}")

    def _check_directories(self):
        """Ensure required directories exist"""
        required_dirs = ["logs", "exports", "data", "config"]

        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                self.results.append(CheckResult(
                    name=f"Directory: {dir_name}",
                    passed=True,
                    message=f"{dir_name}/ ready ✓",
                    critical=True
                ))
            except Exception as e:
                self.results.append(CheckResult(
                    name=f"Directory: {dir_name}",
                    passed=False,
                    message=f"Cannot create {dir_name}/: {e}",
                    critical=True
                ))

    def _check_network_capabilities(self):
        """Check network-wide monitoring capabilities (requires root)"""
        is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

        if not is_root:
            self.results.append(CheckResult(
                name="Root Privileges",
                passed=False,
                message="Network mode requires root/sudo",
                critical=True
            ))
            return

        # Check for network tools
        tools = ["ip", "ss"]
        for tool in tools:
            try:
                result = subprocess.run(
                    ["which", tool],
                    capture_output=True,
                    timeout=2
                )
                self.results.append(CheckResult(
                    name=f"Tool: {tool}",
                    passed=result.returncode == 0,
                    message=f"{tool} {'available' if result.returncode == 0 else 'missing'} ✓",
                    critical=False
                ))
            except Exception:
                self.results.append(CheckResult(
                    name=f"Tool: {tool}",
                    passed=False,
                    message=f"{tool} check failed",
                    critical=False
                ))

    def _check_optional_services(self):
        """Check optional features (non-critical) and update heartbeat"""
        # Check consensus system
        try:
            from src.consensus import ConsensusThreatScorer
            self.results.append(CheckResult(
                name="Consensus System",
                passed=True,
                message="Multi-agent consensus available ✓",
                critical=False,
                component="consensus"
            ))
            heartbeat.beat("consensus", "BFT scoring ready")
        except ImportError:
            self.results.append(CheckResult(
                name="Consensus System",
                passed=False,
                message="Consensus system not available (degraded mode)",
                critical=False,
                component="consensus"
            ))
            heartbeat.mark_offline("consensus", "Module not available")

        # Check ASN/Organization lookup service
        try:
            from src.services.asn_lookup import ASNLookup, TTLAnalyzer
            self.results.append(CheckResult(
                name="ASN Lookup Service",
                passed=True,
                message="ASN/Organization lookup with TTL hop detection available ✓",
                critical=False,
                component="asn_lookup"
            ))
            heartbeat.beat("asn_lookup", "ASN service ready")
        except ImportError:
            self.results.append(CheckResult(
                name="ASN Lookup Service",
                passed=False,
                message="ASN lookup service not available (reduced intelligence)",
                critical=False,
                component="asn_lookup"
            ))
            heartbeat.mark_offline("asn_lookup", "Module not available")

        # Check geolocation service
        try:
            from src.services.geo_lookup import GeoLookup
            self.results.append(CheckResult(
                name="Geolocation Service",
                passed=True,
                message="GeoIP lookup available ✓",
                critical=False,
                component="geo_engine"
            ))
            heartbeat.beat("geo_engine", "GeoIP ready")
        except ImportError:
            self.results.append(CheckResult(
                name="Geolocation Service",
                passed=False,
                message="Geolocation service not available",
                critical=False,
                component="geo_engine"
            ))
            heartbeat.mark_offline("geo_engine", "Module not available")

        # Check IP reputation service
        try:
            from src.services.ip_reputation import IPReputation
            self.results.append(CheckResult(
                name="IP Reputation Service",
                passed=True,
                message="IP reputation lookup available ✓",
                critical=False,
                component="reputation"
            ))
            heartbeat.beat("reputation", "Reputation APIs ready")
        except ImportError:
            self.results.append(CheckResult(
                name="IP Reputation Service",
                passed=False,
                message="IP reputation service not available",
                critical=False,
                component="reputation"
            ))
            heartbeat.mark_offline("reputation", "Module not available")

        # Check export system
        try:
            from src.export import ConsensusExporter
            self.results.append(CheckResult(
                name="Export System",
                passed=True,
                message="Export functionality available ✓",
                critical=False
            ))
        except ImportError:
            self.results.append(CheckResult(
                name="Export System",
                passed=False,
                message="Export system not available",
                critical=False
            ))

    def print_results(self):
        """Print formatted check results"""
        print("\n" + "="*70)
        print("  COBALTGRAPH SYSTEM CHECK")
        print("="*70 + "\n")

        # Group by status
        passed = [r for r in self.results if r.passed]
        failed = [r for r in self.results if not r.passed]
        critical_failed = [r for r in failed if r.critical]

        # Print results
        for result in self.results:
            symbol = "✓" if result.passed else "✗"
            color = "\033[0;32m" if result.passed else "\033[0;31m"
            reset = "\033[0m"
            critical_marker = " [CRITICAL]" if not result.passed and result.critical else ""

            print(f"{color}{symbol}{reset} {result.message}{critical_marker}")

        # Summary
        print("\n" + "-"*70)
        print(f"Passed: {len(passed)}/{len(self.results)}")
        if critical_failed:
            print(f"\033[0;31mCritical failures: {len(critical_failed)}\033[0m")
        print("-"*70 + "\n")

        return len(critical_failed) == 0


def run_health_check(mode: str = "device") -> bool:
    """
    Run system health check

    Args:
        mode: Operating mode to check for

    Returns:
        True if system is healthy
    """
    checker = SystemChecker()
    checker.check_all(mode=mode)
    return checker.print_results()


def check_dependencies_only() -> bool:
    """
    Quick dependency check (Python version + critical imports)

    Returns:
        True if all critical dependencies are available
    """
    checker = SystemChecker()
    checker._check_python_version()
    checker._check_core_modules()

    # Check if any critical checks failed
    failed = [r for r in checker.results if not r.passed and r.critical]

    if failed:
        print("\n" + "="*70)
        print("  MISSING DEPENDENCIES")
        print("="*70 + "\n")

        for result in failed:
            print(f"\033[0;31m✗\033[0m {result.message}")

        print("\n" + "-"*70)
        print("Please install dependencies with:")
        print("  pip3 install -r requirements.txt")
        print("-"*70 + "\n")
        return False

    return True


if __name__ == "__main__":
    # Standalone health check
    import argparse

    parser = argparse.ArgumentParser(description="CobaltGraph System Health Check")
    parser.add_argument("--mode", choices=["device", "network"], default="device",
                       help="Check for specific operational mode")
    args = parser.parse_args()

    healthy = run_health_check(mode=args.mode)
    sys.exit(0 if healthy else 1)
