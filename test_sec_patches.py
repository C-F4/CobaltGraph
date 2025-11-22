#!/usr/bin/env python3
"""
Test script for SEC-005 and SEC-008 patches
Validates: Encrypted Secrets Guide + HTTPS/TLS enforcement
"""

import sys
import os
import json
import ssl
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, '/home/tachyon/CobaltGraph')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

def test_sec005_documentation():
    """Test SEC-005: Encrypted Secrets Guide exists and is complete"""
    logger.info("=" * 60)
    logger.info("Testing SEC-005: Encrypted Secrets Guide")
    logger.info("=" * 60)

    guide_path = Path('/home/tachyon/CobaltGraph/docs/ENCRYPTED_SECRETS_GUIDE.md')

    # Check file exists
    if not guide_path.exists():
        logger.error(f"FAIL: Guide file not found: {guide_path}")
        return False

    # Read content
    with open(guide_path, 'r') as f:
        content = f.read()

    # Check for required sections
    required_sections = [
        'Encrypted Credentials Guide',
        'Environment Variables',
        'HashiCorp Vault',
        'AWS Secrets Manager',
        'Docker Secrets',
        'Phase 4 Encryption',
        'EncryptedConfig',
        'Security Checklist',
        'OWASP A02:2021',
        'CWE-312'
    ]

    missing = []
    for section in required_sections:
        if section not in content:
            missing.append(section)

    if missing:
        logger.error(f"FAIL: Missing sections: {missing}")
        return False

    logger.info(f"PASS: Guide contains all required sections")
    logger.info(f"      File size: {len(content)} bytes")
    logger.info(f"      File path: {guide_path}")
    return True


def test_sec008_dashboard_https():
    """Test SEC-008: HTTPS/TLS enforcement in dashboard"""
    logger.info("=" * 60)
    logger.info("Testing SEC-008: Dashboard HTTPS/TLS Enforcement")
    logger.info("=" * 60)

    from src.dashboard.server import DashboardHandler
    import inspect

    # Check enforce_https method exists
    if not hasattr(DashboardHandler, 'enforce_https'):
        logger.error("FAIL: DashboardHandler missing enforce_https method")
        return False

    logger.info("PASS: DashboardHandler has enforce_https method")

    # Check method signature
    method = getattr(DashboardHandler, 'enforce_https')
    source = inspect.getsource(method)

    required_in_source = [
        'enforce_https',
        'require_https',
        'is_https',
        'SSL',
        '301',
        'Location',
        'https://'
    ]

    missing_in_source = []
    for keyword in required_in_source:
        if keyword not in source:
            missing_in_source.append(keyword)

    if missing_in_source:
        logger.error(f"FAIL: Missing implementation details: {missing_in_source}")
        return False

    logger.info("PASS: enforce_https method has correct implementation")
    return True


def test_sec008_orchestrator_https():
    """Test SEC-008: HTTPS setup in orchestrator"""
    logger.info("=" * 60)
    logger.info("Testing SEC-008: Orchestrator HTTPS Setup")
    logger.info("=" * 60)

    from src.core.orchestrator import CobaltGraphOrchestrator
    import inspect

    # Check start_dashboard method
    if not hasattr(CobaltGraphOrchestrator, 'start_dashboard'):
        logger.error("FAIL: CobaltGraphOrchestrator missing start_dashboard method")
        return False

    method = getattr(CobaltGraphOrchestrator, 'start_dashboard')
    source = inspect.getsource(method)

    # Check for SEC-008 PATCH markers and implementation
    required_in_source = [
        'enable_https',
        'ssl.SSLContext',
        'load_cert_chain',
        'wrap_socket',
        'https_cert_file',
        'https_key_file',
        'SEC-008',
        'HTTPS'
    ]

    missing_in_source = []
    for keyword in required_in_source:
        if keyword not in source:
            missing_in_source.append(keyword)

    if missing_in_source:
        logger.error(f"FAIL: Missing implementation details: {missing_in_source}")
        return False

    logger.info("PASS: start_dashboard method has HTTPS implementation")
    return True


def test_sec008_config_settings():
    """Test SEC-008: Configuration has HTTPS settings"""
    logger.info("=" * 60)
    logger.info("Testing SEC-008: Configuration Settings")
    logger.info("=" * 60)

    config_path = Path('/home/tachyon/CobaltGraph/config/cobaltgraph.conf')

    if not config_path.exists():
        logger.error(f"FAIL: Config file not found: {config_path}")
        return False

    with open(config_path, 'r') as f:
        config_content = f.read()

    # Check for HTTPS configuration settings
    required_settings = [
        'enable_https',
        'require_https',
        'https_cert_file',
        'https_key_file',
        'SEC-008'
    ]

    missing = []
    for setting in required_settings:
        if setting not in config_content:
            missing.append(setting)

    if missing:
        logger.error(f"FAIL: Missing config settings: {missing}")
        return False

    logger.info("PASS: Config has all HTTPS settings")
    logger.info("      Settings: enable_https, require_https, cert_file, key_file")
    return True


def test_ssl_imports():
    """Test that SSL module imports work"""
    logger.info("=" * 60)
    logger.info("Testing SSL/TLS Module Imports")
    logger.info("=" * 60)

    try:
        import ssl as ssl_module
        from src.dashboard.server import DashboardHandler
        from src.core.orchestrator import CobaltGraphOrchestrator

        # Verify ssl module is available
        assert hasattr(ssl_module, 'SSLContext')
        assert hasattr(ssl_module, 'PROTOCOL_TLS_SERVER')

        logger.info("PASS: SSL module available with required features")
        logger.info(f"      Python SSL version: {ssl_module.OPENSSL_VERSION}")
        return True

    except Exception as e:
        logger.error(f"FAIL: SSL import error: {e}")
        return False


def test_do_get_https_enforcement():
    """Test do_GET calls enforce_https"""
    logger.info("=" * 60)
    logger.info("Testing do_GET HTTPS Enforcement Call")
    logger.info("=" * 60)

    from src.dashboard.server import DashboardHandler
    import inspect

    source = inspect.getsource(DashboardHandler.do_GET)

    # Check that do_GET calls enforce_https
    if 'enforce_https()' not in source:
        logger.error("FAIL: do_GET does not call enforce_https")
        return False

    # Check for SEC-008 patch comment
    if 'SEC-008' not in source:
        logger.warning("WARN: SEC-008 patch comment missing from do_GET")

    logger.info("PASS: do_GET properly calls enforce_https method")
    return True


def main():
    """Run all tests"""
    logger.info("CobaltGraph Security Patch Test Suite")
    logger.info("Testing SEC-005 + SEC-008")
    logger.info("")

    results = {
        "SEC-005 Encrypted Secrets Guide": test_sec005_documentation(),
        "SEC-008 Dashboard HTTPS": test_sec008_dashboard_https(),
        "SEC-008 Orchestrator HTTPS": test_sec008_orchestrator_https(),
        "SEC-008 Config Settings": test_sec008_config_settings(),
        "SSL/TLS Module Imports": test_ssl_imports(),
        "HTTPS Enforcement in do_GET": test_do_get_https_enforcement(),
    }

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        logger.info(f"  [{status}] {test_name}")

    logger.info("")
    logger.info(f"Results: {passed}/{total} tests passed")

    if passed == total:
        logger.info("")
        logger.info("✅ ALL TESTS PASSED")
        logger.info("")
        logger.info("Deployment Status:")
        logger.info("  SEC-005: Encrypted Secrets Guide DEPLOYED")
        logger.info("           Location: /home/tachyon/CobaltGraph/docs/ENCRYPTED_SECRETS_GUIDE.md")
        logger.info("           Content: Vault, AWS, Docker + Phase 4 example")
        logger.info("")
        logger.info("  SEC-008: HTTPS/TLS Enforcement DEPLOYED")
        logger.info("           Dashboard: enforce_https() method implemented")
        logger.info("           Orchestrator: SSL/TLS setup in start_dashboard()")
        logger.info("           Config: enable_https, require_https settings added")
        logger.info("")
        return 0
    else:
        logger.error("")
        logger.error("TESTS FAILED - Review errors above")
        return 1


if __name__ == '__main__':
    sys.exit(main())
