"""
Pytest configuration for CobaltGraph tests
Shared fixtures and test utilities
"""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

@pytest.fixture
def sample_config():
    """Sample configuration for tests"""
    return {
        'dashboard_port': 8080,
        'database_path': ':memory:',  # In-memory for tests
        'log_level': 'DEBUG',
        'virustotal_enabled': False,
        'abuseipdb_enabled': False,
    }

@pytest.fixture
def sample_connection():
    """Sample connection data for tests"""
    return {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'dst_port': 443,
        'protocol': 'TCP',
        'timestamp': 1699999999.0,
    }

@pytest.fixture
def temp_db(tmp_path):
    """Temporary database for tests"""
    db_path = tmp_path / "test_cobaltgraph.db"
    return str(db_path)
