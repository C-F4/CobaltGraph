"""
Tests for src.core.config module
"""

import pytest


@pytest.mark.unit
def test_config_load(sample_config):
    """Test configuration loading"""
    # TODO: Implement once Config class is refactored


@pytest.mark.unit
def test_config_validation():
    """Test configuration validation"""
    # TODO: Implement


@pytest.mark.unit
def test_config_defaults():
    """Test default configuration values"""
    # TODO: Implement


def test_threat_intel_sections_are_case_insensitive(tmp_path):
    """README uses lowercase section names; the loader must accept them and the GreyNoise/OTX keys."""
    from src.core.config import ConfigLoader

    (tmp_path / "threat_intel.conf").write_text(
        "[virustotal]\napi_key = VT\n[abuseipdb]\napi_key = AB\n"
        "[alienvault_otx]\napi_key = OTX\n[greynoise]\napi_key = GN\n"
    )
    loader = ConfigLoader(str(tmp_path))
    loader.config = dict(loader.defaults)
    loader._load_threat_intel_config()
    assert loader.config["virustotal_api_key"] == "VT"
    assert loader.config["abuseipdb_api_key"] == "AB"
    assert loader.config["alienvault_otx_api_key"] == "OTX"
    assert loader.config["greynoise_api_key"] == "GN"


def test_health_directory_check_warns_without_creating(tmp_path):
    from src.core.system_check import SystemChecker

    checker = SystemChecker()
    checker.project_root = tmp_path
    checker._check_directories()
    assert not (tmp_path / "logs").exists()
    missing = [r for r in checker.results if r.name == "Directory: logs"]
    assert missing and missing[0].critical is False and missing[0].passed is False


def test_threat_intel_source_is_enabled_when_key_present(tmp_path):
    from src.core.config import ConfigLoader

    (tmp_path / "threat_intel.conf").write_text("[virustotal]\napi_key = VT\n[abuseipdb]\n")
    loader = ConfigLoader(str(tmp_path))
    loader.config = dict(loader.defaults)
    loader._load_threat_intel_config()
    assert loader.config["virustotal_enabled"] is True
    assert loader.config["abuseipdb_enabled"] is False
