#!/usr/bin/env python3
"""
CobaltGraph Configuration Loader
Loads and validates configuration from config/ directory
Supports environment variable overrides
"""

import os
import sys
import logging
import configparser
import stat
import fcntl
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# Import custom exceptions
from src.utils.errors import ConfigurationError

logger = logging.getLogger(__name__)

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'

class ConfigLoader:
    """
    Loads CobaltGraph configuration from config files and environment

    Priority order:
    1. Environment variables (COBALTGRAPH_*)
    2. Config files (config/*.conf)
    3. Default values
    """

    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config = {}
        self.warnings = []
        self.errors = []

        # Default configuration values
        self.defaults = {
            # General
            'system_name': 'CobaltGraph',
            'log_level': 'INFO',
            'max_database_size_mb': 1000,
            'retention_days': 30,

            # Network
            'monitor_mode': 'auto',
            'capture_interface': '',
            'capture_method': 'auto',  # Legacy fallback
            'buffer_size': 100,
            'enable_device_tracking': True,
            'device_timeout': 300,

            # Dashboard
            'web_port': 8080,
            'api_port': 8080,  # API endpoint port (can be different from web_port)
            'web_host': '127.0.0.1',
            'enable_auth': False,
            'refresh_interval': 5,

            # Terminal
            'terminal_refresh': 1,
            'terminal_theme': 'dark',

            # GeoIntelligence
            'primary_geo_service': 'ip-api',
            'enable_geo_cache': True,
            'geo_cache_ttl': 86400,

            # ThreatScoring
            'enable_ip_reputation': True,
            'enable_ml_detection': True,
            'ml_update_interval': 24,
            'alert_threshold': 0.7,

            # Export
            'enable_csv_export': True,
            'enable_json_export': True,
            'export_directory': './exports',

            # Features
            'enable_webhooks': False,
            'enable_email_alerts': False,
            'enable_desktop_notifications': False,

            # WSL
            'enable_wsl_integration': False,
            'wsl_distribution': '',

            # RaspberryPi
            'enable_low_power_mode': False,
            'pi_worker_threads': 2,

            # Auth (from auth.conf)
            'auth_username': 'admin',
            'auth_password': 'changeme',
            'session_timeout': 60,
            'max_login_attempts': 5,
            'lockout_duration': 15,
            'auth_strict_mode': True,  # Enforce strict password policy

            # Threat Intel (from threat_intel.conf)
            'abuseipdb_api_key': '',
            'abuseipdb_enabled': False,
            'abuseipdb_cache_ttl': 86400,
            'abuseipdb_confidence_threshold': 75,
            'virustotal_api_key': '',
            'virustotal_enabled': False,
            'virustotal_cache_ttl': 86400,
            'virustotal_malicious_threshold': 2,
            'threat_priority': 'virustotal,abuseipdb,local',
            'fallback_to_local': True,
            'enable_rate_limiting': True,
            'max_requests_per_minute': 4,
        }

    def load(self) -> Dict[str, Any]:
        """Load configuration from all sources"""
        # Start with defaults
        self.config = self.defaults.copy()

        # [SEC-001 PATCH] Enforce secure permissions on credential files
        self._enforce_secure_permissions()

        # Load from config files
        self._load_main_config()
        self._load_auth_config()
        self._load_threat_intel_config()

        # Override with environment variables
        self._load_env_overrides()

        # Validate configuration
        self._validate()

        return self.config

    def _enforce_secure_permissions(self):
        """
        Enforce 600 permissions on sensitive config files with comprehensive symlink/race/hardlink protection
        (SEC-001 PATCH - CRITICAL SECURITY FIX)
        """
        sensitive_files = {
            self.config_dir / "auth.conf": "Authentication credentials",
            self.config_dir / "threat_intel.conf": "Threat API keys"
        }

        for filepath, description in sensitive_files.items():
            if not filepath.exists():
                continue

            try:
                # FIX 3: Hardlink detection - reject if st_nlink > 1
                file_stat = filepath.lstat()  # Use lstat to detect symlinks
                if file_stat.st_nlink > 1:
                    error_msg = f"[SEC-001] CRITICAL: {filepath.name} has hardlinks (st_nlink={file_stat.st_nlink}). Remove hardlinks immediately!"
                    self.errors.append(error_msg)
                    logger.error(f"[SEC-001] {error_msg}")
                    continue

                # FIX 1: Symlink detection and replacement
                if stat.S_ISLNK(file_stat.st_mode):
                    logger.warning(f"[SEC-001] Symlink detected at {filepath}: Replacing with real file")

                    # Read symlink target
                    symlink_target = filepath.readlink()
                    logger.warning(f"[SEC-001] Symlink points to: {symlink_target}")

                    # Check if target is outside config directory (privilege escalation attempt)
                    try:
                        target_path = (filepath.parent / symlink_target).resolve()
                        config_path = self.config_dir.resolve()

                        if not str(target_path).startswith(str(config_path)):
                            error_msg = f"[SEC-001] CRITICAL: Symlink points outside config directory: {target_path}. Privilege escalation attempt detected!"
                            self.errors.append(error_msg)
                            logger.error(f"[SEC-001] {error_msg}")
                            continue
                    except Exception as e:
                        error_msg = f"[SEC-001] CRITICAL: Cannot validate symlink target: {e}"
                        self.errors.append(error_msg)
                        logger.error(f"[SEC-001] {error_msg}")
                        continue

                    # Create backup of symlink
                    backup_path = filepath.with_suffix(filepath.suffix + '.symlink_backup')
                    if not backup_path.exists():
                        backup_path.write_text(str(symlink_target))
                        logger.warning(f"[SEC-001] Symlink backup created at {backup_path}")

                    # Remove symlink and create real file
                    filepath.unlink()
                    filepath.touch(mode=0o600)
                    logger.warning(f"[SEC-001] Replaced symlink with real file at {filepath}")
                    file_stat = filepath.lstat()

                # FIX 2: Atomic permission enforcement with fcntl.flock()
                with open(filepath, 'rb') as f:
                    try:
                        # Acquire exclusive lock
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        logger.debug(f"[SEC-001] Acquired exclusive lock on {filepath}")

                        # Now check permissions again (after lock acquired)
                        current_stat = filepath.lstat()
                        current_perms = current_stat.st_mode & 0o777

                        # Re-check for symlinks/hardlinks after acquiring lock (TOCTOU fix)
                        if stat.S_ISLNK(current_stat.st_mode):
                            error_msg = f"[SEC-001] CRITICAL: Symlink created between check and lock!"
                            self.errors.append(error_msg)
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                            continue

                        if current_stat.st_nlink > 1:
                            error_msg = f"[SEC-001] CRITICAL: Hardlink created between check and lock!"
                            self.errors.append(error_msg)
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                            continue

                        # Now safe to chmod - still holding lock
                        if current_perms != 0o600:
                            filepath.chmod(0o600)
                            logger.warning(f"[SEC-001] HARDENED: Fixed permissions on {filepath.name} (was {oct(current_perms)}, now 0o600)")
                            self.warnings.append(f"Fixed file permissions on {filepath.name} - was {oct(current_perms)}, now 0o600")
                        else:
                            logger.info(f"[SEC-001] VERIFIED: {filepath.name} has secure permissions (0o600)")

                        # Release lock
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                    except BlockingIOError:
                        error_msg = f"[SEC-001] WARNING: Could not acquire exclusive lock on {filepath} (in use)"
                        self.warnings.append(error_msg)
                        logger.warning(f"[SEC-001] {error_msg}")

            except Exception as e:
                error_msg = f"[SEC-001] CRITICAL: Error enforcing permissions on {filepath.name}: {e}"
                self.errors.append(error_msg)
                logger.error(f"[SEC-001] {error_msg}")

    def _load_main_config(self):
        """Load main configuration from cobaltgraph.conf"""
        config_file = self.config_dir / "cobaltgraph.conf"
        if not config_file.exists():
            self.warnings.append(f"Main config not found: {config_file}")
            logger.warning(f"Main config not found: {config_file}, using defaults")
            return

        try:
            parser = configparser.ConfigParser()
            parser.read(config_file)
        except configparser.Error as e:
            error_msg = f"Failed to parse {config_file}: {e}"
            self.errors.append(error_msg)
            logger.error(error_msg)
            raise ConfigurationError(error_msg, details={'file': str(config_file)})
        except Exception as e:
            error_msg = f"Unexpected error reading {config_file}: {e}"
            self.errors.append(error_msg)
            logger.error(error_msg)
            raise ConfigurationError(error_msg, details={'file': str(config_file)})

        # General
        if parser.has_section('General'):
            self.config['system_name'] = parser.get('General', 'system_name', fallback=self.defaults['system_name'])
            self.config['log_level'] = parser.get('General', 'log_level', fallback=self.defaults['log_level'])
            self.config['max_database_size_mb'] = parser.getint('General', 'max_database_size_mb', fallback=self.defaults['max_database_size_mb'])
            self.config['retention_days'] = parser.getint('General', 'retention_days', fallback=self.defaults['retention_days'])

        # Network
        if parser.has_section('Network'):
            self.config['monitor_mode'] = parser.get('Network', 'monitor_mode', fallback=self.defaults['monitor_mode'])
            self.config['capture_interface'] = parser.get('Network', 'capture_interface', fallback=self.defaults['capture_interface'])
            self.config['capture_method'] = parser.get('Network', 'capture_method', fallback=self.defaults['capture_method'])
            self.config['buffer_size'] = parser.getint('Network', 'buffer_size', fallback=self.defaults['buffer_size'])
            self.config['enable_device_tracking'] = parser.getboolean('Network', 'enable_device_tracking', fallback=self.defaults['enable_device_tracking'])
            self.config['device_timeout'] = parser.getint('Network', 'device_timeout', fallback=self.defaults['device_timeout'])

        # Dashboard
        if parser.has_section('Dashboard'):
            self.config['web_port'] = parser.getint('Dashboard', 'web_port', fallback=self.defaults['web_port'])
            self.config['api_port'] = parser.getint('Dashboard', 'api_port', fallback=self.defaults['api_port'])
            self.config['web_host'] = parser.get('Dashboard', 'web_host', fallback=self.defaults['web_host'])
            self.config['enable_auth'] = parser.getboolean('Dashboard', 'enable_auth', fallback=self.defaults['enable_auth'])
            self.config['refresh_interval'] = parser.getint('Dashboard', 'refresh_interval', fallback=self.defaults['refresh_interval'])

        # Terminal
        if parser.has_section('Terminal'):
            self.config['terminal_refresh'] = parser.getint('Terminal', 'terminal_refresh', fallback=self.defaults['terminal_refresh'])
            self.config['terminal_theme'] = parser.get('Terminal', 'terminal_theme', fallback=self.defaults['terminal_theme'])

        # GeoIntelligence
        if parser.has_section('GeoIntelligence'):
            self.config['primary_geo_service'] = parser.get('GeoIntelligence', 'primary_geo_service', fallback=self.defaults['primary_geo_service'])
            self.config['enable_geo_cache'] = parser.getboolean('GeoIntelligence', 'enable_geo_cache', fallback=self.defaults['enable_geo_cache'])
            self.config['geo_cache_ttl'] = parser.getint('GeoIntelligence', 'geo_cache_ttl', fallback=self.defaults['geo_cache_ttl'])

        # ThreatScoring
        if parser.has_section('ThreatScoring'):
            self.config['enable_ip_reputation'] = parser.getboolean('ThreatScoring', 'enable_ip_reputation', fallback=self.defaults['enable_ip_reputation'])
            self.config['enable_ml_detection'] = parser.getboolean('ThreatScoring', 'enable_ml_detection', fallback=self.defaults['enable_ml_detection'])
            self.config['ml_update_interval'] = parser.getint('ThreatScoring', 'ml_update_interval', fallback=self.defaults['ml_update_interval'])
            self.config['alert_threshold'] = parser.getfloat('ThreatScoring', 'alert_threshold', fallback=self.defaults['alert_threshold'])

        # Export
        if parser.has_section('Export'):
            self.config['enable_csv_export'] = parser.getboolean('Export', 'enable_csv_export', fallback=self.defaults['enable_csv_export'])
            self.config['enable_json_export'] = parser.getboolean('Export', 'enable_json_export', fallback=self.defaults['enable_json_export'])
            self.config['export_directory'] = parser.get('Export', 'export_directory', fallback=self.defaults['export_directory'])

        # Features
        if parser.has_section('Features'):
            self.config['enable_webhooks'] = parser.getboolean('Features', 'enable_webhooks', fallback=self.defaults['enable_webhooks'])
            self.config['enable_email_alerts'] = parser.getboolean('Features', 'enable_email_alerts', fallback=self.defaults['enable_email_alerts'])
            self.config['enable_desktop_notifications'] = parser.getboolean('Features', 'enable_desktop_notifications', fallback=self.defaults['enable_desktop_notifications'])

        # WSL
        if parser.has_section('WSL'):
            self.config['enable_wsl_integration'] = parser.getboolean('WSL', 'enable_wsl_integration', fallback=self.defaults['enable_wsl_integration'])
            self.config['wsl_distribution'] = parser.get('WSL', 'wsl_distribution', fallback=self.defaults['wsl_distribution'])

        # RaspberryPi
        if parser.has_section('RaspberryPi'):
            self.config['enable_low_power_mode'] = parser.getboolean('RaspberryPi', 'enable_low_power_mode', fallback=self.defaults['enable_low_power_mode'])
            self.config['pi_worker_threads'] = parser.getint('RaspberryPi', 'pi_worker_threads', fallback=self.defaults['pi_worker_threads'])

    def _load_auth_config(self):
        """Load authentication configuration from auth.conf"""
        config_file = self.config_dir / "auth.conf"
        if not config_file.exists():
            self.warnings.append(f"Auth config not found: {config_file}")
            logger.warning(f"Auth config not found: {config_file}, using defaults")
            return

        try:
            parser = configparser.ConfigParser()
            parser.read(config_file)
        except configparser.Error as e:
            error_msg = f"Failed to parse {config_file}: {e}"
            self.warnings.append(error_msg)  # Non-critical, use warnings
            logger.warning(error_msg)
            return
        except Exception as e:
            error_msg = f"Unexpected error reading {config_file}: {e}"
            self.warnings.append(error_msg)
            logger.warning(error_msg)
            return

        if parser.has_section('BasicAuth'):
            self.config['auth_username'] = parser.get('BasicAuth', 'username', fallback=self.defaults['auth_username'])
            self.config['auth_password'] = parser.get('BasicAuth', 'password', fallback=self.defaults['auth_password'])
            self.config['session_timeout'] = parser.getint('BasicAuth', 'session_timeout', fallback=self.defaults['session_timeout'])
            self.config['max_login_attempts'] = parser.getint('BasicAuth', 'max_login_attempts', fallback=self.defaults['max_login_attempts'])
            self.config['lockout_duration'] = parser.getint('BasicAuth', 'lockout_duration', fallback=self.defaults['lockout_duration'])
            # [SEC-004 PATCH] Load strict password mode setting
            self.config['auth_strict_mode'] = parser.getboolean('BasicAuth', 'strict_mode', fallback=self.defaults.get('auth_strict_mode', True))

    def _load_threat_intel_config(self):
        """Load threat intelligence API configuration from threat_intel.conf"""
        config_file = self.config_dir / "threat_intel.conf"
        if not config_file.exists():
            self.warnings.append(f"Threat intel config not found: {config_file}")
            logger.warning(f"Threat intel config not found: {config_file}, using defaults")
            return

        try:
            parser = configparser.ConfigParser()
            parser.read(config_file)
        except configparser.Error as e:
            error_msg = f"Failed to parse {config_file}: {e}"
            self.warnings.append(error_msg)  # Non-critical, use warnings
            logger.warning(error_msg)
            return
        except Exception as e:
            error_msg = f"Unexpected error reading {config_file}: {e}"
            self.warnings.append(error_msg)
            logger.warning(error_msg)
            return

        # AbuseIPDB
        if parser.has_section('AbuseIPDB'):
            self.config['abuseipdb_api_key'] = parser.get('AbuseIPDB', 'api_key', fallback=self.defaults['abuseipdb_api_key'])
            self.config['abuseipdb_enabled'] = parser.getboolean('AbuseIPDB', 'enabled', fallback=self.defaults['abuseipdb_enabled'])
            self.config['abuseipdb_cache_ttl'] = parser.getint('AbuseIPDB', 'cache_ttl', fallback=self.defaults['abuseipdb_cache_ttl'])
            self.config['abuseipdb_confidence_threshold'] = parser.getint('AbuseIPDB', 'confidence_threshold', fallback=self.defaults['abuseipdb_confidence_threshold'])

        # VirusTotal
        if parser.has_section('VirusTotal'):
            self.config['virustotal_api_key'] = parser.get('VirusTotal', 'api_key', fallback=self.defaults['virustotal_api_key'])
            self.config['virustotal_enabled'] = parser.getboolean('VirusTotal', 'enabled', fallback=self.defaults['virustotal_enabled'])
            self.config['virustotal_cache_ttl'] = parser.getint('VirusTotal', 'cache_ttl', fallback=self.defaults['virustotal_cache_ttl'])
            self.config['virustotal_malicious_threshold'] = parser.getint('VirusTotal', 'malicious_threshold', fallback=self.defaults['virustotal_malicious_threshold'])

        # ThreatFeed
        if parser.has_section('ThreatFeed'):
            self.config['threat_priority'] = parser.get('ThreatFeed', 'priority', fallback=self.defaults['threat_priority'])
            self.config['fallback_to_local'] = parser.getboolean('ThreatFeed', 'fallback_to_local', fallback=self.defaults['fallback_to_local'])
            self.config['enable_rate_limiting'] = parser.getboolean('ThreatFeed', 'enable_rate_limiting', fallback=self.defaults['enable_rate_limiting'])
            self.config['max_requests_per_minute'] = parser.getint('ThreatFeed', 'max_requests_per_minute', fallback=self.defaults['max_requests_per_minute'])

    def _load_env_overrides(self):
        """Load configuration overrides from environment variables"""
        env_mapping = {
            'COBALTGRAPH_CAPTURE_METHOD': 'capture_method',
            'COBALTGRAPH_WEB_PORT': ('web_port', int),
            'COBALTGRAPH_API_PORT': ('api_port', int),
            'COBALTGRAPH_WEB_HOST': 'web_host',
            'COBALTGRAPH_ENABLE_AUTH': ('enable_auth', lambda x: x.lower() in ['true', '1', 'yes']),
            'COBALTGRAPH_AUTH_USERNAME': 'auth_username',
            'COBALTGRAPH_AUTH_PASSWORD': 'auth_password',
            'COBALTGRAPH_ABUSEIPDB_KEY': 'abuseipdb_api_key',
            'COBALTGRAPH_VIRUSTOTAL_KEY': 'virustotal_api_key',
            'COBALTGRAPH_LOG_LEVEL': 'log_level',
        }

        for env_var, config_key in env_mapping.items():
            if env_var in os.environ:
                # Handle tuple (key, converter)
                if isinstance(config_key, tuple):
                    key, converter = config_key
                    try:
                        self.config[key] = converter(os.environ[env_var])
                    except Exception as e:
                        self.warnings.append(f"Invalid env var {env_var}: {e}")
                else:
                    self.config[config_key] = os.environ[env_var]

        # [SEC-007 PATCH] Clear sensitive environment variables after loading
        # Prevents exposure via 'ps' command output and /proc/[pid]/environ
        sensitive_vars = [
            'COBALTGRAPH_AUTH_PASSWORD',
            'COBALTGRAPH_ABUSEIPDB_KEY',
            'COBALTGRAPH_VIRUSTOTAL_KEY'
        ]

        for var in sensitive_vars:
            if var in os.environ:
                del os.environ[var]
                logger.info(f"[SEC-007] Cleared {var} from environment for process isolation")

    def _validate_authentication(self):
        """Validate authentication credentials meet security standards (SEC-004 PATCH)"""
        if not self.config['enable_auth']:
            return  # Auth disabled, skip validation

        password = self.config['auth_password']
        username = self.config['auth_username']

        # Check if strict mode is enabled (from config file)
        strict_mode = self.config.get('auth_strict_mode', True)

        # Check for default credentials
        if password == 'changeme':
            error_msg = f"[SEC-004] CRITICAL: Using default password 'changeme'. Change in config/auth.conf immediately!"
            self.errors.append(error_msg)

        if username == 'admin' and strict_mode:
            self.warnings.append(
                f"[SEC-004] Default username 'admin' detected. Consider changing in config/auth.conf"
            )

        # Check password length
        if len(password) < 12 and strict_mode:
            self.errors.append(
                f"[SEC-004] Password too short (current: {len(password)}, minimum: 12 characters)"
            )

        # Check password complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?' for c in password)

        complexity = sum([has_upper, has_lower, has_digit, has_symbol])

        if strict_mode and complexity < 3:
            self.errors.append(
                f"[SEC-004] Weak password complexity (requires uppercase, lowercase, numbers, symbols). "
                f"Current: {complexity}/4 requirements met."
            )

        logger.info(f"[SEC-004] Password validation: {complexity}/4 complexity requirements met, strict_mode={strict_mode}")

    def _validate_file_permissions(self):
        """Validate credential file security including symlinks and hardlinks (SEC-001 PATCH)"""
        sensitive_files = [
            self.config_dir / "auth.conf",
            self.config_dir / "threat_intel.conf"
        ]

        for filepath in sensitive_files:
            if not filepath.exists():
                continue

            file_stat = filepath.lstat()  # Use lstat for symlink detection

            # Check for symlinks
            if stat.S_ISLNK(file_stat.st_mode):
                self.errors.append(
                    f"[SEC-001] CRITICAL: {filepath.name} is a symlink! "
                    f"This is a security risk and must be replaced with a real file."
                )

            # Check for hardlinks
            if file_stat.st_nlink > 1:
                self.errors.append(
                    f"[SEC-001] CRITICAL: {filepath.name} has {file_stat.st_nlink} hardlinks. "
                    f"Credentials may be accessible from multiple locations. Remove hardlinks!"
                )

            # Check permissions
            perms = file_stat.st_mode & 0o777
            if perms & 0o004:  # world-readable
                self.errors.append(
                    f"[SEC-001] CRITICAL: {filepath.name} is world-readable (perms: {oct(perms)}). "
                    f"Run: chmod 600 {filepath}"
                )

            if perms & 0o020:  # group-writable
                self.errors.append(
                    f"[SEC-001] CRITICAL: {filepath.name} is group-writable (perms: {oct(perms)}). "
                    f"Run: chmod 600 {filepath}"
                )

    def _validate(self):
        """Validate configuration values"""
        # Validate monitor mode
        valid_monitor_modes = ['auto', 'device', 'network']
        if self.config['monitor_mode'] not in valid_monitor_modes:
            self.errors.append(f"Invalid monitor_mode: {self.config['monitor_mode']} (must be: {', '.join(valid_monitor_modes)})")

        # Validate capture method (legacy)
        valid_capture_methods = ['auto', 'grey_man', 'ss']
        if self.config['capture_method'] not in valid_capture_methods:
            self.errors.append(f"Invalid capture_method: {self.config['capture_method']} (must be: {', '.join(valid_capture_methods)})")

        # Validate web port
        if not (1 <= self.config['web_port'] <= 65535):
            self.errors.append(f"Invalid web_port: {self.config['web_port']} (must be 1-65535)")

        # Validate API port
        if not (1 <= self.config['api_port'] <= 65535):
            self.errors.append(f"Invalid api_port: {self.config['api_port']} (must be 1-65535)")

        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.config['log_level'] not in valid_log_levels:
            self.errors.append(f"Invalid log_level: {self.config['log_level']} (must be: {', '.join(valid_log_levels)})")

        # Validate alert threshold
        if not (0.0 <= self.config['alert_threshold'] <= 1.0):
            self.errors.append(f"Invalid alert_threshold: {self.config['alert_threshold']} (must be 0.0-1.0)")

        # Warn about default password
        if self.config['enable_auth'] and self.config['auth_password'] == 'changeme':
            self.warnings.append("Using default password 'changeme' - CHANGE THIS FOR PRODUCTION!")

        # Warn about disabled threat intelligence
        if self.config['enable_ip_reputation']:
            if not self.config['abuseipdb_api_key'] and not self.config['virustotal_api_key']:
                self.warnings.append("IP reputation enabled but no API keys configured")

        # Warn about public web host
        if self.config['web_host'] == '0.0.0.0' and not self.config['enable_auth']:
            self.warnings.append("Web dashboard exposed on all interfaces without authentication - SECURITY RISK!")

        # [SEC-001 PATCH] Validate file permissions on credential files
        self._validate_file_permissions()

        # [SEC-004 PATCH] Validate authentication credentials
        self._validate_authentication()

    def get_threat_intel_status(self) -> Dict[str, Tuple[bool, str]]:
        """Get status of threat intelligence services"""
        status = {}

        # Check VirusTotal
        vt_enabled = (
            self.config['virustotal_enabled'] and
            bool(self.config['virustotal_api_key'])
        )
        vt_reason = "ENABLED" if vt_enabled else (
            "No API key" if not self.config['virustotal_api_key'] else "Disabled in config"
        )
        status['VirusTotal'] = (vt_enabled, vt_reason)

        # Check AbuseIPDB
        abuse_enabled = (
            self.config['abuseipdb_enabled'] and
            bool(self.config['abuseipdb_api_key'])
        )
        abuse_reason = "ENABLED" if abuse_enabled else (
            "No API key" if not self.config['abuseipdb_api_key'] else "Disabled in config"
        )
        status['AbuseIPDB'] = (abuse_enabled, abuse_reason)

        return status

    def print_status(self, verbose: bool = True):
        """Print configuration status to terminal"""
        print(f"{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")
        print(f"{Colors.BLUE}  {self.config['system_name']} Configuration Status{Colors.NC}")
        print(f"{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")
        print()

        # Network Monitoring
        print(f"{Colors.GREEN}Network Monitoring:{Colors.NC}")

        mode_desc = {
            'auto': 'auto (network → device fallback)',
            'device': 'device (this machine only)',
            'network': 'network (entire segment - requires sudo)'
        }
        mode_color = Colors.GREEN if self.config['monitor_mode'] == 'network' else Colors.YELLOW
        print(f"  ✅ Mode: {mode_color}{mode_desc.get(self.config['monitor_mode'], self.config['monitor_mode'])}{Colors.NC}")

        if self.config['capture_interface']:
            print(f"  ✅ Interface: {self.config['capture_interface']}")
        else:
            print(f"  ✅ Interface: auto-detect")

        if self.config['enable_device_tracking']:
            print(f"  ✅ Device Tracking: {Colors.GREEN}ENABLED{Colors.NC} (MAC address identification)")
        else:
            print(f"  ⚠️  Device Tracking: {Colors.YELLOW}DISABLED{Colors.NC}")

        if self.config['monitor_mode'] == 'network':
            print(f"  ⚠️  Network mode requires sudo and promiscuous mode capability")
        print()

        # Threat Intelligence
        print(f"{Colors.GREEN}Threat Intelligence:{Colors.NC}")
        threat_status = self.get_threat_intel_status()

        for service, (enabled, reason) in threat_status.items():
            if enabled:
                print(f"  ✅ {service}: {Colors.GREEN}ENABLED{Colors.NC}")
            else:
                print(f"  ⚠️  {service}: {Colors.YELLOW}{reason}{Colors.NC}")

        if threat_status['VirusTotal'][0] or threat_status['AbuseIPDB'][0]:
            priority = self.config['threat_priority'].split(',')
            print(f"  ℹ️  Priority chain: {' → '.join(priority)}")
        print()

        # Dashboard
        print(f"{Colors.GREEN}Dashboard:{Colors.NC}")
        host_display = "all interfaces" if self.config['web_host'] == '0.0.0.0' else self.config['web_host']
        print(f"  ✅ Web: http://{self.config['web_host']}:{self.config['web_port']}")
        print(f"  ✅ API: http://{self.config['web_host']}:{self.config['api_port']}")

        if self.config['enable_auth']:
            # [SEC-006 PATCH] Don't expose username in output
            print(f"  ✅ Authentication: {Colors.GREEN}ENABLED{Colors.NC}")
        else:
            print(f"  ⚠️  Authentication: {Colors.YELLOW}DISABLED{Colors.NC} (enable for production!)")
        print()

        # Features
        print(f"{Colors.GREEN}Features:{Colors.NC}")
        if self.config['enable_ml_detection']:
            print(f"  ✅ ML Anomaly Detection: {Colors.GREEN}ENABLED{Colors.NC}")
        if self.config['enable_csv_export']:
            print(f"  ✅ CSV Export: {Colors.GREEN}ENABLED{Colors.NC}")
        if self.config['enable_json_export']:
            print(f"  ✅ JSON Export: {Colors.GREEN}ENABLED{Colors.NC}")

        # Planned features
        planned = []
        if self.config['enable_webhooks']:
            planned.append("Webhooks")
        if self.config['enable_email_alerts']:
            planned.append("Email Alerts")
        if self.config['enable_desktop_notifications']:
            planned.append("Desktop Notifications")

        if planned:
            print(f"  ℹ️  Planned: {', '.join(planned)}")
        else:
            print(f"  ⚠️  Webhooks/Alerts: {Colors.YELLOW}PLANNED{Colors.NC} (not implemented)")
        print()

        # Warnings
        if self.warnings:
            print(f"{Colors.YELLOW}⚠️  Warnings:{Colors.NC}")
            for warning in self.warnings:
                print(f"  • {warning}")
            print()

        # Errors
        if self.errors:
            print(f"{Colors.RED}❌ Errors:{Colors.NC}")
            for error in self.errors:
                print(f"  • {error}")
            print()

        print(f"{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")
        print()


def load_config(config_dir: str = "config", verbose: bool = True) -> Dict[str, Any]:
    """
    Convenience function to load and validate configuration

    Args:
        config_dir: Path to configuration directory
        verbose: Print status to terminal

    Returns:
        Configuration dictionary

    Raises:
        SystemExit: If configuration has errors
    """
    loader = ConfigLoader(config_dir)
    config = loader.load()

    if verbose:
        loader.print_status()

    # Exit if errors
    if loader.errors:
        print(f"{Colors.RED}Configuration has errors. Please fix and restart.{Colors.NC}")
        sys.exit(1)

    return config


if __name__ == "__main__":
    # Test configuration loading
    config = load_config()
    print(f"Configuration loaded successfully!")
    print(f"Sample values:")
    print(f"  - System: {config['system_name']}")
    print(f"  - Capture method: {config['capture_method']}")
    print(f"  - Web port: {config['web_port']}")
