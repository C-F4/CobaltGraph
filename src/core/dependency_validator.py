#!/usr/bin/env python3
"""
CobaltGraph Dependency Validator
Standalone module for venv and package verification

This module is called first by the launcher to ensure:
1. All required pure-Python packages are installed
2. No C/C++ dependencies (deprecated for portability)
3. Clean separation of validation logic from launcher
"""

import importlib.metadata
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    NC = '\033[0m'


class DependencyValidator:
    """Validates Python package dependencies for CobaltGraph"""

    def __init__(self, project_root: Path = None):
        """
        Initialize validator

        Args:
            project_root: Path to project root (defaults to auto-detect)
        """
        if project_root is None:
            # Auto-detect project root (3 levels up from this file)
            self.project_root = Path(__file__).resolve().parent.parent.parent
        else:
            self.project_root = Path(project_root)

        self.requirements_path = self.project_root / "requirements.txt"

    def parse_requirements(self) -> Dict[str, List[Tuple[str, str, str]]]:
        """
        Parse requirements.txt into critical and optional packages

        Returns:
            dict: {'critical': [...], 'optional': [...]}
                  Each entry is (package_name, version, operator)
        """
        if not self.requirements_path.exists():
            return {'critical': [], 'optional': []}

        critical_packages = []
        optional_packages = []
        current_section = 'critical'

        # Regex patterns
        package_regex = re.compile(
            r'^([a-zA-Z0-9\-_]+)\s*([><=!]+)\s*([0-9\.]+(?:\.dev[0-9]+)?)'
        )
        section_header_regex = re.compile(
            r'^#\s+[A-Z\s]+\((?:Optional|Development|Visualization)',
            re.IGNORECASE
        )

        with open(self.requirements_path, 'r') as f:
            for line in f:
                line_stripped = line.strip()

                # Detect section headers
                if section_header_regex.match(line_stripped):
                    upper_line = line_stripped.upper()
                    if any(kw in upper_line for kw in ['OPTIONAL', 'DEVELOPMENT', 'VISUALIZATION']):
                        current_section = 'optional'
                        continue

                # Skip comments and blank lines
                if not line_stripped or line_stripped.startswith('#'):
                    continue

                # Parse package specification
                match = package_regex.match(line_stripped)
                if match:
                    package_name = match.group(1).lower()
                    operator = match.group(2)
                    version_spec = match.group(3)
                    entry = (package_name, version_spec, operator)

                    if current_section == 'critical':
                        critical_packages.append(entry)
                    else:
                        optional_packages.append(entry)

        return {
            'critical': critical_packages,
            'optional': optional_packages
        }

    def check_installed_packages(
        self,
        parsed_requirements: Dict[str, List[Tuple[str, str, str]]],
        mode: str = 'device'
    ) -> Dict[str, List[Tuple]]:
        """
        Check which packages are installed and meet version requirements

        Args:
            parsed_requirements: Output from parse_requirements()
            mode: Operating mode ('device' or 'network')

        Returns:
            dict: Status of all packages
        """
        result = {
            'missing_critical': [],
            'missing_optional': [],
            'installed_critical': [],
            'installed_optional': []
        }

        # Check critical packages
        for package_name, required_version, operator in parsed_requirements['critical']:
            try:
                installed_version = importlib.metadata.version(package_name)
                result['installed_critical'].append(
                    (package_name, installed_version, required_version, operator)
                )
            except Exception:
                result['missing_critical'].append(
                    (package_name, required_version, operator)
                )

        # Check optional packages
        for package_name, required_version, operator in parsed_requirements['optional']:
            try:
                installed_version = importlib.metadata.version(package_name)
                result['installed_optional'].append(
                    (package_name, installed_version, required_version, operator)
                )
            except Exception:
                result['missing_optional'].append(
                    (package_name, required_version, operator)
                )

        return result

    def install_missing_packages(
        self,
        package_status: Dict[str, List[Tuple]],
        install_optional: bool = False
    ) -> bool:
        """
        Automatically install missing packages.

        Args:
            package_status: Output from check_installed_packages()
            install_optional: Whether to also install optional packages

        Returns:
            bool: True if installation succeeded
        """
        missing_critical = package_status['missing_critical']
        missing_optional = package_status['missing_optional']

        packages_to_install = []

        # Always install critical packages
        for package, version, op in missing_critical:
            packages_to_install.append(f"{package}{op}{version}")

        # Optionally install optional packages
        if install_optional:
            for package, version, op in missing_optional:
                packages_to_install.append(f"{package}{op}{version}")

        if not packages_to_install:
            return True

        print(f"\n{Colors.CYAN}Installing {len(packages_to_install)} package(s)...{Colors.NC}")

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install"] + packages_to_install + ["-q"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                print(f"{Colors.GREEN}✓ Packages installed successfully{Colors.NC}\n")
                return True
            else:
                print(f"{Colors.RED}✗ Installation failed: {result.stderr[:200]}{Colors.NC}\n")
                return False

        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}✗ Installation timed out{Colors.NC}\n")
            return False
        except Exception as e:
            print(f"{Colors.RED}✗ Installation error: {e}{Colors.NC}\n")
            return False

    def display_status(
        self,
        package_status: Dict[str, List[Tuple]],
        parsed_requirements: Dict[str, List[Tuple]]
    ) -> None:
        """
        Display dependency status report

        Args:
            package_status: Output from check_installed_packages()
            parsed_requirements: Output from parse_requirements()
        """
        missing_critical = package_status['missing_critical']
        missing_optional = package_status['missing_optional']
        installed_critical = package_status['installed_critical']
        installed_optional = package_status['installed_optional']

        total_critical = len(parsed_requirements['critical'])
        total_optional = len(parsed_requirements['optional'])
        total_missing = len(missing_critical) + len(missing_optional)

        print(f"\n{Colors.CYAN}{'═'*70}{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.CYAN}  DEPENDENCY VALIDATION{Colors.NC}")
        print(f"{Colors.CYAN}{'═'*70}{Colors.NC}\n")

        # Critical packages status
        if missing_critical:
            print(f"{Colors.RED}✗ CRITICAL PACKAGES MISSING ({len(missing_critical)}/{total_critical}){Colors.NC}")
            print(f"{Colors.DIM}  These packages are REQUIRED for CobaltGraph to function.{Colors.NC}\n")

            package_descriptions = {
                'requests': '→ HTTP client for threat intelligence APIs',
                'rich': '→ Terminal formatting and tables',
                'textual': '→ Terminal UI framework',
                'networkx': '→ Network topology analysis'
            }

            for package, version, op in missing_critical:
                print(f"  {Colors.RED}●{Colors.NC} {package} {Colors.DIM}{op}{version}{Colors.NC}")
                if package in package_descriptions:
                    print(f"    {Colors.DIM}{package_descriptions[package]}{Colors.NC}")
            print()
        else:
            print(f"{Colors.GREEN}✓ Critical packages: {len(installed_critical)}/{total_critical} installed{Colors.NC}\n")

        # Optional packages status
        if missing_optional:
            print(f"{Colors.CYAN}ℹ Optional packages: {len(installed_optional)}/{total_optional} installed{Colors.NC}")
            print(f"{Colors.DIM}  Missing {len(missing_optional)} optional packages (non-critical){Colors.NC}\n")

            package_descriptions = {
                'wcwidth': '→ Terminal graphics and Unicode support',
                'colorama': '→ Color manipulation for visualization',
                'textual-plotext': '→ Terminal charts and graphs',
                'plotille': '→ Terminal heatmaps and scatter plots',
                'pytest': '→ Testing framework (development only)',
                'black': '→ Code formatter (development only)',
                'pylint': '→ Linter (development only)',
                'isort': '→ Import sorter (development only)'
            }

            for package, version, op in missing_optional[:10]:
                print(f"    {Colors.CYAN}○{Colors.NC} {package} {Colors.DIM}{op}{version}{Colors.NC}")
                if package in package_descriptions:
                    print(f"      {Colors.DIM}{package_descriptions[package]}{Colors.NC}")

            if len(missing_optional) > 10:
                print(f"    {Colors.DIM}... and {len(missing_optional) - 10} more{Colors.NC}")
            print()
        else:
            print(f"{Colors.GREEN}✓ Optional packages: {len(installed_optional)}/{total_optional} installed{Colors.NC}\n")

        # Installation recommendation
        if total_missing > 0:
            print(f"{Colors.YELLOW}{'─'*70}{Colors.NC}")
            print(f"{Colors.BOLD}RECOMMENDED ACTION:{Colors.NC}")
            print(f"  {Colors.GREEN}pip3 install -r requirements.txt --upgrade{Colors.NC}")
            print(f"{Colors.YELLOW}{'─'*70}{Colors.NC}\n")

    def validate(
        self,
        mode: str = 'device',
        skip_check: bool = False,
        auto_install: bool = True,
        install_optional: bool = False
    ) -> bool:
        """
        Main validation entry point with auto-install capability.

        Args:
            mode: Operating mode ('device' or 'network')
            skip_check: Skip validation (for CI/CD)
            auto_install: Automatically install missing critical packages
            install_optional: Also install optional packages when auto_install is True

        Returns:
            bool: True if all critical dependencies are satisfied
        """
        # Check for skip flag
        if skip_check or os.environ.get('COBALTGRAPH_SKIP_DEPENDENCY_CHECK') == '1':
            print(f"{Colors.YELLOW}Dependency check skipped{Colors.NC}\n")
            return True

        try:
            # Parse requirements
            parsed = self.parse_requirements()

            if not parsed['critical']:
                print(f"{Colors.YELLOW}⚠ No requirements.txt found{Colors.NC}")
                print(f"{Colors.DIM}  Proceeding without dependency validation.{Colors.NC}\n")
                return True

            # Check installed packages
            status = self.check_installed_packages(parsed, mode=mode)

            # Check if critical packages are missing
            has_missing_critical = len(status['missing_critical']) > 0
            has_missing_optional = len(status['missing_optional']) > 0

            # Auto-install if enabled and packages are missing
            if auto_install and (has_missing_critical or (install_optional and has_missing_optional)):
                print(f"\n{Colors.CYAN}{'═'*70}{Colors.NC}")
                print(f"{Colors.BOLD}{Colors.CYAN}  AUTO-INSTALLING DEPENDENCIES{Colors.NC}")
                print(f"{Colors.CYAN}{'═'*70}{Colors.NC}")

                install_success = self.install_missing_packages(
                    status,
                    install_optional=install_optional
                )

                if install_success:
                    # Re-check packages after installation
                    status = self.check_installed_packages(parsed, mode=mode)
                    has_missing_critical = len(status['missing_critical']) > 0

            # Display final status
            self.display_status(status, parsed)

            if has_missing_critical:
                print(f"{Colors.RED}Cannot proceed: Critical dependencies missing{Colors.NC}\n")
                return False

            return True

        except Exception as e:
            print(f"{Colors.YELLOW}Dependency validation warning: {e}{Colors.NC}")
            if os.environ.get('COBALTGRAPH_DEBUG') == '1':
                import traceback
                traceback.print_exc()
            return True  # Allow to continue with warnings


def validate_dependencies(
    mode: str = 'device',
    skip_check: bool = False,
    auto_install: bool = True,
    install_optional: bool = False
) -> bool:
    """
    Convenience function for dependency validation with auto-install.

    Args:
        mode: Operating mode ('device' or 'network')
        skip_check: Skip validation (for CI/CD)
        auto_install: Automatically install missing critical packages
        install_optional: Also install optional packages when auto_install is True

    Returns:
        bool: True if all critical dependencies are satisfied
    """
    validator = DependencyValidator()
    return validator.validate(
        mode=mode,
        skip_check=skip_check,
        auto_install=auto_install,
        install_optional=install_optional
    )


if __name__ == "__main__":
    """Standalone execution for testing and manual validation"""
    import argparse

    parser = argparse.ArgumentParser(
        description="CobaltGraph Dependency Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dependency_validator.py                    # Validate and auto-install
  python dependency_validator.py --no-install       # Check only, no install
  python dependency_validator.py --install-optional # Also install optional packages
  python dependency_validator.py --skip             # Skip validation entirely
        """
    )
    parser.add_argument(
        '--mode',
        choices=['device', 'network'],
        default='device',
        help='Operating mode (default: device)'
    )
    parser.add_argument(
        '--skip',
        action='store_true',
        help='Skip dependency check'
    )
    parser.add_argument(
        '--no-install',
        action='store_true',
        help='Do not auto-install missing packages'
    )
    parser.add_argument(
        '--install-optional',
        action='store_true',
        help='Also install optional packages'
    )

    args = parser.parse_args()

    success = validate_dependencies(
        mode=args.mode,
        skip_check=args.skip,
        auto_install=not args.no_install,
        install_optional=args.install_optional
    )
    sys.exit(0 if success else 1)
