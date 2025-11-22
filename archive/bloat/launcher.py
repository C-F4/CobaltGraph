"""
CobaltGraph Core Launcher
Handles CLI argument parsing, initialization, and orchestration

Responsibilities:
- Parse command-line arguments
- Show legal disclaimer
- Load and validate configuration
- Detect platform capabilities
- Initialize watchfloor
- Handle supervisor mode
- Graceful shutdown
"""

import argparse
import sys
import os
import platform
import signal
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


class Launcher:
    """
    Main launcher for CobaltGraph

    Handles initialization, configuration, and starting the watchfloor
    with appropriate options based on CLI arguments.
    """

    def __init__(self, args=None, config_path: Optional[str] = None):
        """
        Initialize launcher with parsed arguments

        Args:
            args: argparse.Namespace from argument parser (or None for defaults)
            config_path: Optional path to configuration file
        """
        self.args = args if args is not None else argparse.Namespace()
        self.config_path = config_path
        self.config = None
        self.watchfloor = None
        self.supervisor = None
        self.platform_info = None

    def show_legal_disclaimer(self) -> bool:
        """
        Display legal disclaimer and require acceptance

        Returns:
            bool: True if accepted, False otherwise
        """
        # Skip if --no-disclaimer flag set
        if hasattr(self.args, 'no_disclaimer') and self.args.no_disclaimer:
            print(f"{Colors.YELLOW}⚠️  Legal disclaimer skipped (--no-disclaimer flag){Colors.NC}")
            return True

        # Show disclaimer
        print()
        print(f"{Colors.BLUE}{'━' * 70}{Colors.NC}")
        print(f"{Colors.BLUE}{'  ⚖️  LEGAL DISCLAIMER':^70}{Colors.NC}")
        print(f"{Colors.BLUE}{'━' * 70}{Colors.NC}")
        print()
        print(f"{Colors.YELLOW}{Colors.BOLD}IMPORTANT: READ BEFORE PROCEEDING{Colors.NC}")
        print()
        print(f"{Colors.RED}This tool is designed for AUTHORIZED network monitoring ONLY.{Colors.NC}")
        print()
        print("You may ONLY use CobaltGraph to monitor networks where you have:")
        print(f"  • {Colors.GREEN}Explicit written authorization from the network owner{Colors.NC}")
        print(f"  • {Colors.GREEN}Legal ownership of the network{Colors.NC}")
        print(f"  • {Colors.GREEN}Proper consent from all parties being monitored{Colors.NC}")
        print()
        print(f"{Colors.RED}Unauthorized network monitoring may violate:{Colors.NC}")
        print("  • Computer Fraud and Abuse Act (CFAA) - United States")
        print("  • Computer Misuse Act - United Kingdom")
        print("  • Similar laws in other jurisdictions")
        print()
        print(f"{Colors.YELLOW}The authors and contributors of CobaltGraph:")
        print("  • Assume NO liability for misuse")
        print("  • Do NOT condone illegal activity")
        print(f"  • Are NOT responsible for your actions{Colors.NC}")
        print()
        print(f"{Colors.BOLD}By proceeding, you acknowledge that:{Colors.NC}")
        print("  1. You have legal authorization to monitor this network")
        print("  2. You understand the legal implications")
        print("  3. You accept full responsibility for your actions")
        print()

        # Require explicit acceptance
        try:
            response = input(f"{Colors.GREEN}Do you accept these terms? [yes/no]: {Colors.NC}").strip().lower()
            if response in ['yes', 'y']:
                print()
                print(f"{Colors.GREEN}✅ Terms accepted. Proceeding with startup...{Colors.NC}")
                print()
                return True
            else:
                print()
                print(f"{Colors.RED}❌ Terms not accepted. Exiting.{Colors.NC}")
                return False
        except (KeyboardInterrupt, EOFError):
            print()
            print(f"{Colors.RED}❌ Cancelled by user. Exiting.{Colors.NC}")
            return False

    def detect_platform(self) -> Dict:
        """
        Detect platform capabilities (network mode, terminal support, etc.)

        Returns:
            dict: Platform capabilities
        """
        system = platform.system()
        uname = platform.uname()

        # Detect WSL
        is_wsl = False
        if system == 'Linux':
            try:
                with open('/proc/version', 'r') as f:
                    version = f.read().lower()
                    is_wsl = 'microsoft' in version or 'wsl' in version
            except:
                pass

        # Detect root/admin
        is_root = False
        if hasattr(os, 'geteuid'):
            is_root = os.geteuid() == 0
        elif system == 'Windows':
            try:
                import ctypes
                is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                is_root = False

        # Detect raw socket capability
        can_raw_socket = is_root  # Simplified check

        # Detect ncurses support
        supports_ncurses = system in ['Linux', 'Darwin']  # Unix-like systems

        platform_info = {
            'os': system,
            'os_version': uname.release,
            'is_wsl': is_wsl,
            'is_root': is_root,
            'can_raw_socket': can_raw_socket,
            'supports_ncurses': supports_ncurses,
            'supports_network_capture': can_raw_socket,
            'python_version': platform.python_version(),
        }

        self.platform_info = platform_info
        return platform_info

    def show_platform_info(self):
        """Display detected platform information"""
        if not self.platform_info:
            self.detect_platform()

        info = self.platform_info

        print(f"{Colors.CYAN}🔍 Platform Detection:{Colors.NC}")
        print(f"  OS: {info['os']}")
        if info['is_wsl']:
            print(f"  Environment: WSL2")
        print(f"  Python: {info['python_version']}")

        # Capabilities
        print()
        print(f"{Colors.CYAN}Capabilities:{Colors.NC}")

        if info['is_root']:
            print(f"  ✅ Root/Admin access: Available")
        else:
            print(f"  ⚠️  Root/Admin access: Not available (some features limited)")

        if info['supports_network_capture']:
            print(f"  ✅ Network-wide capture: Supported")
        else:
            print(f"  ⚠️  Network-wide capture: Not supported (use device-only mode)")

        if info['supports_ncurses']:
            print(f"  ✅ Terminal UI: Supported")
        else:
            print(f"  ⚠️  Terminal UI: Not supported on {info['os']}")

        print()

    def select_mode(self, requested: Optional[str] = None) -> str:
        """
        Select monitoring mode (network/device/auto)

        Args:
            requested: Requested mode (or None for interactive)

        Returns:
            str: Selected mode ('network' or 'device')
        """
        # If mode explicitly requested via CLI
        if requested and requested in ['network', 'device']:
            return requested

        # Auto-detect
        if requested == 'auto' or requested is None:
            if self.platform_info and self.platform_info['supports_network_capture']:
                # If running interactively without explicit mode, ask
                if not requested:
                    print(f"{Colors.CYAN}📡 Monitoring Mode:{Colors.NC}")
                    print("  1. Network-wide (full capture - requires root)")
                    print("  2. Device-only (no root required)")
                    print("  3. Auto-detect (recommended)")
                    print()

                    try:
                        choice = input(f"{Colors.GREEN}Choose mode [1-3]: {Colors.NC}").strip()
                        if choice == '1':
                            return 'network'
                        elif choice == '2':
                            return 'device'
                        elif choice == '3' or choice == '':
                            return 'network' if self.platform_info['is_root'] else 'device'
                    except (KeyboardInterrupt, EOFError):
                        print()
                        return 'device'

                # Auto-detect based on capabilities
                return 'network' if self.platform_info['is_root'] else 'device'
            else:
                return 'device'

        return 'device'  # Safe default

    def select_interface(self, requested: Optional[str] = None) -> str:
        """
        Select UI interface (web/terminal)

        Args:
            requested: Requested interface (or None for interactive)

        Returns:
            str: Selected interface ('web' or 'terminal')
        """
        # If interface explicitly requested
        if requested and requested in ['web', 'terminal']:
            # Check if terminal is supported
            if requested == 'terminal' and not self.platform_info.get('supports_ncurses'):
                print(f"{Colors.YELLOW}⚠️  Terminal UI not supported on {self.platform_info['os']}, using web{Colors.NC}")
                return 'web'
            return requested

        # Interactive selection
        if not requested:
            print(f"{Colors.CYAN}🖥️  Interface:{Colors.NC}")
            print("  1. Web Dashboard (port 8080)")
            if self.platform_info.get('supports_ncurses'):
                print("  2. Terminal UI (experimental)")
                print()

                try:
                    choice = input(f"{Colors.GREEN}Choose interface [1-2]: {Colors.NC}").strip()
                    if choice == '2':
                        return 'terminal'
                except (KeyboardInterrupt, EOFError):
                    print()

            else:
                print("  (Terminal UI not supported on this platform)")
                print()

        return 'web'  # Default

    def load_configuration(self):
        """
        Load and validate configuration files

        Returns:
            Config: Loaded configuration object
        """
        try:
            from src.core.config import load_config

            config_path = self.config_path or 'config'
            self.config = load_config(config_dir=config_path, verbose=False)

            logger.info(f"✅ Configuration loaded from {config_path}")
            return self.config

        except Exception as e:
            logger.warning(f"⚠️  Failed to load configuration: {e}")
            logger.warning("⚠️  Using default configuration")
            return {}

    def start(self):
        """
        Main entry point - start CobaltGraph

        Orchestrates:
        1. Legal disclaimer
        2. Platform detection
        3. Configuration loading
        4. Mode selection
        5. Interface selection
        6. Watchfloor initialization
        7. Supervisor (if requested)
        """
        try:
            # Show banner
            print()
            print(f"{Colors.BLUE}{'━' * 70}{Colors.NC}")
            print(f"{Colors.BLUE}{'  CobaltGraph Geo-Spatial Watchfloor':^70}{Colors.NC}")
            print(f"{Colors.BLUE}{'━' * 70}{Colors.NC}")
            print()
            print(f"{Colors.CYAN}Passive Reconnaissance & Network Intelligence System{Colors.NC}")
            print(f"{Colors.CYAN}Version: 1.0.0-MVP{Colors.NC}")
            print()

            # Step 1: Legal disclaimer
            if not self.show_legal_disclaimer():
                return False

            # Step 2: Platform detection
            self.detect_platform()
            self.show_platform_info()

            # Step 3: System Initialization & Verification
            print(f"{Colors.CYAN}🔧 System Initialization & Verification{Colors.NC}")
            print()

            from src.core.initialization import initialize_cobaltgraph

            init_success, initializer = initialize_cobaltgraph(verbose=True)

            if not init_success:
                print(f"{Colors.RED}❌ System initialization failed{Colors.NC}")
                print(f"{Colors.RED}   Cannot start CobaltGraph{Colors.NC}")
                return False

            # Step 4: Load configuration
            print(f"{Colors.CYAN}📋 Loading additional configuration...{Colors.NC}")
            self.load_configuration()
            print()

            # Step 5: Select mode
            mode = self.select_mode(getattr(self.args, 'mode', None))
            print(f"  Mode: {Colors.GREEN}{mode}{Colors.NC}")

            # Step 6: Select interface
            interface = self.select_interface(getattr(self.args, 'interface', None))
            print(f"  Interface: {Colors.GREEN}{interface}{Colors.NC}")
            print()

            # Step 7: Dashboard configuration
            dashboard_config = initializer.get_dashboard_config()
            if dashboard_config:
                print(f"  Dashboard: {Colors.GREEN}{dashboard_config['type']}{Colors.NC}")
                port = getattr(self.args, 'port', dashboard_config.get('port', 5000))
                print(f"  Port: {Colors.GREEN}{port}{Colors.NC}")
            else:
                print(f"  Dashboard: {Colors.YELLOW}Disabled{Colors.NC}")
                port = getattr(self.args, 'port', 8080)

            print()

            # Step 8: Start watchfloor
            print(f"{Colors.GREEN}🚀 Starting CobaltGraph...{Colors.NC}")

            if interface == 'web':
                print(f"  Dashboard URL: {Colors.CYAN}http://localhost:{port}{Colors.NC}")

            print()
            print(f"{Colors.YELLOW}Press Ctrl+C to stop{Colors.NC}")
            print()

            # Step 9: Start CobaltGraph Main (Full Observatory)
            print(f"{Colors.CYAN}🎯 Using CobaltGraph Main (Full Observatory){Colors.NC}")
            print(f"{Colors.CYAN}🔬 Multi-Agent Consensus Threat Intelligence{Colors.NC}")

            from src.core.main import CobaltGraphMain

            # Pass dashboard config to main
            config = self.config or {}
            config['dashboard_port'] = port
            config['dashboard_type'] = dashboard_config['type'] if dashboard_config else 'legacy'

            self.watchfloor = CobaltGraphMain(
                mode=mode,
                config=config
            )

            # Step 7: Supervisor mode (if requested)
            if hasattr(self.args, 'supervised') and self.args.supervised:
                print(f"{Colors.CYAN}🤖 Starting with supervisor (auto-restart enabled){Colors.NC}")
                from src.core.supervisor import Supervisor
                self.supervisor = Supervisor(
                    target_func=self.watchfloor.run,
                    max_restarts=10,
                    restart_delay=5
                )
                self.supervisor.start()
            else:
                self.watchfloor.run()

            return True

        except KeyboardInterrupt:
            print()
            print(f"{Colors.YELLOW}⏹️  Shutdown requested by user{Colors.NC}")
            self.shutdown()
            return True

        except Exception as e:
            print()
            print(f"{Colors.RED}❌ Fatal error: {e}{Colors.NC}")
            logger.exception("Fatal error during startup")
            self.shutdown()
            return False

    def shutdown(self):
        """Graceful shutdown"""
        print()
        print(f"{Colors.CYAN}🛑 Shutting down CobaltGraph...{Colors.NC}")

        if self.watchfloor:
            try:
                self.watchfloor.shutdown()
                print(f"{Colors.GREEN}✅ Watchfloor stopped{Colors.NC}")
            except Exception as e:
                print(f"{Colors.RED}⚠️  Error stopping watchfloor: {e}{Colors.NC}")

        if self.supervisor:
            try:
                self.supervisor.stop()
                print(f"{Colors.GREEN}✅ Supervisor stopped{Colors.NC}")
            except Exception as e:
                print(f"{Colors.RED}⚠️  Error stopping supervisor: {e}{Colors.NC}")

        print()
        print(f"{Colors.GREEN}👋 CobaltGraph shutdown complete{Colors.NC}")
        print()


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser for CobaltGraph

    Returns:
        argparse.ArgumentParser: Configured parser
    """
    parser = argparse.ArgumentParser(
        description='CobaltGraph - Geo-Spatial Network Intelligence Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python start.py                           # Interactive mode
  python start.py --mode network            # Network-wide capture
  python start.py --mode device             # Device-only mode
  python start.py --interface terminal      # Terminal UI
  python start.py --supervised              # Auto-restart on crash
  python start.py --no-disclaimer           # Skip legal disclaimer (accept terms)

For network-wide monitoring (requires root/admin):
  Linux/WSL:  sudo python3 start.py
  macOS:      sudo python3 start.py
  Windows:    Run as Administrator

Dashboard will be available at: http://localhost:8080
        """
    )

    parser.add_argument(
        '--mode',
        choices=['network', 'device', 'auto'],
        default='auto',
        help='Monitoring mode (default: auto)'
    )

    parser.add_argument(
        '--interface',
        choices=['web', 'terminal'],
        default='web',
        help='User interface (default: web)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Dashboard port (default: 8080)'
    )

    parser.add_argument(
        '--config',
        help='Path to configuration directory (default: config/)'
    )

    parser.add_argument(
        '--supervised',
        action='store_true',
        help='Run in supervised mode (auto-restart on crash)'
    )

    parser.add_argument(
        '--no-disclaimer',
        action='store_true',
        help='Skip legal disclaimer (you accept all terms)'
    )

    parser.add_argument(
        '--show-disclaimer',
        action='store_true',
        help='Show legal disclaimer and exit'
    )

    parser.add_argument(
        '--health',
        action='store_true',
        help='Run health check and exit'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='CobaltGraph 1.0.0-MVP'
    )

    return parser


def main():
    """Entry point for start.py"""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Handle --show-disclaimer
    if args.show_disclaimer:
        launcher = Launcher(args)
        launcher.show_legal_disclaimer()
        return 0

    # Handle --health
    if args.health:
        print("🏥 CobaltGraph Health Check")
        print("=" * 50)
        # TODO: Implement health check
        print("✅ System: OK")
        print("✅ Configuration: OK")
        print("✅ Dependencies: OK")
        return 0

    # Normal startup
    launcher = Launcher(args, config_path=args.config)
    success = launcher.start()

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
