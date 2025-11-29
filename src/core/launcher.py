#!/usr/bin/env python3
"""
CobaltGraph Unified Launcher
Single entry point for the CobaltGraph Dashboard
"""

import argparse
import logging
import os
import platform
import signal
import sys
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    NC = '\033[0m'


class CobaltGraphMain:
    """
    Main launcher for CobaltGraph Dashboard
    """

    VERSION = "3.0.0"
    DISCLAIMER_FILE = Path.home() / ".cobaltgraph" / "disclaimer_accepted"

    def __init__(self):
        self.mode = None
        self.config_path = None
        self.running = True
        self.db_path = "data/cobaltgraph.db"

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n{Colors.YELLOW}Shutting down...{Colors.NC}")
        self.running = False
        sys.exit(0)

    def show_banner(self):
        """Display CobaltGraph banner"""
        print(f"\n{Colors.BLUE}{'='*70}{Colors.NC}")
        print(f"{Colors.BOLD}                    COBALTGRAPH DASHBOARD{Colors.NC}")
        print(f"{Colors.CYAN}         Unified Threat Monitoring & Intelligence Platform{Colors.NC}")
        print(f"{Colors.CYAN}                       Version {self.VERSION}{Colors.NC}")
        print(f"{Colors.BLUE}{'='*70}{Colors.NC}\n")

    def show_disclaimer(self) -> bool:
        """Display legal disclaimer"""
        disclaimer_text = f"""
{Colors.YELLOW}╔════════════════════════════════════════════════════════════════════╗
║                        LEGAL NOTICE                                ║
║                                                                    ║
║  CobaltGraph performs network monitoring and traffic analysis.    ║
║  UNAUTHORIZED MONITORING IS ILLEGAL.                              ║
║                                                                    ║
║  By using this tool, you acknowledge:                             ║
║  1. You have authorization to monitor the target network          ║
║  2. You will comply with all applicable laws                      ║
║  3. You assume full responsibility for your use of this tool      ║
╚════════════════════════════════════════════════════════════════════╝{Colors.NC}

{Colors.BOLD}Do you accept these terms?{Colors.NC} Type 'yes' to continue: """

        try:
            response = input(disclaimer_text).strip().lower()
            if response in ['yes', 'y']:
                self.DISCLAIMER_FILE.parent.mkdir(parents=True, exist_ok=True)
                self.DISCLAIMER_FILE.write_text(
                    f"Accepted on {platform.node()} at {__import__('datetime').datetime.now()}\n"
                )
                print(f"\n{Colors.GREEN}✓ Terms accepted.{Colors.NC}\n")
                return True
            else:
                print(f"\n{Colors.RED}✗ Terms not accepted. Exiting.{Colors.NC}\n")
                return False
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.RED}✗ Cancelled.{Colors.NC}\n")
            return False

    def check_disclaimer(self, skip: bool = False) -> bool:
        """Check if disclaimer has been accepted"""
        if skip or self.DISCLAIMER_FILE.exists():
            return True
        return self.show_disclaimer()

    def detect_capabilities(self) -> dict:
        """Detect platform capabilities"""
        caps = {
            'os': platform.system(),
            'is_wsl': False,
            'is_root': False,
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}",
        }

        if caps['os'] == 'Linux':
            try:
                with open('/proc/version', 'r') as f:
                    caps['is_wsl'] = 'microsoft' in f.read().lower()
            except:
                pass

        if hasattr(os, 'geteuid'):
            caps['is_root'] = os.geteuid() == 0

        return caps

    def select_mode_interactive(self, capabilities: dict) -> str:
        """Interactive monitoring mode selection"""
        print(f"{Colors.CYAN}Platform: {capabilities['os']} | Python {capabilities['python_version']}{Colors.NC}")
        if capabilities['is_wsl']:
            print(f"{Colors.CYAN}Environment: WSL{Colors.NC}")
        print()

        print(f"{Colors.BOLD}Select Monitoring Mode:{Colors.NC}\n")
        print(f"  {Colors.GREEN}1){Colors.NC} Device-Only Mode {Colors.DIM}(recommended){Colors.NC}")
        print(f"     Monitors this device only, no root required\n")

        if capabilities['is_root']:
            print(f"  {Colors.GREEN}2){Colors.NC} Network-Wide Mode")
            print(f"     Monitors entire network (root required)\n")
        else:
            print(f"  {Colors.YELLOW}2){Colors.NC} Network-Wide Mode {Colors.RED}[REQUIRES ROOT]{Colors.NC}\n")

        try:
            choice = input(f"{Colors.BOLD}Enter choice (1-2):{Colors.NC} ").strip()
            if choice == '2' and capabilities['is_root']:
                return 'network'
            return 'device'
        except (EOFError, KeyboardInterrupt):
            return 'device'

    def run_health_check(self) -> bool:
        """Run system health check"""
        from src.core.system_check import run_health_check
        print(f"\n{Colors.CYAN}Running health check...{Colors.NC}\n")
        return run_health_check(mode=self.mode or 'device')

    def find_database(self) -> str:
        """Find the database file"""
        for path in ["data/cobaltgraph.db", "database/cobaltgraph.db"]:
            if Path(path).exists():
                return path
        return "data/cobaltgraph.db"

    def _select_dashboard(self):
        """Select appropriate dashboard based on mode"""
        try:
            from src.ui.dashboard_v2 import CobaltGraphDashboardV2
            return CobaltGraphDashboardV2
        except ImportError as e:
            raise ImportError(f"CobaltGraphDashboardV2 not found: {e}")

    def launch_dashboard(self) -> int:
        """Launch the CobaltGraph Dashboard (simplified V2)"""
        try:
            from src.utils.logging_config import setup_logging

            # Setup logging
            setup_logging(
                log_level=logging.INFO,
                log_file='cobaltgraph.log',
                log_dir='logs',
                use_color=False,
                detailed_file_logs=True
            )
            logger = logging.getLogger(__name__)
            logger.info(f"CobaltGraph {self.VERSION} starting...")
            logger.info(f"Mode: {self.mode} | Database: {self.db_path}")

            print(f"\n{Colors.GREEN}Launching CobaltGraph Dashboard V2...{Colors.NC}")
            print(f"{Colors.CYAN}Database: {self.db_path}{Colors.NC}")
            print(f"{Colors.DIM}Press [Q] to quit, [R] to refresh, [?] for help{Colors.NC}\n")

            # Launch dashboard directly (no pipeline needed)
            dashboard_class = self._select_dashboard()
            logger.info(f"Launching {dashboard_class.__name__}...")
            print(f"{Colors.GREEN}✓ Dashboard ready{Colors.NC}\n")

            dashboard = dashboard_class()
            dashboard.run()

            return 0

        except ImportError as e:
            print(f"\n{Colors.RED}Dashboard not available: {e}{Colors.NC}")
            return 1
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Stopped by user{Colors.NC}")
            return 130
        except Exception as e:
            print(f"\n{Colors.RED}Error: {e}{Colors.NC}")
            import traceback
            traceback.print_exc()
            return 1

    def parse_arguments(self):
        """Parse command-line arguments"""
        parser = argparse.ArgumentParser(
            description="CobaltGraph Dashboard - Unified Threat Monitoring",
            epilog="""
Examples:
  cobaltgraph                           # Interactive mode
  cobaltgraph --mode device             # Device-only monitoring
  sudo cobaltgraph --mode network       # Network-wide monitoring
  cobaltgraph --health                  # Run health check
            """,
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.add_argument(
            '--mode', choices=['device', 'network', 'auto'], default='auto',
            help='Monitoring mode (default: auto)'
        )
        parser.add_argument(
            '--config', type=str, help='Configuration directory path'
        )
        parser.add_argument(
            '--health', action='store_true', help='Run health check and exit'
        )
        parser.add_argument(
            '--no-disclaimer', action='store_true', help='Skip disclaimer'
        )
        parser.add_argument(
            '--version', action='version', version=f'CobaltGraph {self.VERSION}'
        )

        return parser.parse_args()

    def main(self) -> int:
        """Main entry point"""
        args = self.parse_arguments()

        if args.health:
            self.mode = args.mode if args.mode != 'auto' else 'device'
            return 0 if self.run_health_check() else 1

        # Check dependencies
        from src.core.system_check import check_dependencies_only
        if not check_dependencies_only():
            return 1

        self.show_banner()

        if not self.check_disclaimer(skip=args.no_disclaimer):
            return 1

        capabilities = self.detect_capabilities()

        # Determine monitoring mode
        if args.mode == 'auto':
            self.mode = self.select_mode_interactive(capabilities)
        elif args.mode == 'network' and not capabilities['is_root']:
            print(f"{Colors.RED}Network mode requires root{Colors.NC}")
            return 1
        else:
            self.mode = args.mode

        self.config_path = args.config
        self.db_path = self.find_database()

        # Health check
        print(f"\n{Colors.CYAN}Pre-flight checks...{Colors.NC}")
        if not self.run_health_check():
            print(f"\n{Colors.RED}Health check failed{Colors.NC}")
            return 1

        print(f"\n{Colors.GREEN}✓ All systems ready{Colors.NC}")
        print(f"{Colors.DIM}Database: {self.db_path}{Colors.NC}\n")

        # Launch dashboard
        return self.launch_dashboard()


def main() -> int:
    """Entry point"""
    try:
        return CobaltGraphMain().main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Cancelled{Colors.NC}")
        return 130
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.NC}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
