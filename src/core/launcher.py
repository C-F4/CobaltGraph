#!/usr/bin/env python3
"""
CobaltGraph Unified Launcher
Comprehensive entry point supporting multiple modes and interfaces
"""

import argparse
import os
import platform
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional

# ANSI color codes for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


class CobaltGraphMain:
    """
    Main launcher class for CobaltGraph
    Handles initialization, mode selection, and orchestration
    """

    VERSION = "1.0.0-MVP"
    DISCLAIMER_FILE = Path.home() / ".cobaltgraph" / "disclaimer_accepted"

    def __init__(self):
        self.mode = None
        self.interface = None
        self.config_path = None
        self.running = True
        self.pure_terminal_instance = None

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n{Colors.YELLOW}⏹️  Shutting down gracefully...{Colors.NC}")
        self.running = False
        if self.pure_terminal_instance:
            self.pure_terminal_instance.running = False
        sys.exit(0)

    def show_banner(self):
        """Display CobaltGraph banner"""
        print(f"\n{Colors.BLUE}{'='*76}{Colors.NC}")
        print(f"{Colors.BLUE}{'='*76}{Colors.NC}")
        print(f"{Colors.BOLD}                      COBALTGRAPH GEO-SPATIAL WATCHFLOOR{Colors.NC}")
        print(f"{Colors.CYAN}                   Passive Reconnaissance & Network Intelligence{Colors.NC}")
        print(f"{Colors.CYAN}                              Version {self.VERSION}{Colors.NC}")
        print(f"{Colors.BLUE}{'='*76}{Colors.NC}")
        print(f"{Colors.BLUE}{'='*76}{Colors.NC}\n")

    def show_disclaimer(self) -> bool:
        """
        Display legal disclaimer and get user acceptance
        Returns True if accepted
        """
        disclaimer_text = f"""
{Colors.YELLOW}╔══════════════════════════════════════════════════════════════════════════╗
║                          ⚠️  LEGAL NOTICE ⚠️                              ║
║                                                                          ║
║  CobaltGraph performs network monitoring and traffic analysis.          ║
║                                                                          ║
║  UNAUTHORIZED MONITORING IS ILLEGAL. You must have explicit permission  ║
║  to monitor any network or system you do not own or operate.            ║
║                                                                          ║
║  Applicable Laws:                                                        ║
║  • Computer Fraud and Abuse Act (CFAA) - United States                  ║
║  • Computer Misuse Act - United Kingdom                                 ║
║  • Equivalent laws in your jurisdiction                                 ║
║                                                                          ║
║  By using this tool, you acknowledge:                                   ║
║  1. You have authorization to monitor the target network                ║
║  2. You will comply with all applicable laws and regulations            ║
║  3. You assume full responsibility for your use of this tool            ║
║  4. The authors are not liable for any misuse or damages                ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.NC}

{Colors.BOLD}Do you understand and accept these terms?{Colors.NC}

Type 'yes' to accept and continue, or anything else to exit: """

        try:
            response = input(disclaimer_text).strip().lower()
            if response in ['yes', 'y']:
                # Save acceptance
                self.DISCLAIMER_FILE.parent.mkdir(parents=True, exist_ok=True)
                self.DISCLAIMER_FILE.write_text(
                    f"Accepted on {platform.node()} at {__import__('datetime').datetime.now()}\n"
                )
                print(f"\n{Colors.GREEN}✓ Terms accepted. Proceeding...{Colors.NC}\n")
                return True
            else:
                print(f"\n{Colors.RED}✗ Terms not accepted. Exiting.{Colors.NC}\n")
                return False
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.RED}✗ Cancelled. Exiting.{Colors.NC}\n")
            return False

    def check_disclaimer(self, skip: bool = False) -> bool:
        """
        Check if disclaimer has been accepted
        Returns True if can proceed
        """
        if skip:
            return True

        if self.DISCLAIMER_FILE.exists():
            return True

        return self.show_disclaimer()

    def detect_platform_capabilities(self) -> dict:
        """
        Detect platform and available capabilities
        Returns dict with platform info
        """
        caps = {
            'os': platform.system(),
            'is_wsl': False,
            'is_root': False,
            'can_network_mode': False,
            'supports_terminal_ui': True,
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        }

        # Check for WSL
        if caps['os'] == 'Linux':
            try:
                with open('/proc/version', 'r') as f:
                    caps['is_wsl'] = 'microsoft' in f.read().lower()
            except:
                pass

        # Check for root/admin privileges
        if hasattr(os, 'geteuid'):
            caps['is_root'] = os.geteuid() == 0
        else:
            # Windows - check if admin
            try:
                import ctypes
                caps['is_root'] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                caps['is_root'] = False

        # Network mode requires root
        caps['can_network_mode'] = caps['is_root']

        return caps

    def select_mode_interactive(self, capabilities: dict) -> str:
        """
        Interactive mode selection
        Returns selected mode (device/network)
        """
        print(f"\n{Colors.CYAN}🔍 Platform Detection:{Colors.NC}")
        print(f"   OS: {capabilities['os']}")
        print(f"   Python: {capabilities['python_version']}")
        print(f"   Root/Admin: {'Yes' if capabilities['is_root'] else 'No'}")
        if capabilities['is_wsl']:
            print(f"   Environment: WSL (Windows Subsystem for Linux)")
        print()

        print(f"{Colors.BOLD}Select Monitoring Mode:{Colors.NC}\n")
        print(f"  {Colors.GREEN}1){Colors.NC} Device-Only Mode (recommended)")
        print(f"     • Monitors connections from this device only")
        print(f"     • No special privileges required")
        print(f"     • Lower resource usage\n")

        if capabilities['can_network_mode']:
            print(f"  {Colors.GREEN}2){Colors.NC} Network-Wide Mode")
            print(f"     • Monitors entire network traffic")
            print(f"     • Requires root/sudo privileges")
            print(f"     • Higher resource usage\n")
        else:
            print(f"  {Colors.YELLOW}2){Colors.NC} Network-Wide Mode {Colors.RED}[UNAVAILABLE]{Colors.NC}")
            print(f"     • Requires root privileges")
            print(f"     • Run with: sudo python3 start.py\n")

        try:
            choice = input(f"{Colors.BOLD}Enter choice (1-2):{Colors.NC} ").strip()

            if choice == '1':
                return 'device'
            elif choice == '2' and capabilities['can_network_mode']:
                return 'network'
            elif choice == '2':
                print(f"{Colors.RED}✗ Network mode requires root. Falling back to device mode.{Colors.NC}")
                return 'device'
            else:
                print(f"{Colors.YELLOW}Invalid choice. Using device mode.{Colors.NC}")
                return 'device'

        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}Cancelled. Using device mode.{Colors.NC}")
            return 'device'

    def select_interface_interactive(self) -> str:
        """
        Interface selection (Terminal-only in current version)
        Returns 'terminal'
        """
        print(f"\n{Colors.CYAN}Interface: Pure Terminal Mode{Colors.NC}")
        print(f"  • No web server, no HTTP ports")
        print(f"  • Maximum security, minimal attack surface")
        print(f"  • Real-time terminal display\n")
        return 'terminal'

    def run_health_check(self) -> bool:
        """
        Run system health check
        Returns True if system is healthy
        """
        from src.core.system_check import run_health_check

        print(f"\n{Colors.CYAN}Running system health check...{Colors.NC}\n")
        return run_health_check(mode=self.mode or 'device')

    def launch_terminal_interface(self):
        """Launch pure terminal interface"""
        from src.core.main_terminal_pure import main as terminal_main

        print(f"\n{Colors.GREEN}🚀 Launching CobaltGraph in Pure Terminal Mode...{Colors.NC}")
        print(f"{Colors.CYAN}Mode: {self.mode}{Colors.NC}")
        print(f"{Colors.CYAN}Config: {self.config_path or 'default'}{Colors.NC}\n")

        # Build arguments for terminal launcher
        sys.argv = ['cobaltgraph']
        if self.config_path:
            sys.argv.extend(['--config', str(self.config_path)])
        if self.mode:
            sys.argv.extend(['--mode', self.mode])

        # Launch terminal interface
        try:
            return terminal_main()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⏹️  Stopped by user{Colors.NC}")
            return 130


    def parse_arguments(self):
        """Parse command-line arguments"""
        parser = argparse.ArgumentParser(
            description="CobaltGraph - Geo-Spatial Network Intelligence Platform",
            epilog="""
Examples:
  python start.py                           # Interactive mode
  python start.py --mode device             # Device-only monitoring
  sudo python start.py --mode network       # Network-wide monitoring
  python start.py --interface terminal      # Force terminal interface
  python start.py --health                  # Run health check
  python start.py --show-disclaimer         # Display legal terms

For network-wide monitoring, root/sudo is required.
            """,
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.add_argument(
            '--mode',
            choices=['device', 'network', 'auto'],
            default='auto',
            help='Monitoring mode (default: auto-detect based on privileges)'
        )

        parser.add_argument(
            '--interface',
            choices=['terminal'],
            default='terminal',
            help='User interface type (terminal only in current version)'
        )

        parser.add_argument(
            '--config',
            type=str,
            help='Path to configuration directory'
        )

        parser.add_argument(
            '--health',
            action='store_true',
            help='Run system health check and exit'
        )

        parser.add_argument(
            '--show-disclaimer',
            action='store_true',
            help='Display legal disclaimer and exit'
        )

        parser.add_argument(
            '--no-disclaimer',
            action='store_true',
            help='Skip disclaimer (use only for automated/CI environments)'
        )

        parser.add_argument(
            '--version',
            action='version',
            version=f'CobaltGraph {self.VERSION}'
        )

        return parser.parse_args()

    def main(self) -> int:
        """
        Main entry point
        Returns exit code
        """
        # Parse arguments
        args = self.parse_arguments()

        # Handle special modes
        if args.show_disclaimer:
            self.show_disclaimer()
            return 0

        if args.health:
            self.mode = args.mode if args.mode != 'auto' else 'device'
            healthy = self.run_health_check()
            return 0 if healthy else 1

        # Show banner
        self.show_banner()

        # Check disclaimer acceptance
        if not self.check_disclaimer(skip=args.no_disclaimer):
            return 1

        # Detect platform capabilities
        capabilities = self.detect_platform_capabilities()

        # Determine mode
        if args.mode == 'auto':
            # Interactive mode selection
            self.mode = self.select_mode_interactive(capabilities)
        elif args.mode == 'network' and not capabilities['can_network_mode']:
            print(f"{Colors.RED}✗ Network mode requires root privileges{Colors.NC}")
            print(f"{Colors.CYAN}Run with: sudo python3 start.py --mode network{Colors.NC}\n")
            return 1
        else:
            self.mode = args.mode

        # Determine interface
        if args.interface:
            self.interface = args.interface
        else:
            # Interactive interface selection
            self.interface = self.select_interface_interactive()

        # Set config path
        self.config_path = args.config

        # Run health check before launch
        print(f"\n{Colors.CYAN}Running pre-flight checks...{Colors.NC}")
        if not self.run_health_check():
            print(f"\n{Colors.RED}✗ System health check failed{Colors.NC}")
            print(f"{Colors.YELLOW}Fix the issues above and try again.{Colors.NC}\n")
            return 1

        # Launch terminal interface
        print(f"\n{Colors.GREEN}✓ All systems ready{Colors.NC}\n")
        return self.launch_terminal_interface()


def main() -> int:
    """
    Entry point for launcher
    Returns exit code
    """
    try:
        launcher = CobaltGraphMain()
        return launcher.main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⏹️  Cancelled by user{Colors.NC}")
        return 130
    except Exception as e:
        print(f"\n{Colors.RED}✗ Fatal error: {e}{Colors.NC}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
