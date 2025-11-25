#!/usr/bin/env python3
"""
CobaltGraph Launcher - Cross-Platform Entry Point
Works on: Windows, WSL, Linux, macOS

Usage:
    python cobaltgraph.py              # Start with prompts
    python cobaltgraph.py --help       # Show help
"""

import os
import sys
import subprocess
import argparse

# Get the directory of this script (bin/), then go to project root
BIN_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BIN_DIR)  # Go up one level from bin/
SCRIPT_DIR = PROJECT_ROOT
sys.path.insert(0, os.path.join(SCRIPT_DIR, 'src'))

def main():
    parser = argparse.ArgumentParser(
        description='CobaltGraph Network Security Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cobaltgraph.py              # Interactive startup
  python cobaltgraph.py --health     # Health check

For network-wide monitoring (requires admin):
  Windows (Admin): python cobaltgraph.py
  WSL/Linux:       sudo python3 cobaltgraph.py
        """
    )

    parser.add_argument(
        '--health',
        action='store_true',
        help='Run health check instead of starting CobaltGraph'
    )

    parser.add_argument(
        '--mode',
        choices=['device', 'network', 'auto'],
        default='auto',
        help='Monitoring mode (default: auto)'
    )

    parser.add_argument(
        '--interface',
        help='Network interface to monitor (default: auto-detect)'
    )

    args = parser.parse_args()

    # Change to script directory
    os.chdir(SCRIPT_DIR)

    if args.health:
        # Run health check
        health_script = os.path.join(SCRIPT_DIR, 'bin', 'cobaltgraph-health')
        if os.path.exists(health_script):
            subprocess.run(['bash', health_script])
        else:
            print("Error: Health check script not found")
            sys.exit(1)
    else:
        # Run main startup
        startup_script = os.path.join(SCRIPT_DIR, 'bin', 'cobaltgraph')
        if os.path.exists(startup_script):
            subprocess.run(['bash', startup_script])
        else:
            print("Error: Startup script not found")
            sys.exit(1)

if __name__ == '__main__':
    main()
