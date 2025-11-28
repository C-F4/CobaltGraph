#!/usr/bin/env python3
"""
CobaltGraph - Geo-Spatial Network Intelligence Platform
Cross-Platform Launcher

This is the unified entry point for CobaltGraph that works on:
- Windows (PowerShell, CMD)
- WSL (Windows Subsystem for Linux)
- Linux (Ubuntu, Debian, Fedora, etc.)
- macOS

Usage:
    python start.py                          # Interactive mode
    python start.py --mode network           # Network-wide capture
    python start.py --mode device            # Device-only mode
    python start.py --interface terminal     # Terminal UI
    python start.py --supervised             # Auto-restart on crash
    python start.py --help                   # Show all options

For network-wide monitoring (requires root/admin):
    Linux/WSL:  sudo python3 start.py
    macOS:      sudo python3 start.py
    Windows:    Run PowerShell as Administrator, then: python start.py
"""

import sys
import os
from pathlib import Path

# Add src/ to Python path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

# Ensure we're in the project root directory
os.chdir(PROJECT_ROOT)

def main():
    """Main entry point"""
    try:
        # Show tactical boot sequence
        from src.ui.boot_sequence import boot_sequence

        if not boot_sequence():
            return 1

        # Import unified launcher from src
        from src.core.launcher import main as launcher_main

        # Run launcher
        return launcher_main()

    except KeyboardInterrupt:
        print("\n⏹️  Cancelled by user")
        return 130  # Standard exit code for Ctrl+C

    except ImportError as e:
        print(f"❌ Error: Failed to import CobaltGraph modules")
        print(f"   {e}")
        print()
        print("Make sure you're in the CobaltGraph directory and all dependencies are installed.")
        print("Try: pip install -r requirements.txt")
        return 1

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
