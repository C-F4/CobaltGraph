#!/usr/bin/env python3
"""
Quick Demo Launcher for Enhanced Terminal UI

Run this to test the Enhanced Terminal UI without going through the full launcher.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.ui.enhanced_terminal import EnhancedTerminalUI


def main():
    """Launch Enhanced Terminal UI demo"""
    print("🔬 CobaltGraph Enhanced Terminal UI - Quick Demo")
    print("=" * 60)
    print()
    print("This will launch the Enhanced Terminal UI directly.")
    print("Make sure you have installed dependencies:")
    print("  pip3 install rich textual")
    print()
    print("Press Ctrl+C or 'Q' to quit.")
    print("=" * 60)
    print()

    try:
        ui = EnhancedTerminalUI(database_path="database/cobaltgraph.db")
        ui.run()
    except KeyboardInterrupt:
        print("\n\n✅ Enhanced Terminal UI demo stopped.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure you have installed dependencies:")
        print("  pip3 install rich textual")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
