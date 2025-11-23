#!/usr/bin/env python3
"""
CobaltGraph Initialization Test Script
Tests the complete initialization process without launching the full system
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

def main():
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║       CobaltGraph Initialization Test - Comprehensive Verification    ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    try:
        from src.core.initialization import initialize_cobaltgraph

        # Run full initialization
        success, initializer = initialize_cobaltgraph(verbose=True)

        if success:
            print()
            print("╔══════════════════════════════════════════════════════════════════╗")
            print("║                      INITIALIZATION SUCCESSFUL                    ║")
            print("╚══════════════════════════════════════════════════════════════════╝")
            print()

            # Show dashboard config
            dashboard_config = initializer.get_dashboard_config()
            if dashboard_config:
                print("✅ Dashboard Configuration:")
                print(f"   Type: {dashboard_config['type']}")
                print(f"   Port: {dashboard_config['port']}")
                print(f"   Module: {dashboard_config['module']}")
            else:
                print("⚠️  No dashboard available")

            print()
            print("System is ready to launch with:")
            print("  python3 start.py")
            print()

            return 0

        else:
            print()
            print("╔══════════════════════════════════════════════════════════════════╗")
            print("║                       INITIALIZATION FAILED                       ║")
            print("╚══════════════════════════════════════════════════════════════════╝")
            print()
            print("Please fix the errors above before launching CobaltGraph")
            print()

            return 1

    except KeyboardInterrupt:
        print("\n\n⏹️  Test cancelled by user")
        return 130

    except Exception as e:
        print(f"\n❌ Fatal error during initialization test: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
