#!/usr/bin/env python3
"""
CobaltGraph Dashboard Launcher
Start the real-time network monitoring dashboard
"""

import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.services.dashboard import run_app

if __name__ == '__main__':
    print("=" * 60)
    print("CobaltGraph Dashboard - Real-time Network Monitoring")
    print("=" * 60)
    print()
    print("Starting dashboard server...")
    print()
    print("📍 Dashboard URL: http://localhost:5000")
    print("📍 API URL: http://localhost:5000/api/devices")
    print("📍 Health Check: http://localhost:5000/health")
    print()
    print("Press Ctrl+C to stop")
    print()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    try:
        # Run dashboard (with debug mode for development)
        run_app(host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n\n⏹️  Shutting down dashboard...")
        sys.exit(0)
    except FileNotFoundError as e:
        print(f"\n❌ Configuration error: {e}")
        print("   Please ensure database is configured in config/database.conf")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
