#!/usr/bin/env python3
"""
Run All Unit Tests and Generate Empirical Evidence Report
"""

import sys
import unittest
import time
import json
from pathlib import Path
from io import StringIO

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def run_all_unit_tests():
    """
    Discover and run all unit tests, generate empirical evidence
    """
    print("=" * 80)
    print("COBALTGRAPH UNIT TEST SUITE - EMPIRICAL EVIDENCE GENERATION")
    print("=" * 80)
    print()

    # Discover all tests
    loader = unittest.TestLoader()
    suite = loader.discover('tests/unit', pattern='test_*.py')

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)

    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()

    # Generate empirical evidence report
    print("\n" + "=" * 80)
    print("EMPIRICAL EVIDENCE REPORT")
    print("=" * 80)

    total_tests = result.testsRun
    passed = total_tests - len(result.failures) - len(result.errors)
    failed = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped) if hasattr(result, 'skipped') else 0

    evidence = {
        'timestamp': time.time(),
        'total_tests': total_tests,
        'passed': passed,
        'failed': failed,
        'errors': errors,
        'skipped': skipped,
        'success_rate': (passed / total_tests * 100) if total_tests > 0 else 0,
        'execution_time_seconds': end_time - start_time,
        'test_suites': {
            'consensus': 0,
            'export': 0,
            'database': 0,
            'dashboard': 0,
        }
    }

    # Count tests by category
    for test in result.testsRun.__str__():
        if 'consensus' in str(test):
            evidence['test_suites']['consensus'] += 1
        elif 'export' in str(test):
            evidence['test_suites']['export'] += 1

    print(f"\n📊 Test Execution Summary:")
    print(f"   Total Tests: {total_tests}")
    print(f"   ✅ Passed: {passed}")
    print(f"   ❌ Failed: {failed}")
    print(f"   💥 Errors: {errors}")
    print(f"   ⏭️  Skipped: {skipped}")
    print(f"   📈 Success Rate: {evidence['success_rate']:.1f}%")
    print(f"   ⏱️  Execution Time: {evidence['execution_time_seconds']:.2f}s")

    if result.failures:
        print(f"\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"   {test}: {traceback[:200]}...")

    if result.errors:
        print(f"\n💥 ERRORS:")
        for test, traceback in result.errors:
            print(f"   {test}: {traceback[:200]}...")

    # Save evidence to file
    evidence_file = PROJECT_ROOT / 'TEST_EVIDENCE.json'
    with open(evidence_file, 'w') as f:
        json.dump(evidence, f, indent=2)

    print(f"\n📁 Empirical evidence saved to: {evidence_file}")

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_unit_tests()
    sys.exit(0 if success else 1)
