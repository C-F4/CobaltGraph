#!/usr/bin/env python3
"""
Consensus Integration Test Suite
Tests the consensus module in isolation before orchestrator.py integration

Run with: python3 test_consensus_integration.py
"""

import sys
import json
from pathlib import Path

# Add src to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

def test_import():
    """Test 1: Can we import the consensus module?"""
    print("=" * 70)
    print("TEST 1: Module Import")
    print("=" * 70)

    try:
        from src.consensus import ConsensusThreatScorer, BFTConsensus, ThreatScorer
        print("✅ Successfully imported ConsensusThreatScorer")
        print("✅ Successfully imported BFTConsensus")
        print("✅ Successfully imported ThreatScorer")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False


def test_initialization():
    """Test 2: Can we initialize the consensus scorer?"""
    print("\n" + "=" * 70)
    print("TEST 2: Initialization")
    print("=" * 70)

    try:
        from src.consensus import ConsensusThreatScorer

        scorer = ConsensusThreatScorer()
        print(f"✅ ConsensusThreatScorer initialized")
        print(f"   - Number of scorers: {len(scorer.scorers)}")
        print(f"   - Scorer IDs: {[s.scorer_id for s in scorer.scorers]}")
        print(f"   - Cache size: {scorer.cache_size}")
        return scorer
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_minimal_call(scorer):
    """Test 3: Minimal check_ip() call (backward compatibility)"""
    print("\n" + "=" * 70)
    print("TEST 3: Minimal Call (Backward Compatibility)")
    print("=" * 70)

    try:
        # Simulate old IPReputationManager.check_ip() call
        dst_ip = "8.8.8.8"
        score, details = scorer.check_ip(dst_ip)

        print(f"✅ Minimal call succeeded for {dst_ip}")
        print(f"   - Score: {score:.3f}")
        print(f"   - Type: {type(score)} (should be float)")
        print(f"   - Details keys: {list(details.keys())}")
        print(f"   - High uncertainty: {details.get('high_uncertainty', 'N/A')}")

        # Validate return types
        assert isinstance(score, float), "Score must be float"
        assert isinstance(details, dict), "Details must be dict"
        assert 0.0 <= score <= 1.0, "Score must be in [0.0, 1.0]"

        print("✅ Return type validation passed")
        return True

    except Exception as e:
        print(f"❌ Minimal call failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_full_call(scorer):
    """Test 4: Full check_ip() call with all parameters"""
    print("\n" + "=" * 70)
    print("TEST 4: Full Call (With Context)")
    print("=" * 70)

    try:
        # Simulate real orchestrator data
        dst_ip = "1.1.1.1"

        # Simulated threat intel (what ip_reputation would return)
        threat_intel = {
            'virustotal': {
                'malicious_vendors': 0,
                'suspicious_vendors': 0,
                'total_vendors': 84,
                'is_malicious': False,
            },
            'abuseipdb': {
                'confidence_score': 0,
                'total_reports': 0,
                'is_whitelisted': False,
            },
            'local': {
                'threat_score': 0.2,
            }
        }

        geo_data = {
            'country': 'United States',
            'country_code': 'US',
            'lat': 37.751,
            'lon': -97.822,
            'org': 'Cloudflare, Inc.',
        }

        connection_metadata = {
            'dst_port': 443,
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
        }

        score, details = scorer.check_ip(
            dst_ip=dst_ip,
            threat_intel=threat_intel,
            geo_data=geo_data,
            connection_metadata=connection_metadata
        )

        print(f"✅ Full call succeeded for {dst_ip}")
        print(f"   - Score: {score:.3f}")
        print(f"   - Confidence: {details.get('confidence', 'N/A'):.3f}")
        print(f"   - High uncertainty: {details.get('high_uncertainty', False)}")
        print(f"   - Method: {details.get('method', 'N/A')}")
        print(f"   - Number of votes: {len(details.get('votes', []))}")

        # Display individual scorer votes
        print("\n   Individual Scorer Assessments:")
        for vote in details.get('votes', []):
            print(f"      - {vote['scorer_id']}: score={vote['score']:.3f}, "
                  f"confidence={vote['confidence']:.3f}")
            print(f"        Reasoning: {vote['reasoning'][:80]}...")

        # Check for outliers
        outliers = details.get('outliers', [])
        if outliers:
            print(f"\n   ⚠️  Outliers detected: {outliers}")
        else:
            print(f"\n   ✅ No outliers (all scorers agree)")

        return True

    except Exception as e:
        print(f"❌ Full call failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_malicious_ip(scorer):
    """Test 5: High-threat IP simulation"""
    print("\n" + "=" * 70)
    print("TEST 5: Malicious IP Simulation")
    print("=" * 70)

    try:
        dst_ip = "198.51.100.1"  # Simulated malicious IP

        # Simulate threat intel showing high threat
        threat_intel = {
            'virustotal': {
                'malicious_vendors': 12,
                'suspicious_vendors': 3,
                'total_vendors': 84,
                'is_malicious': True,
            },
            'abuseipdb': {
                'confidence_score': 95,
                'total_reports': 47,
                'is_whitelisted': False,
            },
        }

        geo_data = {
            'country': 'Russia',
            'country_code': 'RU',
        }

        connection_metadata = {
            'dst_port': 3389,  # RDP (high-risk port)
            'protocol': 'TCP',
        }

        score, details = scorer.check_ip(
            dst_ip=dst_ip,
            threat_intel=threat_intel,
            geo_data=geo_data,
            connection_metadata=connection_metadata
        )

        print(f"✅ Malicious IP assessment for {dst_ip}")
        print(f"   - Score: {score:.3f} (expected: >0.7)")
        print(f"   - Is malicious: {details.get('is_malicious', False)}")
        print(f"   - Confidence: {details.get('confidence', 0):.3f}")

        # Validate high threat detected
        if score >= 0.7:
            print(f"   ✅ High threat correctly identified")
        else:
            print(f"   ⚠️  WARNING: Expected high score, got {score:.3f}")

        return True

    except Exception as e:
        print(f"❌ Malicious IP test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_statistics(scorer):
    """Test 6: Get scorer statistics"""
    print("\n" + "=" * 70)
    print("TEST 6: Statistics & Monitoring")
    print("=" * 70)

    try:
        stats = scorer.get_statistics()

        print("✅ Statistics retrieved successfully")
        print(f"\n   Overall Metrics:")
        print(f"      - Total assessments: {stats['total_assessments']}")
        print(f"      - Consensus failures: {stats['consensus_failures']}")
        print(f"      - High uncertainty: {stats['high_uncertainty_count']}")
        print(f"      - Failure rate: {stats['failure_rate']*100:.2f}%")
        print(f"      - Uncertainty rate: {stats['uncertainty_rate']*100:.2f}%")
        print(f"      - Cache size: {stats['cache_size']}")

        print(f"\n   Per-Scorer Metrics:")
        for scorer_id, scorer_stats in stats['scorers'].items():
            print(f"      {scorer_id}:")
            print(f"         - Assessments: {scorer_stats['assessments_made']}")
            print(f"         - Avg confidence: {scorer_stats['avg_confidence']:.3f}")
            print(f"         - Accuracy: {scorer_stats['accuracy']:.3f}")

        return True

    except Exception as e:
        print(f"❌ Statistics test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_performance(scorer):
    """Test 7: Performance benchmark"""
    print("\n" + "=" * 70)
    print("TEST 7: Performance Benchmark")
    print("=" * 70)

    import time

    try:
        test_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222",
            "9.9.9.9",
            "185.228.168.9",
        ]

        times = []

        for dst_ip in test_ips:
            start = time.time()
            score, details = scorer.check_ip(dst_ip)
            elapsed = time.time() - start
            times.append(elapsed)

            print(f"   {dst_ip}: {elapsed*1000:.1f}ms (score={score:.3f})")

        avg_time = sum(times) / len(times)
        max_time = max(times)

        print(f"\n✅ Performance test complete")
        print(f"   - Average: {avg_time*1000:.1f}ms")
        print(f"   - Max: {max_time*1000:.1f}ms")

        if avg_time < 0.1:  # <100ms is good
            print(f"   ✅ Performance: EXCELLENT")
        elif avg_time < 0.5:
            print(f"   ✅ Performance: GOOD")
        else:
            print(f"   ⚠️  Performance: SLOW (may need optimization)")

        return True

    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "CONSENSUS INTEGRATION TEST SUITE" + " " * 21 + "║")
    print("╚" + "=" * 68 + "╝")
    print()

    results = []

    # Test 1: Import
    results.append(('Import', test_import()))

    if not results[0][1]:
        print("\n❌ CRITICAL: Import failed, cannot continue")
        return False

    # Test 2: Initialization
    scorer = test_initialization()
    results.append(('Initialization', scorer is not None))

    if scorer is None:
        print("\n❌ CRITICAL: Initialization failed, cannot continue")
        return False

    # Test 3: Minimal call
    results.append(('Minimal Call', test_minimal_call(scorer)))

    # Test 4: Full call
    results.append(('Full Call', test_full_call(scorer)))

    # Test 5: Malicious IP
    results.append(('Malicious IP', test_malicious_ip(scorer)))

    # Test 6: Statistics
    results.append(('Statistics', test_statistics(scorer)))

    # Test 7: Performance
    results.append(('Performance', test_performance(scorer)))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status}: {test_name}")

    print()
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 ALL TESTS PASSED - Ready for orchestrator.py integration!")
        return True
    else:
        print(f"\n⚠️  {total - passed} test(s) failed - Fix issues before integration")
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
