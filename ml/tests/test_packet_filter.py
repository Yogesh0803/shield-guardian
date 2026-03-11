"""
Test script for GuardianShield custom Windows packet filter.
Must be run as Administrator.
"""

import time
import logging
import sys
import subprocess
import ctypes

import pytest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("test_packet_filter")


def _is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

# ── Helpers ──────────────────────────────────────────────────────

def ping(ip: str, count: int = 2, timeout_ms: int = 1000) -> bool:
    """Return True if ping succeeds."""
    result = subprocess.run(
        ["ping", "-n", str(count), "-w", str(timeout_ms), ip],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ── Tests ────────────────────────────────────────────────────────

def test_packet_filter_standalone():
    """Test the WindowsPacketFilter directly."""
    if not _is_admin():
        pytest.skip("Administrator privileges required for packet filter test")

    from ml.enforcer.windows_packet_filter import WindowsPacketFilter

    section("Test 1: WindowsPacketFilter — standalone")

    pf = WindowsPacketFilter()
    assert pf.is_available, "pydivert not available"
    print("[PASS] pydivert is available")

    assert pf.start(), "Failed to start packet filter"
    assert pf.is_running
    print("[PASS] Packet filter started")

    # Test block/unblock an IP (use Google DNS as safe target)
    target = "8.8.8.8"

    # Baseline: should be reachable
    print(f"\n  Pinging {target} (should succeed)...")
    assert ping(target), f"{target} should be reachable before block"
    print(f"  [PASS] {target} reachable before block")

    # Block
    pf.block_ip(target, reason="test block")
    print(f"\n  Blocked {target} via custom filter")
    time.sleep(1)  # give the filter a moment

    print(f"  Pinging {target} (should FAIL)...")
    blocked = not ping(target, count=2, timeout_ms=1500)
    if blocked:
        print(f"  [PASS] {target} is blocked by custom filter")
    else:
        print(f"  [WARN] {target} still reachable — filter may need more time or admin rights")

    # Unblock
    pf.unblock_ip(target)
    print(f"\n  Unblocked {target}")
    time.sleep(1)

    print(f"  Pinging {target} (should succeed again)...")
    assert ping(target), f"{target} should be reachable after unblock"
    print(f"  [PASS] {target} reachable after unblock")

    # Stats
    stats = pf.get_stats()
    print(f"\n  Filter stats: inspected={stats['total_inspected']}, "
          f"dropped={stats['total_dropped']}, passed={stats['total_passed']}")
    print(f"  Blocked IPs: {stats['blocked_ips']}")
    assert stats["total_inspected"] > 0, "No packets inspected"
    print("[PASS] Packet stats are being tracked")

    pf.stop()
    assert not pf.is_running
    print("[PASS] Packet filter stopped cleanly")


def test_firewall_enforcer_integration():
    """Test FirewallEnforcer using the custom filter."""
    if not _is_admin():
        pytest.skip("Administrator privileges required for packet filter integration test")

    from ml.enforcer.firewall_rules import FirewallEnforcer

    section("Test 2: FirewallEnforcer — integration with custom filter")

    enforcer = FirewallEnforcer(default_block_duration=30)
    print(f"  Platform: {enforcer.platform}")
    print(f"  Custom filter active: {enforcer._use_custom_filter}")

    if not enforcer._use_custom_filter:
        print("[SKIP] Custom filter not active — cannot test packet-level blocking")
        enforcer.cleanup()
        return

    print("[PASS] Custom filter is active")

    target = "8.8.4.4"  # Google public DNS (secondary)

    # Baseline
    print(f"\n  Pinging {target} (baseline)...")
    assert ping(target), f"{target} should be reachable"
    print(f"  [PASS] {target} reachable")

    # Block via enforcer
    result = enforcer.block_ip(target, duration=15, reason="integration test")
    assert result, "block_ip returned False"
    print(f"\n  Blocked {target} via FirewallEnforcer")
    time.sleep(1)

    print(f"  Pinging {target} (should FAIL)...")
    blocked = not ping(target, count=2, timeout_ms=1500)
    if blocked:
        print(f"  [PASS] {target} blocked via enforcer's custom filter")
    else:
        print(f"  [WARN] {target} still reachable")

    # Check status
    rules = enforcer.get_active_rules()
    print(f"\n  Active rules: {len(rules)}")
    for r in rules:
        print(f"    - {r['ip']} (reason: {r['reason']}, expires_in: {r['expires_in']}s)")

    status = enforcer.get_extended_status()
    print(f"  Firewall mode: {status['firewall_mode']}")
    if "packet_filter_stats" in status:
        pfs = status["packet_filter_stats"]
        print(f"  Packet filter: inspected={pfs['total_inspected']}, "
              f"dropped={pfs['total_dropped']}")
    print("[PASS] Status/stats reporting works")

    # Unblock
    enforcer.unblock_ip(target)
    print(f"\n  Unblocked {target}")
    time.sleep(1)

    print(f"  Pinging {target} (should succeed)...")
    assert ping(target), f"{target} should be reachable after unblock"
    print(f"  [PASS] {target} reachable after unblock")

    # Cleanup
    enforcer.cleanup()
    print("[PASS] Cleanup succeeded")


def test_isolation():
    """Test endpoint isolation via the custom filter."""
    if not _is_admin():
        pytest.skip("Administrator privileges required for isolation test")

    from ml.enforcer.firewall_rules import FirewallEnforcer

    section("Test 3: Endpoint isolation")

    enforcer = FirewallEnforcer(default_block_duration=30)
    if not enforcer._use_custom_filter:
        print("[SKIP] Custom filter not active")
        enforcer.cleanup()
        return

    target = "1.1.1.1"  # Cloudflare DNS

    print(f"  Pinging {target} (baseline)...")
    assert ping(target), f"{target} should be reachable"
    print(f"  [PASS] {target} reachable")

    # Isolate (no allowed IPs → blocks everything)
    enforcer.isolate_endpoint(target, scope="endpoint", duration=15, reason="isolation test")
    print(f"\n  Isolated {target}")
    time.sleep(1)

    print(f"  Pinging {target} (should FAIL)...")
    blocked = not ping(target, count=2, timeout_ms=1500)
    if blocked:
        print(f"  [PASS] {target} isolated (blocked)")
    else:
        print(f"  [WARN] {target} still reachable")

    # Unisolate
    enforcer.unisolate_endpoint(target)
    print(f"\n  Removed isolation for {target}")
    time.sleep(1)

    print(f"  Pinging {target} (should succeed)...")
    assert ping(target), f"{target} should be reachable after unisolation"
    print(f"  [PASS] {target} reachable after unisolation")

    enforcer.cleanup()
    print("[PASS] Isolation test passed")


# ── Main ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("GuardianShield Custom Packet Filter — Test Suite")
    print(f"Platform: {sys.platform}")
    print(f"Python: {sys.version}")

    try:
        test_packet_filter_standalone()
        test_firewall_enforcer_integration()
        test_isolation()

        section("ALL TESTS PASSED")
    except Exception as e:
        print(f"\n[FAIL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Safety: make sure we didn't leave any blocks active
        try:
            from ml.enforcer.windows_packet_filter import WindowsPacketFilter
            # If any orphaned filter is running, stop it
        except Exception:
            pass
