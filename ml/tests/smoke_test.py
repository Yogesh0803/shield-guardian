"""Quick smoke test for the custom packet filter."""
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

print("=== Quick smoke test ===")
print(f"Platform: {sys.platform}")

# 1. Test the packet filter directly
from ml.enforcer.windows_packet_filter import WindowsPacketFilter

pf = WindowsPacketFilter()
print(f"pydivert available: {pf.is_available}")
started = pf.start()
print(f"Packet filter started: {started}")
if started:
    print("Running as admin — custom filter works!")
    pf.block_ip("8.8.8.8", reason="smoke test")
    import time; time.sleep(0.5)
    stats = pf.get_stats()
    print(f"Stats: inspected={stats['total_inspected']}, "
          f"dropped={stats['total_dropped']}, passed={stats['total_passed']}")
    print(f"Blocked IPs: {stats['blocked_ips']}")
    pf.unblock_ip("8.8.8.8")
    pf.stop()
    print("Filter stopped cleanly.")
else:
    print("Not admin — filter correctly refused to start.")

# 2. Test FirewallEnforcer fallback behavior
print()
print("=== FirewallEnforcer ===")
from ml.enforcer.firewall_rules import FirewallEnforcer

e = FirewallEnforcer(default_block_duration=30)
print(f"Custom filter active: {e._use_custom_filter}")
status = e.get_extended_status()
print(f"Firewall mode: {status['firewall_mode']}")
if "packet_filter_stats" in status:
    pfs = status["packet_filter_stats"]
    print(f"Packet filter stats: {pfs}")
e.cleanup()
print("Done.")
