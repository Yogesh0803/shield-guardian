"""Quick manual smoke test for the custom packet filter."""

import logging
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def main():
    print("=== Quick smoke test ===")
    print(f"Platform: {sys.platform}")

    from ml.enforcer.windows_packet_filter import WindowsPacketFilter

    pf = WindowsPacketFilter()
    print(f"pydivert available: {pf.is_available}")
    started = pf.start()
    print(f"Packet filter started: {started}")
    if started:
        print("Running as admin - custom filter works!")
        pf.block_ip("8.8.8.8", reason="smoke test")
        time.sleep(0.5)
        stats = pf.get_stats()
        print(
            f"Stats: inspected={stats['total_inspected']}, "
            f"dropped={stats['total_dropped']}, passed={stats['total_passed']}"
        )
        print(f"Blocked IPs: {stats['blocked_ips']}")
        pf.unblock_ip("8.8.8.8")
        pf.stop()
        print("Filter stopped cleanly.")
    else:
        print("Not admin - filter correctly refused to start.")

    print()
    print("=== FirewallEnforcer ===")
    from ml.enforcer.firewall_rules import FirewallEnforcer

    enforcer = FirewallEnforcer(default_block_duration=30)
    print(f"Custom filter active: {enforcer._use_custom_filter}")
    status = enforcer.get_extended_status()
    print(f"Firewall mode: {status['firewall_mode']}")
    if "packet_filter_stats" in status:
        print(f"Packet filter stats: {status['packet_filter_stats']}")
    enforcer.cleanup()
    print("Done.")


if __name__ == "__main__":
    raise SystemExit(main())
