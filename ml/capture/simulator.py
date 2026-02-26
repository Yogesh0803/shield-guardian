"""
Synthetic traffic generator for Guardian Shield ML Engine.

Used when live packet capture is unavailable (no Npcap, no admin rights,
or CI/demo environments).  Generates realistic Flow objects that feed
through the exact same ML inference pipeline as live traffic.

Usage:
    python -m ml.main --simulate
"""

import time
import random
import logging
import threading
from typing import Callable, Optional, List

from .packet_capture import PacketInfo, Flow

logger = logging.getLogger(__name__)

# ── Realistic traffic profiles ──────────────────────────────────────

_BENIGN_PROFILES = [
    # (app_name, dst_ip, dst_port, protocol, pkt_count_range, size_range)
    ("chrome", "142.250.190.46", 443, "TCP", (5, 30), (60, 1400)),
    ("chrome", "151.101.1.69", 443, "TCP", (3, 20), (60, 900)),
    ("firefox", "104.16.249.249", 443, "TCP", (4, 25), (64, 1200)),
    ("outlook", "52.96.166.130", 443, "TCP", (2, 10), (100, 800)),
    ("teams", "52.113.194.132", 443, "TCP", (3, 15), (80, 600)),
    ("vscode", "13.107.42.14", 443, "TCP", (2, 8), (64, 500)),
    ("dns", "8.8.8.8", 53, "UDP", (1, 3), (40, 120)),
    ("dns", "1.1.1.1", 53, "UDP", (1, 2), (40, 100)),
    ("curl", "93.184.216.34", 80, "TCP", (3, 12), (60, 1400)),
    ("spotify", "35.186.224.25", 443, "TCP", (10, 50), (200, 1400)),
    ("zoom", "170.114.52.2", 8801, "UDP", (20, 60), (100, 1200)),
    ("slack", "34.192.25.133", 443, "TCP", (2, 10), (80, 600)),
    ("windows-update", "13.107.4.52", 443, "TCP", (5, 20), (200, 1400)),
    ("pip", "151.101.128.223", 443, "TCP", (4, 15), (100, 1400)),
]

_ATTACK_PROFILES = [
    # (attack_label, dst_ip, dst_port, protocol, pkt_count_range, size_range, flags)
    ("DDoS", "10.0.1.10", 80, "TCP", (50, 200), (40, 60), "S"),
    ("PortScan", "10.0.2.20", 0, "TCP", (10, 40), (40, 44), "S"),
    ("BruteForce", "10.0.1.10", 22, "TCP", (5, 20), (60, 200), "SPA"),
    ("DoS", "10.0.3.30", 443, "TCP", (30, 100), (40, 800), "S"),
    ("WebAttack", "10.0.1.10", 80, "TCP", (5, 15), (200, 1400), "SPA"),
]

# Source IPs
_LOCAL_IPS = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.5"]
_ATTACKER_IPS = ["203.0.113.50", "198.51.100.77", "185.220.101.34", "45.155.205.99"]


def _generate_benign_flow() -> Flow:
    """Generate a single benign-looking flow."""
    profile = random.choice(_BENIGN_PROFILES)
    app, dst_ip, dst_port, proto, pkt_range, size_range = profile
    src_ip = random.choice(_LOCAL_IPS)
    src_port = random.randint(49152, 65535)
    pkt_count = random.randint(*pkt_range)
    now = time.time()

    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    flow = Flow(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
    )

    # Forward packets (client → server)
    fwd_flags = "SA" if proto == "TCP" else ""
    for i in range(pkt_count):
        is_fwd = random.random() < 0.6
        pkt = PacketInfo(
            timestamp=now + i * random.uniform(0.001, 0.1),
            src_ip=src_ip if is_fwd else dst_ip,
            dst_ip=dst_ip if is_fwd else src_ip,
            src_port=src_port if is_fwd else dst_port,
            dst_port=dst_port if is_fwd else src_port,
            protocol=proto,
            length=random.randint(*size_range),
            flags=fwd_flags if proto == "TCP" else "",
            payload_size=random.randint(0, size_range[1] - 40),
            ttl=random.choice([64, 128]),
            header_length=20 if proto == "TCP" else 8,
        )
        flow.add_packet(pkt)

    return flow


def _generate_attack_flow() -> Flow:
    """Generate a single attack-looking flow."""
    profile = random.choice(_ATTACK_PROFILES)
    label, dst_ip, dst_port_base, proto, pkt_range, size_range, flags = profile

    src_ip = random.choice(_ATTACKER_IPS)
    src_port = random.randint(1024, 65535)
    # PortScan varies destination ports
    dst_port = (
        random.randint(1, 1024) if label == "PortScan" else dst_port_base
    )
    pkt_count = random.randint(*pkt_range)
    now = time.time()

    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    flow = Flow(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
    )

    for i in range(pkt_count):
        pkt = PacketInfo(
            timestamp=now + i * random.uniform(0.0001, 0.01),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=random.randint(*size_range),
            flags=flags,
            payload_size=random.randint(0, size_range[1]),
            ttl=random.choice([64, 128, 255]),
            header_length=20,
        )
        flow.add_packet(pkt)

    return flow


class TrafficSimulator:
    """
    Generates synthetic network flows at a configurable rate.

    Mimics PacketCapture's interface: has `start()`, `stop()`,
    `on_flow_complete()`, and `get_stats()` so it can be swapped in
    as a drop-in replacement.
    """

    def __init__(
        self,
        flows_per_minute: float = 30.0,
        attack_ratio: float = 0.15,
    ):
        self.flows_per_minute = flows_per_minute
        self.attack_ratio = attack_ratio
        self.interface = "simulator"
        self.flow_timeout = 5

        self._running = False
        self._capture_alive = False
        self._on_flow_cb: Optional[Callable[[Flow], None]] = None
        self._thread: Optional[threading.Thread] = None

        # Stats (compatible with PacketCapture.get_stats)
        self.total_packets = 0
        self.total_bytes = 0
        self.total_flows = 0

    # ── Public API (mirrors PacketCapture) ──────────────────────────

    def on_flow_complete(self, callback: Callable[[Flow], None]):
        self._on_flow_cb = callback

    def start(self):
        if self._running:
            return
        self._running = True
        self._capture_alive = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="simulator-thread"
        )
        self._thread.start()
        logger.info(
            f"Traffic simulator started — {self.flows_per_minute} flows/min, "
            f"{self.attack_ratio:.0%} attack ratio"
        )

    def stop(self):
        self._running = False
        self._capture_alive = False
        logger.info(
            f"Traffic simulator stopped — generated {self.total_flows} flows"
        )

    def get_stats(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_flows": self.total_flows,
            "active_flows": 0,
            "interface": self.interface,
            "running": self._running,
            "capture_alive": self._capture_alive,
        }

    # ── Internal ────────────────────────────────────────────────────

    def _run(self):
        """Main simulation loop."""
        interval = 60.0 / max(self.flows_per_minute, 1)
        logger.info(f"Simulator interval: one flow every {interval:.1f}s")

        while self._running:
            try:
                is_attack = random.random() < self.attack_ratio
                flow = _generate_attack_flow() if is_attack else _generate_benign_flow()

                self.total_packets += flow.packet_count
                self.total_bytes += flow.total_bytes
                self.total_flows += 1

                if self._on_flow_cb:
                    self._on_flow_cb(flow)

            except Exception as e:
                logger.error(f"Simulator error: {e}", exc_info=True)

            # Jitter ±30% to look realistic
            jitter = interval * random.uniform(0.7, 1.3)
            time.sleep(jitter)

        self._capture_alive = False
        logger.info("Simulator thread exited")
