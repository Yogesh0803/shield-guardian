"""
Live packet capture using Scapy.
Captures TCP/UDP/ICMP packets and groups them into flows.
"""

import sys
import time
import threading
import logging
import ctypes
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list

logger = logging.getLogger(__name__)


def _is_admin() -> bool:
    """Check whether the current process has admin/root privileges."""
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            import os
            return os.geteuid() == 0
    except Exception:
        return False


def _npcap_available() -> bool:
    """Check whether Npcap (or WinPcap) is installed on Windows."""
    if sys.platform != "win32":
        return True  # not applicable
    import shutil
    # Npcap installs into System32\Npcap or its own folder;
    # the simplest probe is whether Scapy can list interfaces.
    try:
        ifaces = get_if_list()
        return len(ifaces) > 0
    except Exception:
        return False


@dataclass
class PacketInfo:
    """Parsed packet metadata."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP
    length: int
    flags: str = ""
    payload_size: int = 0
    ttl: int = 0
    header_length: int = 0


@dataclass
class Flow:
    """A network flow (5-tuple grouped packets)."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: List[PacketInfo] = field(default_factory=list)
    start_time: float = 0.0
    last_time: float = 0.0

    @property
    def duration(self) -> float:
        return self.last_time - self.start_time if self.packets else 0.0

    @property
    def total_bytes(self) -> int:
        return sum(p.length for p in self.packets)

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    def add_packet(self, pkt: PacketInfo):
        if not self.packets:
            self.start_time = pkt.timestamp
        self.last_time = pkt.timestamp
        self.packets.append(pkt)


class PacketCapture:
    """Captures live network packets and groups them into flows."""

    @staticmethod
    def _detect_interface() -> str:
        """Pick a suitable capture interface, preferring real hardware NICs.

        On Windows, ``conf.iface`` may resolve to a Hyper-V / Docker /
        WSL virtual adapter that carries no user traffic.  This helper
        iterates the available interfaces and returns the first one
        whose name looks like a real NIC.  Falls back to ``conf.iface``
        when nothing better is found.
        """
        fallback = str(conf.iface)
        try:
            ifaces = get_if_list()
            if not ifaces:
                logger.warning(
                    "No network interfaces found — falling back to "
                    f"default: {fallback}"
                )
                return fallback

            logger.info(f"Available interfaces: {ifaces}")

            if sys.platform == "win32":
                # Skip common virtual adapters on Windows
                skip_keywords = (
                    "virtual", "hyper-v", "vmware", "vethernet",
                    "docker", "wsl", "loopback", "npcap", "bluetooth",
                )
                real = [
                    i for i in ifaces
                    if not any(k in i.lower() for k in skip_keywords)
                ]
                if real:
                    logger.info(
                        f"Auto-detected interface: {real[0]} "
                        f"(filtered {len(ifaces) - len(real)} virtual adapters)"
                    )
                    return real[0]
                else:
                    logger.warning(
                        "All interfaces look virtual — falling back to "
                        f"default: {fallback}. Consider specifying "
                        "--interface explicitly."
                    )

            return fallback
        except Exception as e:
            logger.warning(
                f"Interface detection failed ({e}) — falling back to "
                f"default: {fallback}"
            )
            return fallback

    def __init__(
        self,
        interface: str = "",
        capture_filter: str = "ip",
        flow_timeout: int = 10,
        buffer_size: int = 100,
    ):
        self.interface = interface or self._detect_interface()
        self.capture_filter = capture_filter
        self.flow_timeout = flow_timeout
        self.buffer_size = buffer_size

        self._active_flows: Dict[str, Flow] = {}
        self._lock = threading.Lock()
        self._running = False
        self._capture_alive = False  # True while capture thread is executing
        self._on_flow_complete: Optional[Callable[[Flow], None]] = None
        self._capture_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None

        # Stats
        self.total_packets = 0
        self.total_bytes = 0
        self.total_flows = 0

    def on_flow_complete(self, callback: Callable[[Flow], None]):
        """Register callback for when a flow is complete (timed out)."""
        self._on_flow_complete = callback

    def start(self):
        """Start packet capture in a background thread."""
        if self._running:
            return

        # ── Pre-flight checks ──────────────────────────────────────
        if sys.platform == "win32" and not _npcap_available():
            logger.critical(
                "STARTUP FAILED — Npcap is not installed or not functioning. "
                "Install Npcap from https://npcap.com/ with "
                "'WinPcap API-compatible mode' enabled, then restart."
            )
            return

        if not _is_admin():
            logger.critical(
                "STARTUP FAILED — packet capture requires admin/root privileges. "
                "On Windows: right-click terminal → 'Run as Administrator'. "
                "On Linux: use 'sudo python -m ml.main'."
            )
            return

        # ── Startup probe — try to capture one packet to validate ──
        logger.info(
            f"Running capture probe on interface '{self.interface}' ..."
        )
        try:
            test_pkts = sniff(
                iface=self.interface,
                filter=self.capture_filter,
                count=1,
                timeout=5,
                store=True,
            )
            if test_pkts:
                logger.info(
                    f"Capture probe OK — received {len(test_pkts)} packet(s) "
                    f"on '{self.interface}'"
                )
            else:
                logger.warning(
                    f"Capture probe: 0 packets in 5 s on '{self.interface}'. "
                    "Interface may be idle or wrong. Continuing anyway …"
                )
        except PermissionError:
            logger.critical(
                "STARTUP FAILED — Permission denied during capture probe. "
                "Run with elevated privileges."
            )
            return
        except Exception as e:
            logger.warning(
                f"Capture probe raised {type(e).__name__}: {e} — continuing anyway"
            )

        self._running = True

        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="capture-thread"
        )
        self._capture_thread.start()

        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="cleanup-thread"
        )
        self._cleanup_thread.start()

        logger.info(f"Packet capture started on interface: {self.interface}")

    def stop(self):
        """Stop packet capture."""
        self._running = False
        # Flush remaining flows — collect under lock, invoke callbacks outside
        remaining = []
        with self._lock:
            for flow in self._active_flows.values():
                if flow.packet_count > 0:
                    remaining.append(flow)
            self._active_flows.clear()
        for flow in remaining:
            if self._on_flow_complete:
                self._on_flow_complete(flow)
        logger.info("Packet capture stopped")

    def _capture_loop(self):
        """Main capture loop using Scapy sniff.

        Uses a bounded ``timeout`` so the loop re-evaluates
        ``self._running`` even when zero packets are arriving.
        Without this, ``stop_filter`` is never invoked on a
        silent interface and ``stop()`` cannot terminate the thread.
        """
        import traceback

        logger.info(
            f"Capture thread started: interface={self.interface}, "
            f"filter={self.capture_filter}"
        )
        self._capture_alive = True
        _zero_warned = False
        _consecutive_sniff_errors = 0
        _last_pkt_log = 0  # monotonic ts of last periodic packet-count log
        try:
            while self._running:
                try:
                    sniff(
                        iface=self.interface,
                        filter=self.capture_filter,
                        prn=self._process_packet,
                        store=False,
                        stop_filter=lambda _: not self._running,
                        timeout=self.flow_timeout,
                    )
                    _consecutive_sniff_errors = 0  # reset on success
                except PermissionError:
                    logger.critical(
                        "CAPTURE THREAD — Permission denied: packet capture "
                        "requires admin/root privileges. Run with elevated "
                        "permissions. No predictions will be generated."
                    )
                    self._running = False
                    return
                except OSError as e:
                    _consecutive_sniff_errors += 1
                    logger.error(
                        f"CAPTURE THREAD — OS error (bad interface?): {e}. "
                        f"Available interfaces: {get_if_list()}. "
                        f"(consecutive errors: {_consecutive_sniff_errors})"
                    )
                    if _consecutive_sniff_errors >= 5:
                        logger.critical(
                            "CAPTURE THREAD EXITING — too many consecutive "
                            "sniff errors. Fix the interface and restart."
                        )
                        self._running = False
                        return
                    time.sleep(2)  # back off before retry
                    continue
                except Exception as e:
                    _consecutive_sniff_errors += 1
                    logger.error(
                        f"CAPTURE THREAD — unexpected sniff error: "
                        f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
                        f"(consecutive errors: {_consecutive_sniff_errors})"
                    )
                    if _consecutive_sniff_errors >= 5:
                        logger.critical(
                            "CAPTURE THREAD EXITING — too many consecutive "
                            "sniff errors."
                        )
                        self._running = False
                        return
                    time.sleep(2)
                    continue

                # Periodic packet-count log (every ~30 s when packets flow)
                now_mono = time.monotonic()
                if now_mono - _last_pkt_log > 30:
                    logger.info(
                        f"[CAPTURE] packets={self.total_packets}, "
                        f"bytes={self.total_bytes}, "
                        f"completed_flows={self.total_flows}, "
                        f"active_flows={len(self._active_flows)}"
                    )
                    _last_pkt_log = now_mono

                # After a timeout cycle with no packets, warn *once*
                if self._running and self.total_packets == 0 and not _zero_warned:
                    logger.warning(
                        f"No packets captured yet on '{self.interface}' — "
                        "verify interface name and traffic availability. "
                        f"Available interfaces: {get_if_list()}"
                    )
                    _zero_warned = True
        except Exception as e:
            logger.critical(
                f"CAPTURE THREAD EXITED — outer loop error: "
                f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
            )
            self._running = False
        finally:
            self._capture_alive = False
            logger.info(
                f"Capture thread exited  "
                f"(packets={self.total_packets}, flows={self.total_flows})"
            )

    def _cleanup_loop(self):
        """Periodically flush timed-out flows."""
        logger.info("Cleanup thread started")
        while self._running:
            time.sleep(self.flow_timeout / 2)
            flushed = self._flush_expired_flows()
            with self._lock:
                active = len(self._active_flows)
            if flushed > 0:
                logger.info(
                    f"[FLOWS] Flushed {flushed} completed flow(s) | "
                    f"active={active}, total_completed={self.total_flows}"
                )
            elif active > 0 or self.total_flows > 0:
                logger.debug(
                    f"Flow cleanup: {active} active flows, "
                    f"{self.total_flows} completed so far"
                )
        logger.info("Cleanup thread exited")

    def _process_packet(self, pkt):
        """Process a single captured packet."""
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        pkt_info = PacketInfo(
            timestamp=float(pkt.time),
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=0,
            dst_port=0,
            protocol="OTHER",
            length=len(pkt),
            ttl=ip.ttl,
            header_length=ip.ihl * 4,
        )

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            pkt_info.src_port = tcp.sport
            pkt_info.dst_port = tcp.dport
            pkt_info.protocol = "TCP"
            pkt_info.flags = str(tcp.flags)
            pkt_info.payload_size = len(tcp.payload) if tcp.payload else 0
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            pkt_info.src_port = udp.sport
            pkt_info.dst_port = udp.dport
            pkt_info.protocol = "UDP"
            pkt_info.payload_size = len(udp.payload) if udp.payload else 0
        elif pkt.haslayer(ICMP):
            pkt_info.protocol = "ICMP"

        # Build flow ID (5-tuple)
        flow_id = f"{pkt_info.src_ip}:{pkt_info.src_port}-{pkt_info.dst_ip}:{pkt_info.dst_port}-{pkt_info.protocol}"

        with self._lock:
            if flow_id not in self._active_flows:
                self._active_flows[flow_id] = Flow(
                    flow_id=flow_id,
                    src_ip=pkt_info.src_ip,
                    dst_ip=pkt_info.dst_ip,
                    src_port=pkt_info.src_port,
                    dst_port=pkt_info.dst_port,
                    protocol=pkt_info.protocol,
                )
            self._active_flows[flow_id].add_packet(pkt_info)

        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt_info.length

    def _flush_expired_flows(self) -> int:
        """Flush flows that have been inactive longer than flow_timeout.

        Returns the number of flows flushed.
        """
        now = time.time()
        completed_flows = []

        with self._lock:
            expired = [
                fid for fid, flow in self._active_flows.items()
                if now - flow.last_time > self.flow_timeout
            ]
            for flow_id in expired:
                flow = self._active_flows.pop(flow_id)
                self.total_flows += 1
                if flow.packet_count > 0:
                    completed_flows.append(flow)

        # Invoke callbacks OUTSIDE the lock so ML inference
        # does not block packet processing.
        for flow in completed_flows:
            if self._on_flow_complete:
                try:
                    self._on_flow_complete(flow)
                except Exception as e:
                    logger.error(
                        f"on_flow_complete callback failed for "
                        f"{flow.flow_id}: {e}"
                    )

        return len(completed_flows)

    def get_stats(self) -> dict:
        """Return capture statistics."""
        with self._lock:
            active = len(self._active_flows)
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_flows": self.total_flows,
            "active_flows": active,
            "interface": self.interface,
            "running": self._running,
            "capture_alive": self._capture_alive,
        }
