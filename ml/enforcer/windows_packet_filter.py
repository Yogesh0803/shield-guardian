"""
Custom Windows Packet Filter using WinDivert.

Provides kernel-level packet interception and filtering on Windows,
completely independent of Windows Defender Firewall (netsh advfirewall).

WinDivert is a user-mode packet capture/divert library that installs a
lightweight kernel driver. It intercepts packets as they traverse the
Windows network stack, allowing us to inspect, modify, drop, or re-inject
them — effectively acting as our own firewall.

Requirements:
    pip install pydivert
    WinDivert driver files (WinDivert.dll, WinDivert64.sys) — bundled
    with pydivert automatically.

Must be run with Administrator privileges.
"""

import os
import sys
import time
import logging
import threading
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Lazy import: pydivert is Windows-only and optional
_pydivert = None
_WINDIVERT_AVAILABLE = False


def _ensure_pydivert():
    """Lazy-load pydivert on first use."""
    global _pydivert, _WINDIVERT_AVAILABLE
    if _pydivert is not None:
        return _WINDIVERT_AVAILABLE
    try:
        import pydivert as _pd
        _pydivert = _pd
        _WINDIVERT_AVAILABLE = True
        logger.info("pydivert loaded — WinDivert custom packet filter available")
    except ImportError:
        _WINDIVERT_AVAILABLE = False
        logger.warning(
            "pydivert not installed. Custom packet filter unavailable. "
            "Install with: pip install pydivert"
        )
    return _WINDIVERT_AVAILABLE


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BlockEntry:
    """A blocked IP entry in the packet filter."""
    ip: str
    direction: str  # "both", "inbound", "outbound"
    created_at: float = field(default_factory=time.time)
    reason: str = ""
    packet_drops: int = 0


@dataclass
class SubnetBlock:
    """A blocked subnet prefix (e.g., '192.168.1.')."""
    prefix: str
    direction: str
    created_at: float = field(default_factory=time.time)
    reason: str = ""


@dataclass
class IsolationEntry:
    """An isolated endpoint with optional management allow-list."""
    ip: str
    allowed_ips: Set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    reason: str = ""


@dataclass
class RateLimitState:
    """Per-IP rate limit tracking."""
    timestamps: List[float] = field(default_factory=list)
    limit: int = 100
    window: int = 60


@dataclass
class FilterStats:
    """Packet filter statistics."""
    total_inspected: int = 0
    total_dropped: int = 0
    total_passed: int = 0
    drops_by_ip: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    started_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Core packet filter
# ---------------------------------------------------------------------------

class WindowsPacketFilter:
    """
    Custom kernel-level packet filter for Windows using WinDivert.

    Unlike the netsh-based approach (which delegates to Windows Defender
    Firewall), this filter intercepts packets directly via a lightweight
    kernel driver installed by WinDivert. Packets matching block rules
    are silently dropped; all other packets are re-injected.

    Capabilities:
        - Block/unblock individual IPs (inbound, outbound, or both)
        - Block/unblock subnets (by /24 prefix)
        - Endpoint isolation with management IP allow-list
        - Per-IP rate limiting (sliding window, drop or pass)
        - Real-time packet statistics

    Usage:
        pf = WindowsPacketFilter()
        pf.start()
        pf.block_ip("1.2.3.4")
        ...
        pf.stop()
    """

    def __init__(self):
        self._blocked_ips: Dict[str, BlockEntry] = {}
        self._blocked_subnets: Dict[str, SubnetBlock] = {}
        self._isolated: Dict[str, IsolationEntry] = {}
        self._rate_limits: Dict[str, RateLimitState] = {}

        self._running = False
        self._filter_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._stats = FilterStats()

        # WinDivert handle — set when started
        self._wd_handle = None

        # Auto-restart settings
        self._max_restarts = 5
        self._restart_count = 0
        self._restart_cooldown = 2  # seconds between restarts

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """Check if WinDivert is installed and usable."""
        return _ensure_pydivert()

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> bool:
        """
        Start the packet filter engine.

        Opens the WinDivert handle synchronously so permission or driver
        errors are reported immediately (rather than silently failing in
        a background thread).

        Returns True if the filter is running (or was already running).
        Returns False if pydivert is not available or the handle cannot
        be opened (e.g. not running as Administrator).
        """
        if self._running:
            return True

        if not _ensure_pydivert():
            logger.error(
                "Cannot start custom packet filter: pydivert not installed. "
                "Install with:  pip install pydivert"
            )
            return False

        # Open the WinDivert handle NOW so errors surface immediately.
        try:
            handle = _pydivert.WinDivert(
                "ip and ip.SrcAddr != 127.0.0.1 and ip.DstAddr != 127.0.0.1"
            )
            handle.open()
        except OSError as e:
            logger.error(
                f"[PacketFilter] Cannot open WinDivert handle: {e}. "
                "Make sure you are running as Administrator."
            )
            return False
        except Exception as e:
            logger.error(f"[PacketFilter] WinDivert open failed: {e}")
            return False

        self._wd_handle = handle
        self._running = True
        self._stats = FilterStats()
        self._filter_thread = threading.Thread(
            target=self._filter_loop,
            name="GuardianShield-PacketFilter",
            daemon=True,
        )
        self._filter_thread.start()
        logger.info("Custom Windows packet filter started (WinDivert)")
        return True

    def stop(self):
        """Stop the packet filter and re-inject any pending packet."""
        if not self._running:
            return
        self._running = False
        # Close the WinDivert handle to unblock the recv() call
        if self._wd_handle is not None:
            try:
                self._wd_handle.close()
            except Exception:
                pass
        if self._filter_thread is not None:
            self._filter_thread.join(timeout=5)
            self._filter_thread = None
        logger.info(
            "Custom Windows packet filter stopped "
            f"(inspected={self._stats.total_inspected}, "
            f"dropped={self._stats.total_dropped})"
        )

    # ------------------------------------------------------------------
    # Block / Unblock IPs
    # ------------------------------------------------------------------

    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> bool:
        """
        Block all traffic to/from an IP address.

        Args:
            ip: IPv4 address to block
            direction: "both", "inbound", or "outbound"
            reason: Human-readable reason (for logging/audit)

        Returns: True (always succeeds once filter is running)
        """
        with self._lock:
            self._blocked_ips[ip] = BlockEntry(
                ip=ip, direction=direction, reason=reason,
            )
        logger.info(f"[PacketFilter] Blocked IP {ip} ({direction}) — {reason}")
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove a per-IP block."""
        with self._lock:
            removed = self._blocked_ips.pop(ip, None)
        if removed:
            logger.info(
                f"[PacketFilter] Unblocked IP {ip} "
                f"(was blocked, {removed.packet_drops} packets dropped)"
            )
        return True

    # ------------------------------------------------------------------
    # Block / Unblock subnets
    # ------------------------------------------------------------------

    def block_subnet(self, prefix: str, direction: str = "both", reason: str = "") -> bool:
        """
        Block a /24 subnet.

        Args:
            prefix: First three octets, e.g. "192.168.1." (trailing dot required)
            direction: "both", "inbound", "outbound"
        """
        with self._lock:
            self._blocked_subnets[prefix] = SubnetBlock(
                prefix=prefix, direction=direction, reason=reason,
            )
        logger.info(f"[PacketFilter] Blocked subnet {prefix}0/24 ({direction})")
        return True

    def unblock_subnet(self, prefix: str) -> bool:
        with self._lock:
            self._blocked_subnets.pop(prefix, None)
        logger.info(f"[PacketFilter] Unblocked subnet {prefix}0/24")
        return True

    # ------------------------------------------------------------------
    # Endpoint isolation
    # ------------------------------------------------------------------

    def isolate_endpoint(
        self,
        ip: str,
        allowed_ips: Optional[List[str]] = None,
        reason: str = "",
    ) -> bool:
        """
        Isolate an endpoint: drop ALL traffic to/from `ip` except for
        packets whose other end is in `allowed_ips` (management hosts).
        """
        with self._lock:
            self._isolated[ip] = IsolationEntry(
                ip=ip,
                allowed_ips=set(allowed_ips or []),
                reason=reason,
            )
        mgmt = ", ".join(allowed_ips) if allowed_ips else "(none)"
        logger.info(f"[PacketFilter] Isolated endpoint {ip} — allowed: {mgmt}")
        return True

    def unisolate_endpoint(self, ip: str) -> bool:
        """Remove endpoint isolation."""
        with self._lock:
            self._isolated.pop(ip, None)
        logger.info(f"[PacketFilter] Removed isolation for {ip}")
        return True

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def set_rate_limit(self, ip: str, limit: int = 100, window: int = 60):
        """Configure a packet-level rate limit for an IP."""
        with self._lock:
            self._rate_limits[ip] = RateLimitState(limit=limit, window=window)
        logger.info(f"[PacketFilter] Rate limit for {ip}: {limit} pkts / {window}s")

    def remove_rate_limit(self, ip: str):
        with self._lock:
            self._rate_limits.pop(ip, None)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return current packet filter statistics."""
        with self._lock:
            uptime = time.time() - self._stats.started_at
            return {
                "running": self._running,
                "uptime_seconds": int(uptime),
                "total_inspected": self._stats.total_inspected,
                "total_dropped": self._stats.total_dropped,
                "total_passed": self._stats.total_passed,
                "blocked_ips": list(self._blocked_ips.keys()),
                "blocked_subnets": list(self._blocked_subnets.keys()),
                "isolated_endpoints": list(self._isolated.keys()),
                "rate_limited_ips": list(self._rate_limits.keys()),
                "top_dropped_ips": dict(
                    sorted(
                        self._stats.drops_by_ip.items(),
                        key=lambda x: x[1],
                        reverse=True,
                    )[:20]
                ),
            }

    # ------------------------------------------------------------------
    # Internal: packet filtering loop
    # ------------------------------------------------------------------

    def _filter_loop(self):
        """
        Main WinDivert packet interception loop with auto-restart.

        The WinDivert handle is already open (created in start()).
        For each packet, decides whether to drop or re-inject.
        If an unexpected error occurs, the loop automatically re-opens
        the handle and resumes (up to _max_restarts times).
        """
        while self._running:
            try:
                logger.debug("[PacketFilter] Filter loop running — handle already open")

                while self._running:
                    try:
                        packet = self._wd_handle.recv()
                    except Exception:
                        if not self._running:
                            return
                        raise

                    if packet is None:
                        continue

                    src_ip = packet.src_addr
                    dst_ip = packet.dst_addr

                    with self._lock:
                        self._stats.total_inspected += 1
                        drop = self._should_drop_packet(src_ip, dst_ip)

                    if drop:
                        with self._lock:
                            self._stats.total_dropped += 1
                            # Track drops for both src and dst if blocked
                            if dst_ip in self._blocked_ips:
                                self._stats.drops_by_ip[dst_ip] += 1
                                self._blocked_ips[dst_ip].packet_drops += 1
                            if src_ip in self._blocked_ips:
                                self._stats.drops_by_ip[src_ip] += 1
                                self._blocked_ips[src_ip].packet_drops += 1
                        # Do NOT re-inject → packet is silently dropped
                        continue

                    # Re-inject the packet into the network stack
                    with self._lock:
                        self._stats.total_passed += 1
                    try:
                        self._wd_handle.send(packet)
                    except OSError:
                        # WinDivert send() can fail with WinError 87 for certain
                        # packets (e.g. loopback, fragmented).  Skip gracefully.
                        if not self._running:
                            return
                    except Exception:
                        if not self._running:
                            return
                        raise

            except Exception as e:
                if not self._running:
                    break
                self._restart_count += 1
                if self._restart_count > self._max_restarts:
                    logger.error(
                        f"[PacketFilter] Filter loop crashed {self._restart_count} times, "
                        "giving up. Last error: {e}"
                    )
                    break
                logger.warning(
                    f"[PacketFilter] Filter loop error ({e}), "
                    f"auto-restarting ({self._restart_count}/{self._max_restarts})..."
                )
                # Close old handle and re-open
                try:
                    self._wd_handle.close()
                except Exception:
                    pass
                time.sleep(self._restart_cooldown)
                if not self._running:
                    break
                try:
                    handle = _pydivert.WinDivert(
                        "ip and ip.SrcAddr != 127.0.0.1 and ip.DstAddr != 127.0.0.1"
                    )
                    handle.open()
                    self._wd_handle = handle
                    logger.info("[PacketFilter] Filter loop restarted successfully")
                except Exception as reopen_err:
                    logger.error(f"[PacketFilter] Failed to reopen WinDivert: {reopen_err}")
                    break

        self._running = False
        if self._wd_handle is not None:
            try:
                self._wd_handle.close()
            except Exception:
                pass
        logger.debug("[PacketFilter] Filter loop exited")

    def _should_drop_packet(self, src_ip: str, dst_ip: str) -> bool:
        """
        Decide whether to drop a packet. Called with self._lock held.

        Priority order:
            1. Isolation rules (strictest)
            2. Direct IP blocks
            3. Subnet blocks
            4. Rate limits
        """
        # --- 1. Isolation ---
        for iso_ip, entry in self._isolated.items():
            if src_ip == iso_ip or dst_ip == iso_ip:
                other = dst_ip if src_ip == iso_ip else src_ip
                if other not in entry.allowed_ips:
                    return True  # isolated and not in allow-list → drop

        # --- 2. Direct IP blocks ---
        for ip, entry in self._blocked_ips.items():
            if entry.direction == "both":
                if src_ip == ip or dst_ip == ip:
                    return True
            elif entry.direction == "inbound" and src_ip == ip:
                return True
            elif entry.direction == "outbound" and dst_ip == ip:
                return True

        # --- 3. Subnet blocks ---
        for prefix, entry in self._blocked_subnets.items():
            if entry.direction == "both":
                if src_ip.startswith(prefix) or dst_ip.startswith(prefix):
                    return True
            elif entry.direction == "inbound" and src_ip.startswith(prefix):
                return True
            elif entry.direction == "outbound" and dst_ip.startswith(prefix):
                return True

        # --- 4. Rate limits ---
        now = time.time()
        for ip, rl in self._rate_limits.items():
            if src_ip == ip or dst_ip == ip:
                # Prune stale timestamps first
                rl.timestamps = [t for t in rl.timestamps if now - t < rl.window]
                rl.timestamps.append(now)
                if len(rl.timestamps) > rl.limit:
                    return True
                break  # Only match one rate-limit rule per packet

        return False
