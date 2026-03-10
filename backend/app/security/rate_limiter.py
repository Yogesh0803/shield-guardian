"""
Lightweight rate-limiting module for Guardian Shield.

Detects obvious abuse patterns (flooding, port scans, SYN bursts) BEFORE
the traffic reaches the ML classification pipeline.  This reduces load on
the models and catches volumetric attacks that don't need ML to identify.

Architecture decision:
    The limiter lives in the backend but exposes a pure-function API so
    the ML engine can also import and call it in-process.  State is kept
    in-memory (dict + deque) for microsecond-level lookups — no DB round-
    trips on the hot path.

Thread safety:
    All mutable state is guarded by a threading.Lock so the module is
    safe for use from the ML engine's multi-threaded capture pipeline.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

logger = logging.getLogger("guardian-shield.rate-limiter")


@dataclass
class RateLimitConfig:
    """Configurable limits — can be overridden per-deployment."""
    # General packet rate
    max_packets_per_minute: int = 100
    window_seconds: int = 60

    # SYN flood detection
    max_syn_per_second: int = 20
    syn_window_seconds: int = 1

    # Scanning burst detection (unique destination ports from one IP)
    max_unique_ports_per_minute: int = 50
    port_scan_window_seconds: int = 60

    # Auto-block duration when limits are exceeded (seconds)
    block_duration: int = 300

    # Feature toggle — set to False to disable rate limiting entirely
    enabled: bool = True


@dataclass
class _IPState:
    """Per-IP sliding-window state."""
    # Timestamps of recent packets (deque acts as circular buffer)
    packet_times: deque = field(default_factory=lambda: deque(maxlen=5000))
    # SYN packet timestamps
    syn_times: deque = field(default_factory=lambda: deque(maxlen=2000))
    # Unique destination ports seen (timestamp, port)
    port_set: deque = field(default_factory=lambda: deque(maxlen=5000))


class RateLimiter:
    """Sliding-window rate limiter that tracks per-source-IP traffic."""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._state: Dict[str, _IPState] = defaultdict(_IPState)
        self._blocked_ips: Dict[str, float] = {}  # ip → block_expires_at
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_packet(
        self,
        source_ip: str,
        dst_port: int = 0,
        is_syn: bool = False,
        now: Optional[float] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Check whether a packet from *source_ip* should be allowed.

        Returns:
            (allowed, reason)
            - allowed=True  → packet passes; reason is None.
            - allowed=False → rate limit exceeded; reason describes which
              limit was hit (e.g. "packets_per_minute", "syn_flood",
              "port_scan").
        """
        if not self.config.enabled:
            return True, None

        now = now or time.time()

        with self._lock:
            # Fast path: already blocked
            if source_ip in self._blocked_ips:
                if now < self._blocked_ips[source_ip]:
                    return False, "ip_already_blocked"
                else:
                    # Block expired — remove
                    del self._blocked_ips[source_ip]

            state = self._state[source_ip]

            # 1. Sliding window — packets per minute
            self._prune_deque(state.packet_times, now - self.config.window_seconds)
            state.packet_times.append(now)
            if len(state.packet_times) > self.config.max_packets_per_minute:
                self._auto_block(source_ip, now)
                return False, "packets_per_minute"

            # 2. SYN flood detection
            if is_syn:
                self._prune_deque(state.syn_times, now - self.config.syn_window_seconds)
                state.syn_times.append(now)
                if len(state.syn_times) > self.config.max_syn_per_second:
                    self._auto_block(source_ip, now)
                    return False, "syn_flood"

            # 3. Port-scan burst detection
            if dst_port:
                self._prune_deque_pair(state.port_set, now - self.config.port_scan_window_seconds)
                state.port_set.append((now, dst_port))
                unique_ports = len({p for _, p in state.port_set})
                if unique_ports > self.config.max_unique_ports_per_minute:
                    self._auto_block(source_ip, now)
                    return False, "port_scan"

        return True, None

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently rate-limit-blocked."""
        with self._lock:
            if ip in self._blocked_ips:
                if time.time() < self._blocked_ips[ip]:
                    return True
                del self._blocked_ips[ip]
        return False

    def get_stats(self) -> dict:
        """Return current rate limiter statistics."""
        with self._lock:
            return {
                "tracked_ips": len(self._state),
                "blocked_ips": len(self._blocked_ips),
                "blocked_list": list(self._blocked_ips.keys()),
                "config": {
                    "max_packets_per_minute": self.config.max_packets_per_minute,
                    "max_syn_per_second": self.config.max_syn_per_second,
                    "max_unique_ports_per_minute": self.config.max_unique_ports_per_minute,
                    "window_seconds": self.config.window_seconds,
                    "enabled": self.config.enabled,
                },
            }

    def unblock_ip(self, ip: str) -> bool:
        """Manually remove a rate-limit block."""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                logger.info(f"Rate-limit block removed for {ip}")
                return True
        return False

    def cleanup_expired(self):
        """Remove expired blocks and stale IP state."""
        now = time.time()
        with self._lock:
            expired = [ip for ip, exp in self._blocked_ips.items() if now >= exp]
            for ip in expired:
                del self._blocked_ips[ip]
            # Clear state for IPs with no recent activity (>5 min idle)
            idle = [
                ip for ip, s in self._state.items()
                if s.packet_times and (now - s.packet_times[-1]) > 300
            ]
            for ip in idle:
                del self._state[ip]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auto_block(self, ip: str, now: float):
        """Block an IP due to rate limit violation."""
        self._blocked_ips[ip] = now + self.config.block_duration
        logger.warning(
            f"Rate limit exceeded for {ip} — auto-blocked for "
            f"{self.config.block_duration}s"
        )

    @staticmethod
    def _prune_deque(dq: deque, cutoff: float):
        """Remove entries older than *cutoff* from the left."""
        while dq and dq[0] < cutoff:
            dq.popleft()

    @staticmethod
    def _prune_deque_pair(dq: deque, cutoff: float):
        """Remove (timestamp, value) pairs older than *cutoff*."""
        while dq and dq[0][0] < cutoff:
            dq.popleft()


# Module-level singleton
rate_limiter = RateLimiter()
