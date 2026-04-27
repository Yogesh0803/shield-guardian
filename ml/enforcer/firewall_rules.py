"""
Firewall rule enforcement.
Actually blocks/allows traffic using OS-level firewall commands.

On Windows: uses a custom WinDivert-based packet filter (kernel-level
interception, independent of Windows Defender Firewall). Falls back to
netsh advfirewall if WinDivert/pydivert is not available.

On Linux: uses iptables.

Extended actions: rate limiting, endpoint isolation, monitoring.
"""

import re
import sys
import subprocess
import logging
import time
from typing import Dict, List, Optional, Set, TYPE_CHECKING
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Timer, Lock

if sys.platform == "win32":
    from .windows_packet_filter import WindowsPacketFilter
elif TYPE_CHECKING:
    from .windows_packet_filter import WindowsPacketFilter

# Structured security logger (graceful import — never crash if missing)
try:
    from backend.app.utils.security_logger import security_log as _sec_log
except ImportError:
    _sec_log = None  # type: ignore[assignment]

# Strict regex: bare IPv4 or IPv6 address only — no CIDR, no spaces.
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")  # coarse check; good enough to prevent injection

logger = logging.getLogger(__name__)


@dataclass
class BlockRule:
    """An active block rule."""
    ip: str
    rule_name: str
    created_at: float
    expires_at: Optional[float] = None  # None = permanent
    app_name: str = ""
    reason: str = ""


@dataclass
class IsolationRule:
    """An active endpoint isolation rule."""
    target: str  # IP or hostname
    scope: str  # "endpoint" or "subnet"
    rule_name: str
    created_at: float
    expires_at: Optional[float] = None
    reason: str = ""
    allowed_ips: List[str] = field(default_factory=list)  # management IPs still allowed


@dataclass
class RateLimitEntry:
    """Tracks request counts for rate limiting."""
    timestamps: List[float] = field(default_factory=list)
    limit: int = 100
    window: int = 60  # seconds
    action: str = "block"  # "block", "alert", "throttle"


@dataclass
class MonitorEntry:
    """An active monitoring rule."""
    target: str
    mode: str  # "log_only", "alert_admin", "dashboard"
    created_at: float
    expires_at: Optional[float] = None
    logged_events: int = 0


class FirewallEnforcer:
    """Cross-platform firewall rule management with extended actions.

    On Windows, uses a custom WinDivert-based kernel packet filter
    (GuardianShield's own firewall) instead of Windows Defender Firewall.
    Falls back to netsh advfirewall only if WinDivert is not available.
    """

    def __init__(self, default_block_duration: int = 300):
        self.default_block_duration = default_block_duration
        self.active_rules: Dict[str, BlockRule] = {}
        self.isolation_rules: Dict[str, IsolationRule] = {}
        self.rate_limiters: Dict[str, RateLimitEntry] = {}
        self.monitors: Dict[str, MonitorEntry] = {}
        self.platform = "windows" if sys.platform == "win32" else "linux"
        self._timers: Dict[str, Timer] = {}
        self._lock = Lock()

        # --- Custom Windows packet filter (WinDivert) ---
        self._packet_filter: Optional["WindowsPacketFilter"] = None
        self._use_custom_filter = False
        if self.platform == "windows":
            self._init_custom_packet_filter()

    def _init_custom_packet_filter(self):
        """Attempt to start the custom WinDivert-based packet filter.

        If successful, all Windows block/isolate operations will go through
        our own kernel-level filter instead of Windows Defender Firewall.
        """
        try:
            pf = WindowsPacketFilter()
            if pf.is_available:
                if pf.start():
                    self._packet_filter = pf
                    self._use_custom_filter = True
                    logger.info(
                        "Using GuardianShield custom packet filter (WinDivert) "
                        "— Windows Defender Firewall will NOT be used"
                    )
                    return
            logger.warning(
                "WinDivert not available — falling back to "
                "Windows Defender Firewall (netsh advfirewall)"
            )
        except Exception as e:
            logger.warning(
                f"Custom packet filter init failed ({e}) — falling back "
                "to Windows Defender Firewall (netsh advfirewall)"
            )

    def block_ip(
        self,
        ip: str,
        duration: Optional[int] = None,
        app_name: str = "",
        reason: str = "",
    ) -> bool:
        """
        Block an IP address.

        Args:
            ip: IP address to block
            duration: Block duration in seconds (None = permanent)
            app_name: App that triggered the block
            reason: Reason for blocking (e.g., "DDoS detected")

        Returns: True if rule was applied successfully
        """
        if ip in self.active_rules:
            logger.debug(f"IP {ip} already blocked")
            return True

        # Validate IP address to prevent injection via attacker-controlled
        # packet data.  Only bare IPv4/IPv6 addresses are accepted — no
        # CIDR notation, wildcards, or embedded whitespace.
        if not (_IPV4_RE.match(ip) or _IPV6_RE.match(ip)):
            logger.warning(f"Refusing to block invalid IP: {ip!r}")
            return False

        rule_name = f"GuardianShield_Block_{ip.replace('.', '_')}"
        dur = duration or self.default_block_duration

        try:
            if self.platform == "windows":
                if self._use_custom_filter:
                    success = self._packet_filter.block_ip(ip, reason=reason)
                else:
                    success = self._block_windows(ip, rule_name)
            else:
                success = self._block_linux(ip)

            if success:
                now = time.time()
                self.active_rules[ip] = BlockRule(
                    ip=ip,
                    rule_name=rule_name,
                    created_at=now,
                    expires_at=now + dur if dur else None,
                    app_name=app_name,
                    reason=reason,
                )

                # Set auto-expire timer
                if dur:
                    timer = Timer(dur, self._expire_rule, args=[ip])
                    timer.daemon = True
                    timer.start()
                    self._timers[ip] = timer

                logger.info(f"Blocked IP {ip} for {dur}s (reason: {reason})")
                if _sec_log:
                    _sec_log.ip_blocked(ip=ip, reason=reason, duration=dur, app_name=app_name)
                return True

        except Exception as e:
            logger.error(f"Failed to block {ip}: {e}")

        return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove block rule for an IP."""
        if ip not in self.active_rules:
            return True

        rule = self.active_rules[ip]

        try:
            if self.platform == "windows":
                if self._use_custom_filter:
                    success = self._packet_filter.unblock_ip(ip)
                else:
                    success = self._unblock_windows(rule.rule_name)
            else:
                success = self._unblock_linux(ip)

            if success:
                del self.active_rules[ip]
                if ip in self._timers:
                    self._timers[ip].cancel()
                    del self._timers[ip]
                logger.info(f"Unblocked IP {ip}")
                if _sec_log:
                    _sec_log.ip_unblocked(ip=ip)
                return True

        except Exception as e:
            logger.error(f"Failed to unblock {ip}: {e}")

        return False

    def _expire_rule(self, ip: str):
        """Called when a temporary block expires."""
        logger.info(f"Block expired for IP {ip}")
        self.unblock_ip(ip)

    # ============ Windows (netsh) — fallback only ============

    def _block_windows(self, ip: str, rule_name: str) -> bool:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                "protocol=any",
            ],
            capture_output=True, text=True,
        )
        return result.returncode == 0

    def _unblock_windows(self, rule_name: str) -> bool:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ],
            capture_output=True, text=True,
        )
        return result.returncode == 0

    # ============ Linux (iptables / nftables) ============

    @staticmethod
    def _iptables_cmd() -> list:
        """Return iptables or nft command depending on what's available."""
        # Prefer nftables on modern distros
        result = subprocess.run(["which", "nft"], capture_output=True, text=True)
        if result.returncode == 0:
            return ["nft"]
        return ["iptables"]

    def _block_linux(self, ip: str) -> bool:
        # Try iptables first, fall back to nft
        result = subprocess.run(
            ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.warning(f"iptables failed ({result.stderr.strip()}), trying nft...")
            result = subprocess.run(
                ["sudo", "nft", "add", "rule", "ip", "filter", "OUTPUT",
                 f"ip daddr {ip}", "drop"],
                capture_output=True, text=True,
            )
        if result.returncode != 0:
            logger.error(f"Linux block failed for {ip}: {result.stderr.strip()}")
        return result.returncode == 0

    def _unblock_linux(self, ip: str) -> bool:
        result = subprocess.run(
            ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            result = subprocess.run(
                ["sudo", "nft", "delete", "rule", "ip", "filter", "OUTPUT",
                 f"ip daddr {ip}", "drop"],
                capture_output=True, text=True,
            )
        return result.returncode == 0

    # ============ Status ============

    def get_active_rules(self) -> list:
        """Get all active block rules."""
        now = time.time()
        return [
            {
                "ip": r.ip,
                "app_name": r.app_name,
                "reason": r.reason,
                "created_at": r.created_at,
                "expires_in": int(r.expires_at - now) if r.expires_at else None,
                "permanent": r.expires_at is None,
            }
            for r in self.active_rules.values()
        ]

    def cleanup(self):
        """Remove all active rules (called on shutdown)."""
        for ip in list(self.active_rules.keys()):
            self.unblock_ip(ip)
        for target in list(self.isolation_rules.keys()):
            self.unisolate_endpoint(target)
        for timer in self._timers.values():
            timer.cancel()
        self._timers.clear()
        self.rate_limiters.clear()
        self.monitors.clear()
        # Stop the custom packet filter if running
        if self._packet_filter is not None:
            self._packet_filter.stop()
            self._packet_filter = None
            self._use_custom_filter = False
            logger.info("Custom packet filter stopped during cleanup")

    # ============ Endpoint Isolation ============

    def isolate_endpoint(
        self,
        target_ip: str,
        scope: str = "endpoint",
        duration: Optional[int] = None,
        reason: str = "",
        allowed_ips: Optional[List[str]] = None,
    ) -> bool:
        """
        Isolate an endpoint by blocking all traffic except management IPs.

        Args:
            target_ip: IP to isolate
            scope: "endpoint" (single host) or "subnet" (block entire /24)
            duration: Isolation duration in seconds (None = permanent)
            reason: Reason for isolation
            allowed_ips: IPs still allowed to communicate (e.g., management server)

        Returns: True if isolation was applied successfully
        """
        if target_ip in self.isolation_rules:
            logger.debug(f"Endpoint {target_ip} already isolated")
            return True

        if not (_IPV4_RE.match(target_ip) or _IPV6_RE.match(target_ip)):
            logger.warning(f"Refusing to isolate invalid IP: {target_ip!r}")
            return False

        rule_name = f"GuardianShield_Isolate_{target_ip.replace('.', '_')}"
        allowed = allowed_ips or []

        try:
            if self.platform == "windows":
                if self._use_custom_filter:
                    success = self._isolate_windows_custom(
                        target_ip, scope, allowed, reason,
                    )
                else:
                    success = self._isolate_windows(target_ip, rule_name, scope, allowed)
            else:
                success = self._isolate_linux(target_ip, scope, allowed)

            if success:
                now = time.time()
                dur = duration or self.default_block_duration
                self.isolation_rules[target_ip] = IsolationRule(
                    target=target_ip,
                    scope=scope,
                    rule_name=rule_name,
                    created_at=now,
                    expires_at=now + dur if dur else None,
                    reason=reason,
                    allowed_ips=allowed,
                )

                if dur:
                    timer = Timer(dur, self._expire_isolation, args=[target_ip])
                    timer.daemon = True
                    timer.start()
                    self._timers[f"iso_{target_ip}"] = timer

                logger.info(f"Isolated endpoint {target_ip} ({scope}) for {dur}s: {reason}")
                return True

        except Exception as e:
            logger.error(f"Failed to isolate {target_ip}: {e}")

        return False

    def unisolate_endpoint(self, target_ip: str) -> bool:
        """Remove isolation for an endpoint."""
        if target_ip not in self.isolation_rules:
            return True

        rule = self.isolation_rules[target_ip]

        try:
            if self.platform == "windows":
                if self._use_custom_filter:
                    success = self._packet_filter.unisolate_endpoint(target_ip)
                    if rule.scope == "subnet":
                        parts = target_ip.split(".")
                        if len(parts) == 4:
                            self._packet_filter.unblock_subnet(
                                f"{parts[0]}.{parts[1]}.{parts[2]}."
                            )
                else:
                    success = self._unblock_windows(rule.rule_name)
                    # Also remove allow rules
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule.rule_name}_allow"],
                        capture_output=True, text=True,
                    )
            else:
                success = self._unisolate_linux(target_ip, rule.scope)

            if success:
                del self.isolation_rules[target_ip]
                timer_key = f"iso_{target_ip}"
                if timer_key in self._timers:
                    self._timers[timer_key].cancel()
                    del self._timers[timer_key]
                logger.info(f"Removed isolation for {target_ip}")
                return True

        except Exception as e:
            logger.error(f"Failed to unisolate {target_ip}: {e}")

        return False

    def _expire_isolation(self, target_ip: str):
        """Called when endpoint isolation expires."""
        logger.info(f"Isolation expired for {target_ip}")
        self.unisolate_endpoint(target_ip)

    def _isolate_windows_custom(
        self, ip: str, scope: str, allowed_ips: List[str], reason: str = "",
    ) -> bool:
        """Isolate endpoint on Windows using the custom WinDivert packet filter."""
        pf = self._packet_filter
        if scope == "subnet":
            parts = ip.split(".")
            if len(parts) == 4:
                pf.block_subnet(f"{parts[0]}.{parts[1]}.{parts[2]}.")
        pf.isolate_endpoint(ip, allowed_ips=allowed_ips, reason=reason)
        return True

    def _isolate_windows(self, ip: str, rule_name: str, scope: str, allowed_ips: List[str]) -> bool:
        """Isolate endpoint on Windows using netsh (fallback)."""
        remote_ip = ip
        if scope == "subnet":
            parts = ip.split(".")
            if len(parts) == 4:
                remote_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        # Block all outbound to/from target
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", "action=block",
             f"remoteip={remote_ip}", "protocol=any"],
            capture_output=True, text=True,
        )
        # Block inbound too
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}_in", "dir=in", "action=block",
             f"remoteip={remote_ip}", "protocol=any"],
            capture_output=True, text=True,
        )
        # Allow management IPs
        for mgmt_ip in allowed_ips:
            if _IPV4_RE.match(mgmt_ip):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}_allow", "dir=out", "action=allow",
                     f"remoteip={mgmt_ip}", "protocol=any"],
                    capture_output=True, text=True,
                )

        return result.returncode == 0

    def _isolate_linux(self, ip: str, scope: str, allowed_ips: List[str]) -> bool:
        """Isolate endpoint on Linux using iptables (with sudo)."""
        target = ip
        if scope == "subnet":
            parts = ip.split(".")
            if len(parts) == 4:
                target = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        # Allow management first (order matters in iptables)
        for mgmt_ip in allowed_ips:
            subprocess.run(
                ["sudo", "iptables", "-I", "OUTPUT", "-d", mgmt_ip, "-j", "ACCEPT"],
                capture_output=True, text=True,
            )
        # Block all traffic to target
        result = subprocess.run(
            ["sudo", "iptables", "-A", "OUTPUT", "-d", target, "-j", "DROP"],
            capture_output=True, text=True,
        )
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", target, "-j", "DROP"],
            capture_output=True, text=True,
        )
        return result.returncode == 0

    def _unisolate_linux(self, ip: str, scope: str) -> bool:
        """Remove isolation on Linux."""
        target = ip
        if scope == "subnet":
            parts = ip.split(".")
            if len(parts) == 4:
                target = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        subprocess.run(
            ["sudo", "iptables", "-D", "OUTPUT", "-d", target, "-j", "DROP"],
            capture_output=True, text=True,
        )
        result = subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", target, "-j", "DROP"],
            capture_output=True, text=True,
        )
        return result.returncode == 0

    # ============ Rate Limiting ============

    def check_rate_limit(
        self,
        key: str,
        limit: int = 100,
        window: int = 60,
        action: str = "block",
    ) -> dict:
        """
        Check if a rate limit is exceeded for a given key (e.g., IP).

        Returns:
            {"exceeded": bool, "current_count": int, "action": str}
        """
        with self._lock:
            now = time.time()

            if key not in self.rate_limiters:
                self.rate_limiters[key] = RateLimitEntry(
                    limit=limit, window=window, action=action,
                )

            entry = self.rate_limiters[key]
            # Prune timestamps outside the window
            entry.timestamps = [t for t in entry.timestamps if now - t < window]
            entry.timestamps.append(now)

            exceeded = len(entry.timestamps) > limit
            return {
                "exceeded": exceeded,
                "current_count": len(entry.timestamps),
                "limit": limit,
                "window": window,
                "action": action if exceeded else "allow",
            }

    def set_rate_limit(
        self,
        key: str,
        limit: int,
        window: int = 60,
        action: str = "block",
    ):
        """Configure a rate limit for a key."""
        with self._lock:
            self.rate_limiters[key] = RateLimitEntry(
                limit=limit, window=window, action=action,
            )
        logger.info(f"Rate limit set for {key}: {limit}/{window}s → {action}")

    # ============ Monitoring ============

    def add_monitor(
        self,
        target: str,
        mode: str = "dashboard",
        duration: Optional[int] = None,
    ):
        """Add a monitoring rule for a target."""
        now = time.time()
        self.monitors[target] = MonitorEntry(
            target=target,
            mode=mode,
            created_at=now,
            expires_at=now + duration if duration else None,
        )
        logger.info(f"Monitoring {target} in '{mode}' mode")

        if duration:
            timer = Timer(duration, self._expire_monitor, args=[target])
            timer.daemon = True
            timer.start()
            self._timers[f"mon_{target}"] = timer

    def log_monitored_event(self, target: str, event: dict):
        """Log an event for a monitored target."""
        if target in self.monitors:
            entry = self.monitors[target]
            entry.logged_events += 1
            logger.info(f"[MONITOR:{entry.mode}] {target}: {event}")
            return True
        return False

    def _expire_monitor(self, target: str):
        """Remove an expired monitor."""
        if target in self.monitors:
            entry = self.monitors[target]
            logger.info(f"Monitor expired for {target} ({entry.logged_events} events logged)")
            del self.monitors[target]

    # ============ Status ============

    def get_active_rules(self) -> list:
        """Get all active block rules."""
        now = time.time()
        return [
            {
                "ip": r.ip,
                "app_name": r.app_name,
                "reason": r.reason,
                "created_at": r.created_at,
                "expires_in": int(r.expires_at - now) if r.expires_at else None,
                "permanent": r.expires_at is None,
            }
            for r in self.active_rules.values()
        ]

    def get_extended_status(self) -> dict:
        """Get full status including isolation, rate limits, monitors, and packet filter."""
        now = time.time()
        status = {
            "block_rules": self.get_active_rules(),
            "isolation_rules": [
                {
                    "target": r.target,
                    "scope": r.scope,
                    "reason": r.reason,
                    "created_at": r.created_at,
                    "expires_in": int(r.expires_at - now) if r.expires_at else None,
                    "allowed_ips": r.allowed_ips,
                }
                for r in self.isolation_rules.values()
            ],
            "rate_limiters": {
                key: {
                    "limit": entry.limit,
                    "window": entry.window,
                    "current_count": len([
                        t for t in entry.timestamps if now - t < entry.window
                    ]),
                    "action": entry.action,
                }
                for key, entry in self.rate_limiters.items()
            },
            "monitors": [
                {
                    "target": m.target,
                    "mode": m.mode,
                    "logged_events": m.logged_events,
                    "created_at": m.created_at,
                    "expires_in": int(m.expires_at - now) if m.expires_at else None,
                }
                for m in self.monitors.values()
            ],
            "firewall_mode": (
                "custom_packet_filter"
                if self._use_custom_filter
                else ("netsh_fallback" if self.platform == "windows" else "iptables")
            ),
        }
        # Attach live packet filter stats when available
        if self._use_custom_filter and self._packet_filter is not None:
            status["packet_filter_stats"] = self._packet_filter.get_stats()
        return status
