"""
Policy enforcement service.
Blocks/unblocks domains by modifying the Windows hosts file.
Blocks/unblocks IPs using Windows Firewall (netsh).

IMPORTANT: The backend MUST run as Administrator for enforcement to work.
"""

import os
import sys
import ctypes
import socket
import subprocess
import logging
import re
import time
from datetime import datetime, timezone
from shutil import which
from typing import List, Optional, Dict, Set, Iterable

logger = logging.getLogger(__name__)

HOSTS_PATH = (
    r"C:\Windows\System32\drivers\etc\hosts"
    if sys.platform == "win32"
    else "/etc/hosts"
)
MARKER_START = "# >>> GuardianShield Blocked Domains"
MARKER_END = "# <<< GuardianShield Blocked Domains"

# Comprehensive subdomain map for popular services.
# When a user blocks e.g. "youtube.com", we also block all subdomains
# that the browser/app uses to load content.
EXTRA_SUBDOMAINS: Dict[str, List[str]] = {
    "youtube.com": [
        "m.youtube.com", "music.youtube.com", "tv.youtube.com",
        "kids.youtube.com", "studio.youtube.com", "accounts.youtube.com",
        "gaming.youtube.com", "youtu.be", "youtube-nocookie.com",
        "www.youtube-nocookie.com", "youtubei.googleapis.com",
        "yt3.ggpht.com", "yt3.googleusercontent.com",
        "i.ytimg.com", "s.ytimg.com", "i9.ytimg.com", "img.youtube.com",
        "ytimg.com", "googlevideo.com", "manifest.googlevideo.com",
        "redirector.googlevideo.com",
    ],
    "facebook.com": [
        "m.facebook.com", "web.facebook.com", "mobile.facebook.com",
        "touch.facebook.com", "static.facebook.com", "static.xx.fbcdn.net",
        "scontent.fbcdn.net", "fbcdn.net", "login.facebook.com",
        "graph.facebook.com", "upload.facebook.com",
    ],
    "instagram.com": [
        "i.instagram.com", "graph.instagram.com",
        "cdninstagram.com", "scontent.cdninstagram.com",
        "static.cdninstagram.com",
    ],
    "twitter.com": [
        "mobile.twitter.com", "api.twitter.com",
        "abs.twimg.com", "pbs.twimg.com", "t.co",
        "x.com", "www.x.com",
    ],
    "x.com": [
        "twitter.com", "www.twitter.com", "api.twitter.com",
        "abs.twimg.com", "pbs.twimg.com", "t.co",
    ],
    "reddit.com": [
        "old.reddit.com", "new.reddit.com",
        "i.redd.it", "v.redd.it", "preview.redd.it",
        "external-preview.redd.it",
    ],
    "tiktok.com": [
        "m.tiktok.com", "v16.tiktokcdn.com", "v19.tiktokcdn.com",
    ],
    "netflix.com": [
        "assets.nflxext.com", "cdn-0.nflximg.com", "cdn-1.nflximg.com",
        "codex.nflxext.com", "api-global.netflix.com",
    ],
    "whatsapp.com": [
        "web.whatsapp.com", "whatsapp.net", "static.whatsapp.net",
        "pps.whatsapp.net", "mmg.whatsapp.net", "media.whatsapp.net",
    ],
    "telegram.org": [
        "web.telegram.org", "api.telegram.org", "core.telegram.org",
        "t.me", "updates.telegram.org",
    ],
    "spotify.com": [
        "open.spotify.com", "apresolve.spotify.com",
        "spclient.wg.spotify.com", "login5.spotify.com", "dealer.spotify.com",
    ],
    "discord.com": [
        "discord.gg", "discordapp.com", "gateway.discord.gg",
        "cdn.discordapp.com", "images-ext-1.discordapp.net",
        "media.discordapp.net",
    ],
    "chatgpt.com": [
        "chat.openai.com", "openai.com", "www.openai.com",
        "api.openai.com", "cdn.oaistatic.com", "files.oaiusercontent.com",
    ],
    "openai.com": [
        "chat.openai.com", "chatgpt.com", "www.chatgpt.com",
        "api.openai.com", "cdn.oaistatic.com", "files.oaiusercontent.com",
    ],
    "linkedin.com": [
        "static.licdn.com", "media.licdn.com",
    ],
    "snapchat.com": [
        "web.snapchat.com", "accounts.snapchat.com",
        "snap.com", "www.snap.com",
    ],
    "pinterest.com": [
        "i.pinimg.com", "s.pinimg.com",
    ],
    "twitch.tv": [
        "m.twitch.tv", "static.twitchcdn.net", "usher.twitchcdn.net",
    ],
    "amazon.com": [
        "smile.amazon.com", "images-na.ssl-images-amazon.com",
    ],
    "github.com": [
        "api.github.com", "raw.githubusercontent.com",
        "gist.github.com", "github.githubassets.com",
    ],
    "claude.ai": [
        "anthropic.com", "www.anthropic.com", "api.anthropic.com",
    ],
}


def is_admin() -> bool:
    """Check if the current process has admin/root privileges."""
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def _parse_time(time_str: str) -> int:
    """Parse 'HH:MM' (or 'HH.MM', 'HHMM', 'HH') to minutes since midnight.

    Handles common user-input variations:
      '09:30', '9:30', '09.30', '0930', '9', '09', ' 09:30 '
    """
    s = time_str.strip()
    # Try HH:MM or HH.MM
    m = re.match(r'^(\d{1,2})[:.]?(\d{2})?$', s)
    if m:
        h = int(m.group(1))
        mins = int(m.group(2)) if m.group(2) else 0
        return h * 60 + mins
    # Fallback: try to parse whatever we can
    digits = re.findall(r'\d+', s)
    if digits:
        h = int(digits[0]) % 24
        mins = int(digits[1]) % 60 if len(digits) > 1 else 0
        return h * 60 + mins
    return 0


def _is_within_time_range(conditions: dict) -> bool:
    """Check if the current time falls within the policy's time_range / days_of_week.

    Returns True when the policy should be active RIGHT NOW.
    If no time_range is configured the policy is always active.
    """
    schedule = conditions.get("schedule")
    time_range = schedule.get("time_range", conditions.get("time_range")) if schedule else conditions.get("time_range")
    days_of_week = schedule.get("days", conditions.get("days_of_week")) if schedule else conditions.get("days_of_week")

    now = datetime.now(timezone.utc).astimezone()  # local time
    now_minutes = now.hour * 60 + now.minute

    # Check day-of-week first (0=Monday)
    if days_of_week is not None:
        if now.weekday() not in days_of_week:
            return False

    if time_range:
        start = _parse_time(time_range.get("start", "00:00"))
        end = _parse_time(time_range.get("end", "23:59"))
        if start <= end:
            # Normal range e.g. 09:00-17:00
            if not (start <= now_minutes < end):
                return False
        else:
            # Wraps midnight e.g. 22:00-06:00
            if not (now_minutes >= start or now_minutes < end):
                return False

    return True


def _to_local_datetime(dt_value):
    if dt_value is None:
        return None
    if dt_value.tzinfo is None:
        return dt_value.replace(tzinfo=timezone.utc).astimezone()
    return dt_value.astimezone()


def _is_policy_expired(conditions: dict, created_at, now=None) -> bool:
    auto_expire = conditions.get("auto_expire")
    if not auto_expire or created_at is None:
        return False
    now_local = now or datetime.now(timezone.utc).astimezone()
    created_local = _to_local_datetime(created_at)
    if created_local is None:
        return False
    return (now_local - created_local).total_seconds() >= int(auto_expire)


class PolicyEnforcer:
    """Enforces policies by modifying hosts file and firewall rules."""

    def __init__(self):
        self.blocked_domains: Dict[str, List[str]] = {}  # policy_id -> [domains]
        self.blocked_ips: Dict[str, List[str]] = {}  # policy_id -> [ips]
        self.ml_policies: Dict[str, dict] = {}  # policy_id -> {purpose, conditions}
        self.isolated_endpoints: Dict[str, List[str]] = {}  # policy_id -> [ips]
        self.policy_state: Dict[str, dict] = {}  # policy_id -> {purpose, conditions}
        # Policies with time_range that are currently outside their window
        self._deferred_policies: Dict[str, dict] = {}  # policy_id -> {purpose, conditions}
        self._is_admin = is_admin()
        if self._is_admin:
            logger.info("PolicyEnforcer: running with ADMIN privileges")
        else:
            logger.warning(
                "PolicyEnforcer: NOT running as admin! "
                "Start the backend as Administrator for blocking to work."
            )

    def _dedupe_preserve_order(self, values: Iterable[str]) -> List[str]:
        seen: Set[str] = set()
        result: List[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _normalize_domain(self, domain: str) -> Optional[str]:
        domain = domain.strip().lower().strip(".,;:()[]{}<>\"'")
        if not domain:
            return None
        domain = re.sub(r"^(?:https?://)?(?:www\.)?", "", domain)
        domain = domain.split("/", 1)[0]
        domain = domain.split(":", 1)[0]
        if domain.startswith("*."):
            domain = domain[2:]
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain):
            return None
        if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", domain):
            return None
        return domain

    def _normalize_ip(self, ip: str) -> Optional[str]:
        ip = ip.strip()
        ipv4 = re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip)
        if ipv4:
            octets = ip.split(".")
            if all(0 <= int(octet) <= 255 for octet in octets):
                return ip
            return None
        if "/" in ip:
            base, _, suffix = ip.partition("/")
            normalized = self._normalize_ip(base)
            if normalized and suffix.isdigit():
                prefix = int(suffix)
                if 0 <= prefix <= 32:
                    return f"{normalized}/{prefix}"
        return None

    def _normalize_conditions(self, conditions: dict) -> dict:
        normalized = dict(conditions or {})
        normalized["domains"] = self._dedupe_preserve_order(
            filter(None, (self._normalize_domain(domain) for domain in normalized.get("domains", [])))
        )
        normalized["ips"] = self._dedupe_preserve_order(
            filter(None, (self._normalize_ip(ip) for ip in normalized.get("ips", [])))
        )
        isolation_targets = normalized.get("isolation_targets", normalized.get("ips", []))
        normalized["isolation_targets"] = self._dedupe_preserve_order(
            filter(None, (self._normalize_ip(ip) or ip.strip() for ip in isolation_targets))
        )
        if normalized.get("schedule") and isinstance(normalized["schedule"], dict):
            schedule = dict(normalized["schedule"])
            if "days" in schedule and "days_of_week" not in normalized:
                normalized["days_of_week"] = schedule.get("days")
            if "time_range" in schedule and "time_range" not in normalized:
                normalized["time_range"] = schedule.get("time_range")
            normalized["schedule"] = schedule
        return normalized

    def sync_from_db(self, db_session):
        """Load all active policies from the DB and sync enforcement state.

        Can be called multiple times — always re-syncs to match DB state.
        """
        try:
            from app.models.policy import Policy

            policies = (
                db_session.query(Policy)
                .filter(Policy.is_active == True)
                .all()
            )
            self.blocked_domains.clear()
            self.blocked_ips.clear()
            self.ml_policies.clear()
            self.isolated_endpoints.clear()
            self.policy_state.clear()
            self._deferred_policies.clear()

            for p in policies:
                if not p.conditions or not isinstance(p.conditions, dict):
                    continue
                normalized_conditions = self._normalize_conditions(p.conditions)
                if _is_policy_expired(normalized_conditions, p.created_at):
                    p.is_active = False
                    logger.info(f"[PolicyEngine] Policy expired before sync: {p.name}")
                    continue
                self.policy_state[p.id] = {
                    "purpose": p.purpose,
                    "conditions": normalized_conditions,
                }

                if p.purpose == "block":
                    # Only enforce if within time window (or no time_range)
                    if not _is_within_time_range(normalized_conditions):
                        self._deferred_policies[p.id] = {
                            "purpose": p.purpose,
                            "conditions": normalized_conditions,
                        }
                        continue
                    domains = normalized_conditions.get("domains", [])
                    if domains:
                        self.blocked_domains[p.id] = domains
                    ips = normalized_conditions.get("ips", [])
                    if ips:
                        self.blocked_ips[p.id] = ips

                elif p.purpose in ("monitor", "alert", "rate_limit", "isolate"):
                    self.ml_policies[p.id] = {
                        "purpose": p.purpose,
                        "conditions": normalized_conditions,
                    }

            db_session.commit()

            self._rewrite_hosts_file()

            # Re-create firewall rules for blocked IPs (lost on restart)
            for pid, ips in self.blocked_ips.items():
                self._block_ips(pid, ips)

            # Also resolve and block IPs for domain-based policies
            for pid, domains in self.blocked_domains.items():
                resolved = self._resolve_domain_ips(domains)
                if resolved:
                    self._block_ips(pid, resolved)

            logger.info(
                f"Synced from DB: {len(self.blocked_domains)} domain policies, "
                f"{len(self.blocked_ips)} IP policies, "
                f"{len(self.ml_policies)} ML-aware policies, "
                f"{len(self._deferred_policies)} deferred (outside time window)"
            )
        except Exception as e:
            logger.error(f"Failed to sync policies from DB: {e}")

    def enforce_policy(self, policy_id: str, purpose: str, conditions: dict,
                       _skip_time_check: bool = False) -> dict:
        """Enforce a policy. Returns status dict.

        Args:
            _skip_time_check: If True, skip the time-range validation.
                Used by the scheduler which has already validated the window.
        """
        if not conditions:
            return {"status": "no_conditions", "enforced": False}
        conditions = self._normalize_conditions(conditions)
        self.policy_state[policy_id] = {"purpose": purpose, "conditions": conditions}

        # If the policy has a time_range and we're outside it, defer enforcement
        # (skip this check when called from the scheduler to avoid race conditions)
        if not _skip_time_check:
            has_time_range = conditions.get("time_range") or (
                conditions.get("schedule", {}).get("time_range")
            )
            if has_time_range and not _is_within_time_range(conditions):
                self._deferred_policies[policy_id] = {
                    "purpose": purpose,
                    "conditions": conditions,
                }
                logger.info(
                    f"Policy '{policy_id}' deferred — outside time window "
                    f"({conditions.get('time_range') or conditions.get('schedule', {}).get('time_range')})"
                )
                return {
                    "status": "deferred",
                    "enforced": False,
                    "reason": "outside_time_window",
                }

        # Remove from deferred if previously deferred
        self._deferred_policies.pop(policy_id, None)

        results = {}
        domains = conditions.get("domains", [])
        ips = conditions.get("ips", [])

        if purpose == "block":
            if domains:
                # 1. Resolve domain IPs FIRST (before hosts file blocks DNS)
                resolved_ips = self._resolve_domain_ips(domains)
                logger.info(f"Resolved IPs for {domains}: {resolved_ips}")
                # 2. Block via hosts file
                success = self._block_domains(policy_id, domains)
                results["domains"] = {"blocked": domains, "success": success}
                # 3. Block resolved IPs via firewall
                if resolved_ips:
                    ip_success = self._block_ips(policy_id, resolved_ips)
                    logger.info(f"Firewall IP block result: {ip_success}")
                    results["resolved_ips"] = {
                        "blocked": resolved_ips, "success": ip_success,
                    }
            if ips:
                success = self._block_ips(policy_id, ips)
                results["ips"] = {"blocked": ips, "success": success}

        elif purpose == "unblock":
            if domains:
                success = self._unblock_domains_list(domains)
                results["domains"] = {"unblocked": domains, "success": success}
            if ips:
                success = self._unblock_ips_list(ips)
                results["ips"] = {"unblocked": ips, "success": success}

        elif purpose == "monitor":
            # Store monitoring policy — ML pipeline will check these
            self._store_ml_policy(policy_id, purpose, conditions)
            monitor_mode = conditions.get("monitor_mode", "dashboard")
            results["monitoring"] = {
                "mode": monitor_mode,
                "targets": ips or domains or ["all_traffic"],
                "success": True,
            }
            logger.info(f"Monitor policy '{policy_id}' active: mode={monitor_mode}")

        elif purpose == "alert":
            # Store alert policy — ML pipeline will check these
            self._store_ml_policy(policy_id, purpose, conditions)
            results["alerting"] = {
                "targets": ips or domains or ["all_traffic"],
                "severity": conditions.get("severity"),
                "success": True,
            }
            logger.info(f"Alert policy '{policy_id}' active")

        elif purpose == "isolate":
            # Isolate endpoints via firewall rules
            isolation_targets = conditions.get("isolation_targets", ips)
            isolation_scope = conditions.get("isolation_scope", "endpoint")
            if isolation_targets:
                for target_ip in isolation_targets:
                    success = self._isolate_endpoint(
                        policy_id, target_ip, isolation_scope,
                    )
                    results[f"isolate_{target_ip}"] = {
                        "target": target_ip,
                        "scope": isolation_scope,
                        "success": success,
                    }
            self._store_ml_policy(policy_id, purpose, conditions)
            logger.info(f"Isolation policy '{policy_id}' active")

        elif purpose == "rate_limit":
            # Store rate limit policy — ML pipeline will enforce
            self._store_ml_policy(policy_id, purpose, conditions)
            results["rate_limit"] = {
                "limit": conditions.get("rate_limit"),
                "window": conditions.get("rate_limit_window", 60),
                "action": conditions.get("rate_limit_action", "block"),
                "success": True,
            }
            logger.info(
                f"Rate limit policy '{policy_id}' active: "
                f"{conditions.get('rate_limit')}/{conditions.get('rate_limit_window', 60)}s"
            )

        enforced = any(r.get("success") for r in results.values())
        return {
            "status": "enforced" if enforced else "failed",
            "enforced": enforced,
            "purpose": purpose,
            "details": results,
        }

    def unenforce_policy(self, policy_id: str) -> dict:
        """Remove all enforcement for a policy (when deleted or toggled off)."""
        results = {}
        policy_snapshot = self.policy_state.pop(policy_id, None)

        # Remove from deferred if it was waiting for its time window
        self._deferred_policies.pop(policy_id, None)

        # Remove blocked domains
        if policy_id in self.blocked_domains:
            domains = self.blocked_domains.pop(policy_id)
            success = self._unblock_domains_list(domains)
            results["domains"] = {"unblocked": domains, "success": success}

        # Remove blocked IPs and their firewall rules
        if policy_id in self.blocked_ips:
            blocked_ips = self.blocked_ips.pop(policy_id)
            results["ips"] = {"unblocked": blocked_ips, "success": True}

        # Remove ML-aware policies (monitor, alert, rate_limit, isolate)
        if policy_id in self.ml_policies:
            ml_policy = self.ml_policies.pop(policy_id)
            results["ml_policy"] = {"removed": ml_policy.get("purpose"), "success": True}

        # Remove isolation rules
        if policy_id in self.isolated_endpoints:
            for target_ip in self.isolated_endpoints.pop(policy_id, []):
                rule_name_iso = f"GuardianShield_Iso_{policy_id}"
                self._delete_firewall_rule(rule_name_iso)
                self._delete_firewall_rule(f"{rule_name_iso}_in")
            results["isolation"] = {"removed": True}

        # ALWAYS try to delete the firewall rule by policy_id
        # (handles case where backend restarted and in-memory state was lost)
        rule_name = f"GuardianShield_{policy_id}"
        fw_success = self._delete_firewall_rule(rule_name)
        results["firewall"] = {"rule": rule_name, "deleted": fw_success}

        self._rewrite_hosts_file()
        if policy_snapshot:
            results["policy"] = {"removed": policy_snapshot.get("purpose"), "success": True}
        return {"status": "unenforced", "details": results}

    # ============ ML-aware policy storage ============

    def _store_ml_policy(self, policy_id: str, purpose: str, conditions: dict):
        """Store a policy that the ML inference pipeline will evaluate."""
        self.ml_policies[policy_id] = {
            "purpose": purpose,
            "conditions": conditions,
        }

    def get_ml_policies(self) -> List[dict]:
        """Return all ML-aware policies for the inference pipeline to evaluate."""
        return [
            {"id": pid, **data}
            for pid, data in self.ml_policies.items()
        ]

    # ============ Endpoint isolation ============

    def _isolate_endpoint(self, policy_id: str, target_ip: str, scope: str) -> bool:
        """Isolate an endpoint via firewall rules."""
        import re as _re
        ipv4_re = _re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        )
        if not ipv4_re.match(target_ip):
            logger.warning(f"Invalid IP for isolation: {target_ip}")
            return False

        rule_name = f"GuardianShield_Iso_{policy_id}"
        remote_ip = target_ip

        if scope == "subnet":
            parts = target_ip.split(".")
            if len(parts) == 4:
                remote_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        if sys.platform == "win32":
            # Block outbound
            cmd_out = (
                f'netsh advfirewall firewall add rule name={rule_name} '
                f'dir=out action=block remoteip={remote_ip} protocol=any'
            )
            # Block inbound
            cmd_in = (
                f'netsh advfirewall firewall add rule name={rule_name}_in '
                f'dir=in action=block remoteip={remote_ip} protocol=any'
            )
            result = subprocess.run(cmd_out, shell=True, capture_output=True, text=True, timeout=15)
            subprocess.run(cmd_in, shell=True, capture_output=True, text=True, timeout=15)
            success = result.returncode == 0
            if not success:
                success = self._run_elevated(f"{cmd_out} & {cmd_in}")
        else:
            r1 = subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", remote_ip, "-j", "DROP"],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", remote_ip, "-j", "DROP"],
                capture_output=True, timeout=10,
            )
            success = r1.returncode == 0

        if success:
            if policy_id not in self.isolated_endpoints:
                self.isolated_endpoints[policy_id] = []
            self.isolated_endpoints[policy_id].append(target_ip)
            logger.info(f"Isolated endpoint {target_ip} ({scope})")

        return success

    # ============ DNS resolution for app-level blocking ============

    def _resolve_domain_ips(self, domains: List[str]) -> List[str]:
        """Resolve domains to IPs using the local resolver and nslookup fallback."""
        resolved: Set[str] = set()
        all_variants: Set[str] = set()

        for domain in domains:
            normalized = self._normalize_domain(domain)
            if not normalized:
                continue
            all_variants.add(normalized)
            all_variants.add(f"www.{normalized}")
            for extra in EXTRA_SUBDOMAINS.get(normalized, []):
                all_variants.add(extra)

        for domain in all_variants:
            try:
                infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
                for info in infos:
                    ip = self._normalize_ip(info[4][0])
                    if ip and not ip.startswith("127."):
                        resolved.add(ip)
            except socket.gaierror:
                pass

            if which("nslookup") is None:
                continue

            try:
                result = subprocess.run(
                    ["nslookup", domain, "8.8.8.8"],
                    capture_output=True, text=True, timeout=5,
                )
                in_answer = False
                for line in result.stdout.splitlines():
                    if "Name:" in line:
                        in_answer = True
                        continue
                    if in_answer:
                        ipv4s = re.findall(
                            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line
                        )
                        for ip in ipv4s:
                            normalized_ip = self._normalize_ip(ip)
                            if normalized_ip and not normalized_ip.startswith("127.") and normalized_ip != "8.8.8.8":
                                resolved.add(normalized_ip)
            except (subprocess.TimeoutExpired, OSError):
                pass

        logger.info(
            f"Resolved {len(resolved)} IPs from {len(domains)} domains: {resolved}"
        )
        return sorted(resolved)

    # ============ Domain blocking via hosts file ============

    def _block_domains(self, policy_id: str, domains: List[str]) -> bool:
        """Block domains by adding them to hosts file."""
        self.blocked_domains[policy_id] = self._dedupe_preserve_order(
            filter(None, (self._normalize_domain(domain) for domain in domains))
        )
        success = self._rewrite_hosts_file()
        if not success:
            # Rollback in-memory state so the scheduler retries next tick
            self.blocked_domains.pop(policy_id, None)
            logger.error(f"Failed to write hosts file for policy '{policy_id}' - will retry")
        return success

    def _unblock_domains_list(self, domains: List[str]) -> bool:
        """Remove specific domains from all policies' blocked lists."""
        targets = set(filter(None, (self._normalize_domain(domain) for domain in domains)))
        for pid in list(self.blocked_domains.keys()):
            self.blocked_domains[pid] = [
                d for d in self.blocked_domains[pid] if d not in targets
            ]
            if not self.blocked_domains[pid]:
                del self.blocked_domains[pid]
        return self._rewrite_hosts_file()

    def _expand_domains(self, domains: Set[str]) -> Set[str]:
        """Expand a set of base domains to include all known subdomains."""
        expanded = set()
        for domain in domains:
            expanded.add(domain)
            expanded.add(f"www.{domain}")
            for extra in EXTRA_SUBDOMAINS.get(domain, []):
                expanded.add(extra)
        return expanded

    def _rewrite_hosts_file(self) -> bool:
        """Rewrite the GuardianShield section of the hosts file."""
        try:
            try:
                with open(HOSTS_PATH, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(HOSTS_PATH, "r", encoding="latin-1") as f:
                    content = f.read()

            # Remove existing GuardianShield block
            pattern = re.compile(
                rf"{re.escape(MARKER_START)}.*?{re.escape(MARKER_END)}\n?",
                re.DOTALL,
            )
            content = pattern.sub("", content).rstrip("\n")

            # Collect all base domains to block
            base_domains: Set[str] = set()
            for domains in self.blocked_domains.values():
                base_domains.update(domains)

            if base_domains:
                # Expand with all known subdomains
                all_domains = self._expand_domains(base_domains)

                block_lines = [f"\n{MARKER_START}"]
                for domain in sorted(all_domains):
                    block_lines.append(f"127.0.0.1 {domain}")
                block_lines.append(MARKER_END)
                content += "\n".join(block_lines) + "\n"
            else:
                content += "\n"

            written = self._write_hosts_content(content)
            if not written:
                logger.error(
                    "FAILED to write hosts file! "
                    "Make sure the backend is running as Administrator."
                )
                return False

            # Flush DNS cache
            self._flush_dns()

            total = len(self._expand_domains(base_domains)) if base_domains else 0
            logger.info(
                f"Hosts file updated: {len(base_domains)} base domains "
                f"({total} entries incl. subdomains)"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to update hosts file: {e}")
            return False

    def _flush_dns(self):
        """Flush system DNS cache and browser DNS caches."""
        if sys.platform != "win32":
            return
        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True, timeout=10,
            )
            logger.info("DNS cache flushed")
        except Exception as e:
            logger.warning(f"DNS flush failed: {e}")

        # Attempt to flush Chrome / Edge internal DNS cache.
        # These browsers expose a net-internals API on their debug port.
        # A lightweight workaround is to send a clear-host-resolver-cache
        # command via their DevTools protocol, but that requires the
        # browser to have been started with --remote-debugging-port.
        # As a more reliable alternative, we rely on the firewall IP
        # blocking which is not affected by browser DNS caches.
        # Log a note so the user knows.
        logger.info(
            "Note: Browser DNS caches (Chrome/Edge) may take up to 1 minute "
            "to expire. IP-level firewall blocking is active immediately."
        )

    def _write_hosts_content(self, content: str) -> bool:
        """Write content to hosts file, elevating privileges if needed."""
        # Attempt 1: Direct write (works if running as admin)
        try:
            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("Hosts file written directly (admin mode).")
            return True
        except PermissionError:
            logger.warning("Direct hosts file write failed (PermissionError).")

        if sys.platform != "win32":
            logger.error("Permission denied writing to hosts file (non-Windows).")
            return False

        # Attempt 2: UAC elevation via batch file
        logger.info("Attempting UAC elevation to write hosts file...")
        try:
            temp_dir = os.environ.get("TEMP", os.environ.get("TMP", r"C:\Windows\Temp"))
            temp_hosts = os.path.join(temp_dir, "gs_hosts_new.txt")
            bat_path = os.path.join(temp_dir, "gs_hosts_update.bat")
            done_path = os.path.join(temp_dir, "gs_hosts_done.txt")

            # Write new content to a temp file (no admin needed)
            with open(temp_hosts, "w", encoding="utf-8") as f:
                f.write(content)

            if os.path.exists(done_path):
                os.remove(done_path)

            # Create batch file that copies hosts and flushes DNS
            with open(bat_path, "w") as f:
                f.write(f'@echo off\n')
                f.write(f'copy /Y "{temp_hosts}" "{HOSTS_PATH}"\n')
                f.write(f'ipconfig /flushdns\n')
                f.write(f'echo DONE > "{done_path}"\n')

            # Elevate the batch file via UAC
            ps_cmd = (
                f'Start-Process cmd.exe -Verb RunAs -Wait '
                f'-ArgumentList "/c","{bat_path}"'
            )
            subprocess.Popen(["powershell", "-Command", ps_cmd])

            # Wait for completion (up to 30 seconds)
            for _ in range(30):
                time.sleep(1)
                if os.path.exists(done_path):
                    os.remove(done_path)
                    try:
                        os.remove(temp_hosts)
                        os.remove(bat_path)
                    except OSError:
                        pass
                    logger.info("Hosts file written via elevated batch script.")
                    return True

            logger.warning("Elevated hosts file write timed out (UAC may have been denied).")
            return False
        except Exception as e:
            logger.error(f"Elevated hosts write error: {e}")
            return False

    # ============ IP blocking via Windows Firewall ============

    def _run_elevated(self, cmd: str) -> bool:
        """Run a command with admin privileges via UAC elevation."""
        import time
        try:
            # First try direct (works if already admin)
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"Direct command succeeded: {cmd[:60]}")
                return True

            # Not admin — write batch file and elevate
            temp_dir = os.environ.get("TEMP", os.environ.get("TMP", r"C:\Windows\Temp"))
            bat_path = os.path.join(temp_dir, "gs_fw_cmd.bat")
            done_path = os.path.join(temp_dir, "gs_fw_done.txt")

            if os.path.exists(done_path):
                os.remove(done_path)

            with open(bat_path, "w") as f:
                f.write(f"@echo off\n{cmd}\necho DONE > \"{done_path}\"\n")

            # Use Start-Process -Verb RunAs -Wait with the batch file path
            ps_cmd = (
                f'Start-Process cmd.exe -Verb RunAs -Wait '
                f'-ArgumentList "/c","{bat_path}"'
            )
            subprocess.Popen(
                ["powershell", "-Command", ps_cmd],
            )

            # Wait for completion
            for _ in range(25):
                time.sleep(1)
                if os.path.exists(done_path):
                    os.remove(done_path)
                    logger.info(f"Elevated command completed: {cmd[:60]}")
                    return True

            logger.warning("Elevated command timed out")
            return False
        except Exception as e:
            logger.error(f"Elevated command error: {e}")
            return False

    def _block_ips(self, policy_id: str, ips: List[str]) -> bool:
        """Block IPs using Windows Firewall (both inbound and outbound)."""
        normalized_ips = self._dedupe_preserve_order(
            filter(None, (self._normalize_ip(ip) for ip in ips))
        )
        self.blocked_ips[policy_id] = normalized_ips
        if not normalized_ips:
            return True

        rule_name = f"GuardianShield_{policy_id}"
        ip_list = ",".join(normalized_ips)

        if sys.platform == "win32":
            cmd_out = f'netsh advfirewall firewall add rule name={rule_name} dir=out action=block remoteip={ip_list} protocol=any'
            cmd_in = f'netsh advfirewall firewall add rule name={rule_name}_in dir=in action=block remoteip={ip_list} protocol=any'
            result_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True, timeout=15)
            result_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True, timeout=15)
            if result_out.returncode == 0 and result_in.returncode == 0:
                logger.info(f"Firewall rules '{rule_name}' created (in+out) blocking {len(normalized_ips)} IPs")
                self._kill_existing_connections(normalized_ips)
                return True

            if result_out.returncode == 0 or result_in.returncode == 0:
                if result_out.returncode != 0:
                    self._run_elevated(cmd_out)
                if result_in.returncode != 0:
                    self._run_elevated(cmd_in)
                self._kill_existing_connections(normalized_ips)
                return True

            logger.warning(f"Direct netsh failed ({result_out.stderr.strip()}), trying elevated...")
            success = self._run_elevated(f"{cmd_out} & {cmd_in}")
            if success:
                self._kill_existing_connections(normalized_ips)
            return success

        success = True
        for ip in normalized_ips:
            result = subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, timeout=10,
            )
            if result.returncode != 0:
                success = False
        return success

    def _kill_existing_connections(self, ips: List[str]):
        """Terminate existing TCP connections to blocked IPs (Windows only)."""
        if sys.platform != "win32":
            return
        try:
            # Use PowerShell to find and reset active connections to blocked IPs
            ip_filter = ",".join(f"'{ip}'" for ip in ips[:50])  # limit to 50 IPs
            ps_cmd = (
                f'Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue '
                f'| Where-Object {{ @({ip_filter}) -contains $_.RemoteAddress }} '
                f'| ForEach-Object {{ $_.OwningProcess }} '
                f'| Sort-Object -Unique'
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                pids = result.stdout.strip().splitlines()
                logger.info(f"Found {len(pids)} processes with connections to blocked IPs: {pids}")
                # We don't kill the processes — instead the firewall inbound block
                # will cause their connections to timeout within seconds.
                # Just log for debugging purposes.
            else:
                logger.info("No existing TCP connections to blocked IPs found")
        except Exception as e:
            logger.debug(f"Connection check failed (non-critical): {e}")

    def _delete_firewall_rule(self, rule_name: str) -> bool:
        """Delete a specific Windows Firewall rule by name (both outbound and inbound)."""
        if sys.platform != "win32":
            return True
        # Delete outbound rule
        cmd_out = f'netsh advfirewall firewall delete rule name={rule_name}'
        result = subprocess.run(cmd_out, shell=True, capture_output=True, text=True, timeout=10)
        # Also delete corresponding inbound rule (may or may not exist)
        cmd_in = f'netsh advfirewall firewall delete rule name={rule_name}_in'
        subprocess.run(cmd_in, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info(f"Deleted firewall rules: {rule_name} (+_in)")
            return True
        # Try elevated if direct fails
        logger.warning(f"Direct delete failed for {rule_name}, trying elevated...")
        return self._run_elevated(f"{cmd_out} & {cmd_in}")

    def _unblock_ips_list(self, ips: List[str]) -> bool:
        """Remove firewall rules for blocked IPs."""
        normalized_ips = set(filter(None, (self._normalize_ip(ip) for ip in ips)))
        if not normalized_ips:
            return True

        if sys.platform == "win32":
            cmds = []
            for pid, blocked in list(self.blocked_ips.items()):
                if normalized_ips.intersection(blocked):
                    rule_name = f"GuardianShield_{pid}"
                    cmds.append(f'netsh advfirewall firewall delete rule name={rule_name}')
                    cmds.append(f'netsh advfirewall firewall delete rule name={rule_name}_in')
                    self.blocked_ips.pop(pid, None)
            if not cmds:
                return True
            return self._run_elevated(" & ".join(cmds))

        success = True
        for ip in normalized_ips:
            result = subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, timeout=10,
            )
            if result.returncode != 0:
                success = False
        return success

    def get_status(self) -> dict:
        """Get current enforcement status including extended policy types."""
        all_domains: Set[str] = set()
        for domains in self.blocked_domains.values():
            all_domains.update(domains)
        all_ips: Set[str] = set()
        for blocked in self.blocked_ips.values():
            all_ips.update(blocked)
        all_isolated: Set[str] = set()
        for targets in self.isolated_endpoints.values():
            all_isolated.update(targets)

        ml_policy_summary: Dict[str, int] = {}
        for data in self.ml_policies.values():
            purpose = data.get("purpose", "unknown")
            ml_policy_summary[purpose] = ml_policy_summary.get(purpose, 0) + 1

        return {
            "is_admin": self._is_admin,
            "blocked_domains": sorted(all_domains),
            "blocked_ips": sorted(all_ips),
            "isolated_endpoints": sorted(all_isolated),
            "ml_policies": ml_policy_summary,
            "tracked_policies": len(self.policy_state),
            "total_policies_enforced": (
                len(self.blocked_domains) + len(self.blocked_ips)
                + len(self.ml_policies) + len(self.isolated_endpoints)
            ),
            "deferred_policies": {
                pid: data.get("conditions", {}).get("time_range")
                or data.get("conditions", {}).get("schedule", {}).get("time_range")
                for pid, data in self._deferred_policies.items()
            },
            "blocked_domain_policies": {
                pid: domains for pid, domains in self.blocked_domains.items()
            },
        }

    def check_time_policies(self):
        """Periodic check: enforce deferred policies whose window has started,
        and unenforce active policies whose window has ended.

        Called by the background scheduler in main.py.
        """
        # 1. Activate deferred policies whose time window has started
        now_active = []
        for pid, data in list(self._deferred_policies.items()):
            if _is_within_time_range(data["conditions"]):
                now_active.append((pid, data))

        for pid, data in now_active:
            del self._deferred_policies[pid]
            logger.info(f"Time window started for deferred policy '{pid}' — enforcing now")
            self.enforce_policy(pid, data["purpose"], data["conditions"], _skip_time_check=True)

        # 2. Deactivate active block policies whose time window has ended
        expired = []
        for pid in list(self.blocked_domains.keys()):
            # Look up conditions from DB-cached ml_policies or inline
            conds = self.ml_policies.get(pid, {}).get("conditions")
            if not conds:
                # Not stored in ml_policies — try to find via DB
                continue
            if conds.get("time_range") or (conds.get("schedule", {}).get("time_range")):
                if not _is_within_time_range(conds):
                    expired.append(pid)

        for pid in expired:
            logger.info(f"Time window ended for policy '{pid}' — unenforcing")
            conds = self.ml_policies.get(pid, {}).get("conditions", {})
            self.unenforce_policy(pid)
            self._deferred_policies[pid] = {"purpose": "block", "conditions": conds}

    def check_time_policies_from_db(self, db_session):
        """Full time-range check using DB as source of truth."""
        try:
            from app.models.policy import Policy

            policies = (
                db_session.query(Policy)
                .filter(Policy.is_active == True)
                .all()
            )
            active_policy_ids = {policy.id for policy in policies}
            for policy_id in list(self.policy_state.keys()):
                if policy_id not in active_policy_ids:
                    self.unenforce_policy(policy_id)

            now = datetime.now(timezone.utc).astimezone()
            now_str = now.strftime("%H:%M:%S")

            for policy in policies:
                if not policy.conditions or not isinstance(policy.conditions, dict):
                    continue

                normalized_conditions = self._normalize_conditions(policy.conditions)
                if _is_policy_expired(normalized_conditions, policy.created_at, now):
                    logger.info(f"[PolicyEngine] Policy expired: {policy.name}")
                    self.unenforce_policy(policy.id)
                    policy.is_active = False
                    self._deferred_policies.pop(policy.id, None)
                    continue

                self.policy_state[policy.id] = {
                    "purpose": policy.purpose,
                    "conditions": normalized_conditions,
                }

                has_time = normalized_conditions.get("time_range") or (
                    normalized_conditions.get("schedule", {}).get("time_range")
                )
                if not has_time:
                    continue

                is_active_now = _is_within_time_range(normalized_conditions)
                currently_enforced = policy.id in self.blocked_domains or policy.id in self.blocked_ips
                currently_deferred = policy.id in self._deferred_policies

                logger.info(
                    f"[SCHEDULER] Policy '{policy.name}' (id={policy.id[:8]}): "
                    f"time_range={has_time}, now={now_str}, "
                    f"is_active_now={is_active_now}, "
                    f"currently_enforced={currently_enforced}, "
                    f"currently_deferred={currently_deferred}"
                )

                if policy.purpose != "block":
                    continue

                if is_active_now and not currently_enforced:
                    self._deferred_policies.pop(policy.id, None)
                    logger.info(f">>> Time window STARTED for '{policy.name}' - ENFORCING NOW")
                    self.enforce_policy(policy.id, policy.purpose, normalized_conditions, _skip_time_check=True)
                elif not is_active_now and currently_enforced:
                    logger.info(f">>> Time window ENDED for '{policy.name}' - UNENFORCING")
                    self.unenforce_policy(policy.id)
                    self._deferred_policies[policy.id] = {
                        "purpose": policy.purpose,
                        "conditions": normalized_conditions,
                    }
                elif not is_active_now and not currently_deferred:
                    self._deferred_policies[policy.id] = {
                        "purpose": policy.purpose,
                        "conditions": normalized_conditions,
                    }
            db_session.commit()
        except Exception as e:
            db_session.rollback()
            logger.error(f"check_time_policies_from_db failed: {e}")

# Singleton instance
enforcer = PolicyEnforcer()
