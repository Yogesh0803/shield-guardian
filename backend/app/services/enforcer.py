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
from typing import List, Optional, Dict, Set

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
        "manifest.googlevideo.com", "redirector.googlevideo.com",
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


class PolicyEnforcer:
    """Enforces policies by modifying hosts file and firewall rules."""

    def __init__(self):
        self.blocked_domains: Dict[str, List[str]] = {}  # policy_id -> [domains]
        self.blocked_ips: Dict[str, List[str]] = {}  # policy_id -> [ips]
        self._is_admin = is_admin()
        if self._is_admin:
            logger.info("PolicyEnforcer: running with ADMIN privileges")
        else:
            logger.warning(
                "PolicyEnforcer: NOT running as admin! "
                "Start the backend as Administrator for blocking to work."
            )

    def sync_from_db(self, db_session):
        """Load all active 'block' policies from the DB and sync hosts file.

        Can be called multiple times — always re-syncs to match DB state.
        """
        try:
            from app.models.policy import Policy

            policies = (
                db_session.query(Policy)
                .filter(
                    Policy.is_active == True,
                    Policy.purpose == "block",
                )
                .all()
            )
            self.blocked_domains.clear()
            self.blocked_ips.clear()
            for p in policies:
                if p.conditions and isinstance(p.conditions, dict):
                    domains = p.conditions.get("domains", [])
                    if domains:
                        self.blocked_domains[p.id] = domains
                    ips = p.conditions.get("ips", [])
                    if ips:
                        self.blocked_ips[p.id] = ips
            self._rewrite_hosts_file()
            logger.info(
                f"Synced from DB: {len(self.blocked_domains)} domain policies, "
                f"{len(self.blocked_ips)} IP policies"
            )
        except Exception as e:
            logger.error(f"Failed to sync policies from DB: {e}")

    def enforce_policy(self, policy_id: str, purpose: str, conditions: dict) -> dict:
        """Enforce a policy. Returns status dict."""
        if not conditions:
            return {"status": "no_conditions", "enforced": False}

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

        enforced = any(r.get("success") for r in results.values())
        return {
            "status": "enforced" if enforced else "failed",
            "enforced": enforced,
            "details": results,
        }

    def unenforce_policy(self, policy_id: str) -> dict:
        """Remove all enforcement for a policy (when deleted or toggled off)."""
        results = {}

        # Remove blocked domains
        if policy_id in self.blocked_domains:
            domains = self.blocked_domains.pop(policy_id)
            success = self._unblock_domains_list(domains)
            results["domains"] = {"unblocked": domains, "success": success}

        # Remove blocked IPs from in-memory state
        if policy_id in self.blocked_ips:
            self.blocked_ips.pop(policy_id)

        # ALWAYS try to delete the firewall rule by policy_id
        # (handles case where backend restarted and in-memory state was lost)
        rule_name = f"GuardianShield_{policy_id[:8]}"
        fw_success = self._delete_firewall_rule(rule_name)
        results["firewall"] = {"rule": rule_name, "deleted": fw_success}

        self._rewrite_hosts_file()
        return {"status": "unenforced", "details": results}

    # ============ DNS resolution for app-level blocking ============

    def _resolve_domain_ips(self, domains: List[str]) -> List[str]:
        """Resolve domains to IPs using public DNS (bypasses local hosts file)."""
        resolved: Set[str] = set()
        all_variants: Set[str] = set()

        for domain in domains:
            all_variants.add(domain)
            all_variants.add(f"www.{domain}")
            for extra in EXTRA_SUBDOMAINS.get(domain, []):
                all_variants.add(extra)

        for d in all_variants:
            try:
                result = subprocess.run(
                    ["nslookup", d, "8.8.8.8"],
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
                            if not ip.startswith("127.") and ip != "8.8.8.8":
                                resolved.add(ip)
            except (subprocess.TimeoutExpired, OSError):
                pass

        logger.info(
            f"Resolved {len(resolved)} IPs from {len(domains)} domains: {resolved}"
        )
        return list(resolved)

    # ============ Domain blocking via hosts file ============

    def _block_domains(self, policy_id: str, domains: List[str]) -> bool:
        """Block domains by adding them to hosts file."""
        self.blocked_domains[policy_id] = domains
        return self._rewrite_hosts_file()

    def _unblock_domains_list(self, domains: List[str]) -> bool:
        """Remove specific domains from all policies' blocked lists."""
        for pid in list(self.blocked_domains.keys()):
            self.blocked_domains[pid] = [
                d for d in self.blocked_domains[pid] if d not in domains
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
        """Flush system DNS cache."""
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
        """Block IPs using Windows Firewall."""
        self.blocked_ips[policy_id] = ips
        if not ips:
            return True

        rule_name = f"GuardianShield_{policy_id[:8]}"
        ip_list = ",".join(ips)

        if sys.platform == "win32":
            # Try direct netsh first (works if backend runs as admin)
            cmd = f'netsh advfirewall firewall add rule name={rule_name} dir=out action=block remoteip={ip_list} protocol=any'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                logger.info(f"Firewall rule '{rule_name}' created blocking {len(ips)} IPs")
                return True

            # Fallback: try elevated PowerShell
            logger.warning(f"Direct netsh failed ({result.stderr.strip()}), trying elevated...")
            return self._run_elevated(cmd)
        else:
            success = True
            for ip in ips:
                r = subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True, timeout=10,
                )
                if r.returncode != 0:
                    success = False
            return success

    def _delete_firewall_rule(self, rule_name: str) -> bool:
        """Delete a specific Windows Firewall rule by name."""
        if sys.platform != "win32":
            return True
        cmd = f'netsh advfirewall firewall delete rule name={rule_name}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info(f"Deleted firewall rule: {rule_name}")
            return True
        # Try elevated if direct fails
        logger.warning(f"Direct delete failed for {rule_name}, trying elevated...")
        return self._run_elevated(cmd)

    def _unblock_ips_list(self, ips: List[str]) -> bool:
        """Remove firewall rules for blocked IPs."""
        if not ips:
            return True

        if sys.platform == "win32":
            # Build commands to delete all GuardianShield rules
            cmds = []
            for pid in list(self.blocked_ips.keys()):
                rule_name = f"GuardianShield_{pid[:8]}"
                cmds.append(f'netsh advfirewall firewall delete rule name={rule_name}')
            if not cmds:
                return True
            return self._run_elevated(" & ".join(cmds))
        else:
            success = True
            for ip in ips:
                r = subprocess.run(
                    ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True, timeout=10,
                )
                if r.returncode != 0:
                    success = False
            return success

    def get_status(self) -> dict:
        """Get current enforcement status."""
        all_domains: Set[str] = set()
        for domains in self.blocked_domains.values():
            all_domains.update(domains)
        all_ips: Set[str] = set()
        for ips in self.blocked_ips.values():
            all_ips.update(ips)
        return {
            "is_admin": self._is_admin,
            "blocked_domains": sorted(all_domains),
            "blocked_ips": sorted(all_ips),
            "total_policies_enforced": len(self.blocked_domains) + len(self.blocked_ips),
        }


# Singleton instance
enforcer = PolicyEnforcer()
