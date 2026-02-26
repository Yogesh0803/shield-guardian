"""
Natural language policy parser.
Converts human-readable policy descriptions into structured rules.

Uses rule-based keyword extraction (no external LLM needed).
Deterministic, auditable, and works offline — ideal for security tooling.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ============ Keyword dictionaries ============

ACTION_KEYWORDS = {
    "block": ["block", "deny", "reject", "prevent", "stop", "forbid", "restrict", "disallow", "drop"],
    "unblock": ["allow", "permit", "enable", "accept", "unblock", "whitelist", "let"],
    "monitor": ["monitor", "watch", "observe", "track", "log", "record", "audit", "inspect"],
    "alert": ["alert", "notify", "warn", "flag", "report", "alarm", "escalate"],
    "isolate": ["isolate", "quarantine", "sandbox", "contain", "segregate", "disconnect"],
    "rate_limit": ["rate limit", "rate-limit", "throttle", "slow down", "limit rate", "cap requests"],
}

SEVERITY_KEYWORDS = {
    "critical": ["critical", "severe", "emergency", "urgent", "p0", "p1"],
    "high": ["high", "important", "major", "dangerous", "serious"],
    "medium": ["medium", "moderate", "normal", "standard"],
    "low": ["low", "minor", "informational", "info", "minimal"],
}

MONITOR_KEYWORDS = {
    "log_only": ["log only", "just log", "logging only", "silent"],
    "alert_admin": ["alert admin", "notify admin", "notify team", "send alert", "email alert"],
    "dashboard": ["show on dashboard", "dashboard alert", "display", "visualize"],
    "webhook": ["webhook", "send to", "push notification", "post to"],
}

PROTOCOL_KEYWORDS = {
    "TCP": ["tcp"],
    "UDP": ["udp"],
    "ICMP": ["icmp", "ping"],
}

TIME_PATTERNS = {
    r"after (\d{1,2})\s*(am|pm|AM|PM)?": "after_hour",
    r"before (\d{1,2})\s*(am|pm|AM|PM)?": "before_hour",
    r"between (\d{1,2})\s*(am|pm)?\s*(?:and|to|-)\s*(\d{1,2})\s*(am|pm)?": "time_range",
    r"business hours": "business_hours",
    r"outside business hours": "outside_business_hours",
    r"night(?:time)?|late night": "night",
}

DAY_KEYWORDS = {
    "weekday": [0, 1, 2, 3, 4],
    "weekdays": [0, 1, 2, 3, 4],
    "weekend": [5, 6],
    "weekends": [5, 6],
    "monday": [0], "tuesday": [1], "wednesday": [2],
    "thursday": [3], "friday": [4], "saturday": [5], "sunday": [6],
}

COUNTRY_KEYWORDS = {
    "china": "CN", "chinese": "CN",
    "russia": "RU", "russian": "RU",
    "north korea": "KP",
    "iran": "IR", "iranian": "IR",
    "united states": "US", "us": "US", "usa": "US", "american": "US",
    "india": "IN", "indian": "IN",
    "germany": "DE", "german": "DE",
    "uk": "GB", "united kingdom": "GB", "british": "GB",
    "japan": "JP", "japanese": "JP",
    "brazil": "BR", "brazilian": "BR",
    "france": "FR", "french": "FR",
    "australia": "AU", "australian": "AU",
}

ATTACK_KEYWORDS = {
    "DDoS": ["ddos", "distributed denial"],
    "DoS": ["dos", "denial of service"],
    "BruteForce": ["brute force", "bruteforce", "brute-force"],
    "PortScan": ["port scan", "portscan", "port-scan"],
    "WebAttack": ["web attack", "sql injection", "xss", "cross-site"],
    "Botnet": ["botnet", "bot net"],
    "Infiltration": ["infiltration", "intrusion"],
    "Phishing": ["phishing", "phish"],
    "Malware": ["malware", "virus", "trojan", "ransomware"],
}


@dataclass
class ParsedPolicy:
    purpose: str = "block"
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    ports: List[dict] = field(default_factory=list)
    app_names: List[str] = field(default_factory=list)
    time_range: Optional[dict] = None
    days_of_week: Optional[List[int]] = None
    geo_countries: Optional[List[str]] = None
    anomaly_threshold: Optional[float] = None
    attack_types: Optional[List[str]] = None
    rate_limit: Optional[int] = None
    confidence: float = 0.0
    explanation: str = ""
    # --- Extended fields for intelligent firewall actions ---
    confidence_threshold: Optional[float] = None
    severity: Optional[str] = None  # "low", "medium", "high", "critical"
    isolation_scope: Optional[str] = None  # "endpoint", "subnet", "vlan"
    isolation_targets: List[str] = field(default_factory=list)
    monitor_mode: Optional[str] = None  # "log_only", "alert_admin", "dashboard", "webhook"
    monitor_duration: Optional[int] = None  # seconds
    rate_limit_window: Optional[int] = None  # window in seconds (default 60)
    rate_limit_action: Optional[str] = None  # "block", "alert", "throttle"
    protocols: List[str] = field(default_factory=list)
    schedule: Optional[dict] = None  # recurring schedule {"days": [...], "time_range": {...}}
    auto_expire: Optional[int] = None  # auto-expire policy after N seconds


class NLPPolicyParser:
    """Parses natural language policy descriptions into structured rules."""

    def parse(self, text: str) -> ParsedPolicy:
        """
        Parse a natural language policy description.

        Examples:
            "Block Chrome from accessing Russian IPs after 10PM"
            "Allow only TCP traffic on port 443 during business hours"
            "Block any app with anomaly score above 0.8"
            "Deny all DDoS and brute force attacks"
        """
        result = ParsedPolicy()
        text_lower = text.lower().strip()
        explanations = []

        # 1. Determine action (block/allow)
        result.purpose = self._extract_action(text_lower)
        explanations.append(f"Action: {result.purpose}")

        # 2. Extract app names
        apps = self._extract_apps(text_lower)
        if apps:
            result.app_names = apps
            explanations.append(f"Apps: {', '.join(apps)}")

        # 3. Extract IPs
        ips = self._extract_ips(text)
        if ips:
            result.ips = ips
            explanations.append(f"IPs: {', '.join(ips)}")

        # 4. Extract domains
        domains = self._extract_domains(text)
        if domains:
            result.domains = domains
            explanations.append(f"Domains: {', '.join(domains)}")

        # 5. Extract ports
        ports = self._extract_ports(text_lower)
        if ports:
            result.ports = ports
            explanations.append(f"Ports: {ports}")

        # 6. Extract time conditions
        time_range, days = self._extract_time(text_lower)
        if time_range:
            result.time_range = time_range
            explanations.append(f"Time: {time_range['start']} - {time_range['end']}")
        if days:
            result.days_of_week = days
            explanations.append(f"Days: {days}")

        # 7. Extract geo countries
        countries = self._extract_countries(text_lower)
        if countries:
            result.geo_countries = countries
            explanations.append(f"Countries: {', '.join(countries)}")

        # 8. Extract anomaly threshold
        threshold = self._extract_threshold(text_lower)
        if threshold is not None:
            result.anomaly_threshold = threshold
            explanations.append(f"Anomaly threshold: {threshold}")

        # 9. Extract attack types
        attacks = self._extract_attack_types(text_lower)
        if attacks:
            result.attack_types = attacks
            explanations.append(f"Attack types: {', '.join(attacks)}")

        # 10. Extract rate limit (enhanced with window and action)
        rate, rate_window, rate_action = self._extract_rate_limit_extended(text_lower)
        if rate:
            result.rate_limit = rate
            result.rate_limit_window = rate_window or 60
            result.rate_limit_action = rate_action or "block"
            explanations.append(f"Rate limit: {rate}/{result.rate_limit_window}s → {result.rate_limit_action}")

        # 11. Extract confidence threshold
        conf_threshold = self._extract_confidence_threshold(text_lower)
        if conf_threshold is not None:
            result.confidence_threshold = conf_threshold
            explanations.append(f"Confidence threshold: {conf_threshold}")

        # 12. Extract severity
        severity = self._extract_severity(text_lower)
        if severity:
            result.severity = severity
            explanations.append(f"Severity: {severity}")

        # 13. Extract isolation targets
        isolation_scope, isolation_targets = self._extract_isolation(text_lower, text)
        if isolation_scope:
            result.isolation_scope = isolation_scope
            result.isolation_targets = isolation_targets
            explanations.append(f"Isolate: {isolation_scope} {', '.join(isolation_targets)}")

        # 14. Extract monitoring mode
        monitor_mode, monitor_duration = self._extract_monitor(text_lower)
        if monitor_mode:
            result.monitor_mode = monitor_mode
            if monitor_duration:
                result.monitor_duration = monitor_duration
            explanations.append(f"Monitor: {monitor_mode}")

        # 15. Extract protocols
        protocols = self._extract_protocols(text_lower)
        if protocols:
            result.protocols = protocols
            explanations.append(f"Protocols: {', '.join(protocols)}")

        # 16. Build recurring schedule from time + days
        if result.time_range and result.days_of_week:
            result.schedule = {
                "days": result.days_of_week,
                "time_range": result.time_range,
            }
            explanations.append("Schedule: recurring")

        # 17. Extract auto-expire duration
        auto_expire = self._extract_auto_expire(text_lower)
        if auto_expire:
            result.auto_expire = auto_expire
            explanations.append(f"Auto-expire: {auto_expire}s")

        # Calculate confidence based on how many fields were extracted
        fields_found = sum([
            bool(result.app_names), bool(result.ips), bool(result.domains),
            bool(result.ports), bool(result.time_range), bool(result.geo_countries),
            bool(result.anomaly_threshold is not None), bool(result.attack_types),
            bool(result.rate_limit), bool(result.confidence_threshold is not None),
            bool(result.severity), bool(result.isolation_scope),
            bool(result.monitor_mode), bool(result.protocols),
            bool(result.auto_expire),
        ])
        result.confidence = min(0.5 + fields_found * 0.08, 1.0)
        result.explanation = "; ".join(explanations)

        return result

    def _extract_action(self, text: str) -> str:
        for action, keywords in ACTION_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    return action
        return "block"  # default

    def _extract_apps(self, text: str) -> List[str]:
        apps = []
        known_apps = [
            "chrome", "firefox", "brave", "edge", "safari", "opera",
            "python", "node", "java", "curl", "wget",
            "slack", "discord", "teams", "zoom", "spotify",
            "vscode", "code", "terminal", "powershell", "cmd",
        ]
        for app in known_apps:
            if app in text:
                apps.append(app)
        return apps

    def _extract_ips(self, text: str) -> List[str]:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        return re.findall(ip_pattern, text)

    def _extract_domains(self, text: str) -> List[str]:
        domain_pattern = r'\b(?:\*\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b'
        candidates = re.findall(domain_pattern, text)
        # Filter out common words that match the pattern
        skip = {"e.g", "i.e", "etc.com"}
        return [d for d in candidates if d not in skip]

    def _extract_ports(self, text: str) -> List[dict]:
        ports = []
        # "port 80", "port 443", "ports 80 and 443"
        port_pattern = r'port[s]?\s+(\d+(?:\s*(?:,|and)\s*\d+)*)'
        matches = re.findall(port_pattern, text)
        for match in matches:
            for port_str in re.findall(r'\d+', match):
                port = int(port_str)
                if 1 <= port <= 65535:
                    # Check for protocol near the port mention
                    protocols = []
                    for proto, kws in PROTOCOL_KEYWORDS.items():
                        for kw in kws:
                            if kw in text:
                                protocols.append(proto)
                    ports.append({"port": port, "protocol": protocols or ["TCP", "UDP"]})
        return ports

    def _extract_time(self, text: str) -> Tuple[Optional[dict], Optional[List[int]]]:
        time_range = None
        days = None

        if "business hours" in text:
            if "outside" in text:
                time_range = {"start": "18:00", "end": "09:00"}
            else:
                time_range = {"start": "09:00", "end": "18:00"}

        if "night" in text or "late night" in text:
            time_range = {"start": "22:00", "end": "06:00"}

        # "between 9am and 5pm"
        between_match = re.search(
            r'between\s+(\d{1,2})\s*(am|pm)?\s*(?:and|to|-)\s*(\d{1,2})\s*(am|pm)?',
            text,
        )
        if between_match:
            h1 = int(between_match.group(1))
            p1 = between_match.group(2)
            if p1 and p1.lower() == "pm" and h1 < 12:
                h1 += 12
            elif p1 and p1.lower() == "am" and h1 == 12:
                h1 = 0
            h2 = int(between_match.group(3))
            p2 = between_match.group(4)
            if p2 and p2.lower() == "pm" and h2 < 12:
                h2 += 12
            elif p2 and p2.lower() == "am" and h2 == 12:
                h2 = 0
            time_range = {"start": f"{h1:02d}:00", "end": f"{h2:02d}:00"}

        # "after 10pm"
        after_match = re.search(r'after (\d{1,2})\s*(am|pm)?', text)
        if after_match and not between_match:
            hour = int(after_match.group(1))
            period = after_match.group(2)
            if period and period.lower() == "pm" and hour < 12:
                hour += 12
            time_range = {"start": f"{hour:02d}:00", "end": "23:59"}

        # "before 6am"
        before_match = re.search(r'before (\d{1,2})\s*(am|pm)?', text)
        if before_match and not between_match:
            hour = int(before_match.group(1))
            period = before_match.group(2)
            if period and period.lower() == "pm" and hour < 12:
                hour += 12
            time_range = {"start": "00:00", "end": f"{hour:02d}:00"}

        # Days of week
        for day_kw, day_nums in DAY_KEYWORDS.items():
            if day_kw in text:
                days = day_nums
                break

        return time_range, days

    def _extract_countries(self, text: str) -> List[str]:
        countries = []
        for name, code in COUNTRY_KEYWORDS.items():
            # Use word-boundary matching to prevent false positives
            # (e.g., "us" inside "business", "in" inside "during")
            if re.search(r'\b' + re.escape(name) + r'\b', text):
                if code not in countries:
                    countries.append(code)
        return countries

    def _extract_threshold(self, text: str) -> Optional[float]:
        patterns = [
            r'anomaly\s*(?:score)?\s*(?:above|over|greater than|>)\s*(\d*\.?\d+)',
            r'threshold\s*(?:of|:)?\s*(\d*\.?\d+)',
            r'score\s*>\s*(\d*\.?\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return float(match.group(1))
        return None

    def _extract_attack_types(self, text: str) -> List[str]:
        attacks = []
        for attack_type, keywords in ATTACK_KEYWORDS.items():
            for kw in keywords:
                # Word-boundary match prevents "dos" matching inside "ddos"
                if re.search(r'\b' + re.escape(kw) + r'\b', text):
                    if attack_type not in attacks:
                        attacks.append(attack_type)
                    break
        return attacks

    def _extract_rate_limit(self, text: str) -> Optional[int]:
        patterns = [
            r'(?:rate|request)\s*(?:limit)?\s*(?:>|above|over|exceeds?)\s*(\d+)',
            r'more than (\d+)\s*(?:requests?|connections?)\s*(?:per|/)\s*(?:min|minute)',
            r'(\d+)\s*(?:requests?|connections?)\s*(?:per|/)\s*(?:min|minute)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return int(match.group(1))
        return None

    def _extract_rate_limit_extended(self, text: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        """Extract rate limit value, window (seconds), and overflow action."""
        rate = self._extract_rate_limit(text)
        if rate is None:
            return None, None, None

        # Extract window – "per second", "per 5 minutes", "per hour"
        window = 60  # default: per minute
        window_match = re.search(
            r'(?:per|/)\s*(?:(\d+)\s*)?'
            r'(second|sec|minute|min|hour|hr)s?',
            text,
        )
        if window_match:
            multiplier = int(window_match.group(1)) if window_match.group(1) else 1
            unit = window_match.group(2)
            if unit in ("second", "sec"):
                window = multiplier
            elif unit in ("minute", "min"):
                window = multiplier * 60
            elif unit in ("hour", "hr"):
                window = multiplier * 3600

        # Extract overflow action
        action = "block"  # default
        if "throttle" in text or "slow" in text:
            action = "throttle"
        elif "alert" in text or "warn" in text or "notify" in text:
            action = "alert"

        return rate, window, action

    def _extract_confidence_threshold(self, text: str) -> Optional[float]:
        """Extract ML confidence threshold."""
        patterns = [
            r'confidence\s*(?:above|over|greater than|>|threshold)?\s*(\d*\.?\d+)',
            r'(?:ml|model)\s*confidence\s*(?:>|above|over)?\s*(\d*\.?\d+)',
            r'(?:at least|minimum)\s*(\d*\.?\d+)\s*confidence',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                val = float(match.group(1))
                # Normalize to 0-1 if given as percentage
                return val / 100.0 if val > 1.0 else val
        return None

    def _extract_severity(self, text: str) -> Optional[str]:
        """Extract severity level."""
        for severity, keywords in SEVERITY_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    return severity
        return None

    def _extract_isolation(self, text_lower: str, text_original: str) -> Tuple[Optional[str], List[str]]:
        """Extract isolation scope and targets."""
        scope = None
        targets = []

        # Check for isolation keywords
        isolation_mentioned = any(
            kw in text_lower
            for kw in ["isolate", "quarantine", "sandbox", "contain", "segregate", "disconnect"]
        )
        if not isolation_mentioned:
            return None, []

        # Determine scope
        if any(w in text_lower for w in ["subnet", "network", "vlan", "segment"]):
            scope = "subnet"
        elif any(w in text_lower for w in ["endpoint", "device", "host", "machine", "computer"]):
            scope = "endpoint"
        else:
            scope = "endpoint"  # default

        # Extract IP targets for isolation
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        targets = re.findall(ip_pattern, text_original)

        # Extract named endpoints
        endpoint_match = re.search(r'(?:isolate|quarantine|disconnect)\s+(?:endpoint|device|host)?\s*["\']?([\w.-]+)["\']?', text_lower)
        if endpoint_match and not targets:
            targets = [endpoint_match.group(1)]

        return scope, targets

    def _extract_monitor(self, text: str) -> Tuple[Optional[str], Optional[int]]:
        """Extract monitoring mode and duration."""
        mode = None
        duration = None

        for monitor_type, keywords in MONITOR_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    mode = monitor_type
                    break
            if mode:
                break

        # If action is "monitor" or "alert" but no specific mode, default to dashboard
        if mode is None and any(w in text for w in ["monitor", "watch", "observe", "track"]):
            mode = "dashboard"

        # Extract duration: "for 24 hours", "for 30 minutes"
        dur_match = re.search(r'for\s+(\d+)\s*(second|sec|minute|min|hour|hr|day)s?', text)
        if dur_match:
            value = int(dur_match.group(1))
            unit = dur_match.group(2)
            if unit in ("second", "sec"):
                duration = value
            elif unit in ("minute", "min"):
                duration = value * 60
            elif unit in ("hour", "hr"):
                duration = value * 3600
            elif unit == "day":
                duration = value * 86400

        return mode, duration

    def _extract_protocols(self, text: str) -> List[str]:
        """Extract protocol specifications."""
        protocols = []
        for proto, keywords in PROTOCOL_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    protocols.append(proto)
                    break
        # Additional protocols
        if "http" in text and "https" not in text:
            protocols.append("HTTP")
        if "https" in text:
            protocols.append("HTTPS")
        if "dns" in text:
            protocols.append("DNS")
        if "ssh" in text:
            protocols.append("SSH")
        if "ftp" in text:
            protocols.append("FTP")
        if "smtp" in text:
            protocols.append("SMTP")
        return protocols

    def _extract_auto_expire(self, text: str) -> Optional[int]:
        """Extract auto-expiry duration in seconds."""
        patterns = [
            r'(?:expire|expires|auto[- ]?expire|timeout|ttl)\s*(?:after|in)?\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?',
            r'(?:temporary|temp)\s*(?:for)?\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?',
            r'(?:for|lasting)\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?\s*(?:only|then)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                value = int(match.group(1))
                unit = match.group(2)
                if unit in ("second", "sec"):
                    return value
                elif unit in ("minute", "min"):
                    return value * 60
                elif unit in ("hour", "hr"):
                    return value * 3600
                elif unit == "day":
                    return value * 86400
        return None
