"""
Natural language policy parser.
Converts human-readable policy descriptions into structured rules.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ACTION_KEYWORDS = {
    "rate_limit": ["rate limit", "rate-limit", "throttle", "slow down", "limit rate", "cap requests"],
    "isolate": ["isolate", "quarantine", "sandbox", "contain", "segregate", "disconnect"],
    "monitor": ["monitor", "watch", "observe", "track", "log", "record", "audit", "inspect"],
    "alert": ["alert", "notify", "warn", "flag", "report", "alarm", "escalate"],
    "unblock": ["allow", "permit", "enable", "accept", "unblock", "whitelist", "let"],
    "block": ["block", "deny", "reject", "prevent", "stop", "forbid", "restrict", "disallow", "drop"],
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

DAY_KEYWORDS = {
    "weekday": [0, 1, 2, 3, 4],
    "weekdays": [0, 1, 2, 3, 4],
    "weekend": [5, 6],
    "weekends": [5, 6],
    "monday": [0],
    "tuesday": [1],
    "wednesday": [2],
    "thursday": [3],
    "friday": [4],
    "saturday": [5],
    "sunday": [6],
}

COUNTRY_KEYWORDS = {
    "china": "CN",
    "chinese": "CN",
    "russia": "RU",
    "russian": "RU",
    "north korea": "KP",
    "iran": "IR",
    "iranian": "IR",
    "united states": "US",
    "us": "US",
    "usa": "US",
    "american": "US",
    "india": "IN",
    "indian": "IN",
    "germany": "DE",
    "german": "DE",
    "uk": "GB",
    "united kingdom": "GB",
    "british": "GB",
    "japan": "JP",
    "japanese": "JP",
    "brazil": "BR",
    "brazilian": "BR",
    "france": "FR",
    "french": "FR",
    "australia": "AU",
    "australian": "AU",
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

KNOWN_SERVICE_DOMAINS = {
    "google": ["google.com", "www.google.com"],
    "youtube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"],
    "facebook": ["facebook.com", "fbcdn.net"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "twitter": ["twitter.com", "x.com", "twimg.com", "t.co"],
    "x": ["x.com", "twitter.com", "twimg.com", "t.co"],
    "reddit": ["reddit.com", "redd.it", "redd.it", "redditmedia.com"],
    "tiktok": ["tiktok.com", "tiktokcdn.com"],
    "netflix": ["netflix.com", "nflximg.com", "nflxvideo.net"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "telegram": ["telegram.org", "t.me"],
    "spotify": ["spotify.com", "scdn.co"],
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
    "chatgpt": ["chatgpt.com", "openai.com", "chat.openai.com"],
    "openai": ["openai.com", "chatgpt.com", "chat.openai.com"],
    "linkedin": ["linkedin.com", "licdn.com"],
    "snapchat": ["snapchat.com", "snap.com"],
    "pinterest": ["pinterest.com", "pinimg.com"],
    "twitch": ["twitch.tv", "twitchcdn.net"],
    "amazon": ["amazon.com", "amazonvideo.com"],
    "github": ["github.com", "githubusercontent.com"],
    "claude": ["claude.ai", "anthropic.com"],
    "gemini": ["gemini.google.com"],
    "copilot": ["copilot.microsoft.com"],
    "perplexity": ["perplexity.ai"],
}

KNOWN_APPS = [
    "chrome",
    "firefox",
    "brave",
    "edge",
    "safari",
    "opera",
    "python",
    "node",
    "java",
    "curl",
    "wget",
    "slack",
    "discord",
    "teams",
    "zoom",
    "spotify",
    "vscode",
    "code",
    "terminal",
    "powershell",
    "cmd",
]

DOMAIN_PATTERN = re.compile(
    r"\b(?:https?://)?(?:www\.)?(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


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
    confidence_threshold: Optional[float] = None
    severity: Optional[str] = None
    isolation_scope: Optional[str] = None
    isolation_targets: List[str] = field(default_factory=list)
    monitor_mode: Optional[str] = None
    monitor_duration: Optional[int] = None
    rate_limit_window: Optional[int] = None
    rate_limit_action: Optional[str] = None
    protocols: List[str] = field(default_factory=list)
    schedule: Optional[dict] = None
    auto_expire: Optional[int] = None


class NLPPolicyParser:
    def parse(self, text: str) -> ParsedPolicy:
        result = ParsedPolicy()
        normalized = text.strip()
        text_lower = normalized.lower()
        explanations: List[str] = []

        result.purpose = self._extract_action(text_lower)
        explanations.append(f"Action: {result.purpose}")

        result.app_names = self._extract_apps(text_lower)
        if result.app_names:
            explanations.append(f"Apps: {', '.join(result.app_names)}")

        result.ips = self._extract_ips(normalized)
        if result.ips:
            explanations.append(f"IPs: {', '.join(result.ips)}")

        result.domains = self._extract_domains(normalized, text_lower)
        if result.domains:
            explanations.append(f"Domains: {', '.join(result.domains)}")

        result.ports = self._extract_ports(text_lower)
        if result.ports:
            explanations.append(f"Ports: {', '.join(str(item['port']) for item in result.ports)}")

        time_range, days = self._extract_time(text_lower)
        if time_range:
            result.time_range = time_range
            explanations.append(f"Time: {time_range['start']} - {time_range['end']}")
        if days is not None:
            result.days_of_week = days
            explanations.append(f"Days: {days}")

        result.geo_countries = self._extract_countries(text_lower) or None
        if result.geo_countries:
            explanations.append(f"Countries: {', '.join(result.geo_countries)}")

        result.anomaly_threshold = self._extract_threshold(text_lower)
        if result.anomaly_threshold is not None:
            explanations.append(f"Anomaly threshold: {result.anomaly_threshold}")

        result.attack_types = self._extract_attack_types(text_lower) or None
        if result.attack_types:
            explanations.append(f"Attack types: {', '.join(result.attack_types)}")

        rate, rate_window, rate_action = self._extract_rate_limit_extended(text_lower)
        if rate is not None:
            result.rate_limit = rate
            result.rate_limit_window = rate_window or 60
            result.rate_limit_action = rate_action or "block"
            explanations.append(
                f"Rate limit: {rate}/{result.rate_limit_window}s -> {result.rate_limit_action}"
            )

        result.confidence_threshold = self._extract_confidence_threshold(text_lower)
        if result.confidence_threshold is not None:
            explanations.append(f"Confidence threshold: {result.confidence_threshold}")

        result.severity = self._extract_severity(text_lower)
        if result.severity:
            explanations.append(f"Severity: {result.severity}")

        isolation_scope, isolation_targets = self._extract_isolation(text_lower, normalized)
        if isolation_scope:
            result.isolation_scope = isolation_scope
            result.isolation_targets = isolation_targets
            explanations.append(
                f"Isolate: {isolation_scope} {', '.join(isolation_targets) if isolation_targets else 'target'}"
            )

        monitor_mode, monitor_duration = self._extract_monitor(text_lower)
        if monitor_mode:
            result.monitor_mode = monitor_mode
            result.monitor_duration = monitor_duration
            explanations.append(f"Monitor: {monitor_mode}")

        result.protocols = self._extract_protocols(text_lower)
        if result.protocols:
            explanations.append(f"Protocols: {', '.join(result.protocols)}")

        if result.time_range and result.days_of_week is not None:
            result.schedule = {"days": result.days_of_week, "time_range": result.time_range}
            explanations.append("Schedule: recurring")

        result.auto_expire = self._extract_auto_expire(text_lower)
        if result.auto_expire:
            explanations.append(f"Auto-expire: {result.auto_expire}s")

        fields_found = sum(
            [
                bool(result.app_names),
                bool(result.ips),
                bool(result.domains),
                bool(result.ports),
                bool(result.time_range),
                bool(result.geo_countries),
                result.anomaly_threshold is not None,
                bool(result.attack_types),
                result.rate_limit is not None,
                result.confidence_threshold is not None,
                bool(result.severity),
                bool(result.isolation_scope),
                bool(result.monitor_mode),
                bool(result.protocols),
                bool(result.auto_expire),
            ]
        )
        result.confidence = min(0.45 + fields_found * 0.08, 0.99)
        result.explanation = "; ".join(explanations)
        return result

    def _extract_action(self, text: str) -> str:
        for action, keywords in ACTION_KEYWORDS.items():
            for keyword in keywords:
                if re.search(rf"\b{re.escape(keyword)}\b", text):
                    return action
        return "block"

    def _extract_apps(self, text: str) -> List[str]:
        return [app for app in KNOWN_APPS if re.search(rf"\b{re.escape(app)}\b", text)]

    def _extract_ips(self, text: str) -> List[str]:
        return self._dedupe(IP_PATTERN.findall(text))

    def _extract_domains(self, text: str, text_lower: str) -> List[str]:
        domains: List[str] = []

        for service, service_domains in KNOWN_SERVICE_DOMAINS.items():
            if re.search(rf"\b{re.escape(service)}\b", text_lower):
                domains.extend(service_domains)

        for candidate in DOMAIN_PATTERN.findall(text):
            domain = self._normalize_domain(candidate)
            if domain:
                domains.append(domain)

        return self._dedupe(domains)

    def _extract_ports(self, text: str) -> List[dict]:
        ports: List[dict] = []
        port_pattern = r"port[s]?\s+(\d+(?:\s*(?:,|and)\s*\d+)*)"
        matches = re.findall(port_pattern, text)
        for match in matches:
            for port_str in re.findall(r"\d+", match):
                port = int(port_str)
                if not (1 <= port <= 65535):
                    continue
                protocols = [
                    proto
                    for proto, keywords in PROTOCOL_KEYWORDS.items()
                    if any(re.search(rf"\b{re.escape(keyword)}\b", text) for keyword in keywords)
                ]
                ports.append({"port": port, "protocol": protocols or ["TCP", "UDP"]})
        return ports

    def _extract_time(self, text: str) -> Tuple[Optional[dict], Optional[List[int]]]:
        time_range: Optional[dict] = None
        days: Optional[List[int]] = None

        if "outside business hours" in text:
            time_range = {"start": "18:00", "end": "09:00"}
        elif "business hours" in text:
            time_range = {"start": "09:00", "end": "18:00"}
        elif "night" in text or "late night" in text:
            time_range = {"start": "22:00", "end": "06:00"}

        range_patterns = [
            r"between\s+([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)\s*(?:and|to|-)\s*([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)",
            r"from\s+([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)\s*(?:to|-|until|till)\s*([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)",
            r"([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)\s*(?:to|-|until|till)\s*([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)",
        ]
        for pattern in range_patterns:
            match = re.search(pattern, text)
            if match:
                start = self._parse_time_token(match.group(1))
                end = self._parse_time_token(match.group(2))
                if start and end:
                    time_range = {"start": start, "end": end}
                    break

        after_match = re.search(r"after\s+([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)", text)
        if after_match and time_range is None:
            start = self._parse_time_token(after_match.group(1))
            if start:
                time_range = {"start": start, "end": "23:59"}

        before_match = re.search(r"before\s+([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)", text)
        if before_match and time_range is None:
            end = self._parse_time_token(before_match.group(1))
            if end:
                time_range = {"start": "00:00", "end": end}

        until_match = re.search(r"until\s+([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)", text)
        if until_match and time_range is None:
            end = self._parse_time_token(until_match.group(1))
            if end:
                time_range = {"start": "00:00", "end": end}

        for day_keyword, day_numbers in DAY_KEYWORDS.items():
            if re.search(rf"\b{re.escape(day_keyword)}\b", text):
                days = day_numbers
                break

        return time_range, days

    def _extract_countries(self, text: str) -> List[str]:
        countries: List[str] = []
        for name, code in COUNTRY_KEYWORDS.items():
            if re.search(rf"\b{re.escape(name)}\b", text) and code not in countries:
                countries.append(code)
        return countries

    def _extract_threshold(self, text: str) -> Optional[float]:
        patterns = [
            r"anomaly\s*(?:score)?\s*(?:above|over|greater than|>)\s*(\d*\.?\d+)",
            r"threshold\s*(?:of|:)?\s*(\d*\.?\d+)",
            r"score\s*>\s*(\d*\.?\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return float(match.group(1))
        return None

    def _extract_attack_types(self, text: str) -> List[str]:
        attacks: List[str] = []
        for attack_type, keywords in ATTACK_KEYWORDS.items():
            if any(re.search(rf"\b{re.escape(keyword)}\b", text) for keyword in keywords):
                attacks.append(attack_type)
        return attacks

    def _extract_rate_limit(self, text: str) -> Optional[int]:
        patterns = [
            r"(?:rate|request)\s*(?:limit)?\s*(?:>|above|over|exceeds?)\s*(\d+)",
            r"more than (\d+)\s*(?:requests?|connections?)\s*(?:per|/)",
            r"(\d+)\s*(?:requests?|connections?)\s*(?:per|/)",
            r"limit\s*(?:to)?\s*(\d+)\s*(?:requests?|connections?)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return int(match.group(1))
        return None

    def _extract_rate_limit_extended(self, text: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        rate = self._extract_rate_limit(text)
        if rate is None:
            return None, None, None

        window = 60
        window_match = re.search(
            r"(?:per|/)\s*(?:(\d+)\s*)?(second|sec|minute|min|hour|hr)s?",
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

        action = "block"
        if "throttle" in text or "slow" in text:
            action = "throttle"
        elif "alert" in text or "warn" in text or "notify" in text:
            action = "alert"

        return rate, window, action

    def _extract_confidence_threshold(self, text: str) -> Optional[float]:
        patterns = [
            r"confidence\s*(?:above|over|greater than|>|threshold)?\s*(\d*\.?\d+)",
            r"(?:ml|model)\s*confidence\s*(?:>|above|over)?\s*(\d*\.?\d+)",
            r"(?:at least|minimum)\s*(\d*\.?\d+)\s*confidence",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                value = float(match.group(1))
                return value / 100.0 if value > 1.0 else value
        return None

    def _extract_severity(self, text: str) -> Optional[str]:
        for severity, keywords in SEVERITY_KEYWORDS.items():
            if any(re.search(rf"\b{re.escape(keyword)}\b", text) for keyword in keywords):
                return severity
        return None

    def _extract_isolation(self, text_lower: str, text_original: str) -> Tuple[Optional[str], List[str]]:
        if not any(
            re.search(rf"\b{re.escape(keyword)}\b", text_lower)
            for keyword in ["isolate", "quarantine", "sandbox", "contain", "segregate", "disconnect"]
        ):
            return None, []

        if any(word in text_lower for word in ["subnet", "network", "vlan", "segment"]):
            scope = "subnet"
        else:
            scope = "endpoint"

        targets = self._extract_ips(text_original)
        endpoint_match = re.search(
            r'(?:isolate|quarantine|disconnect)\s+(?:endpoint|device|host|machine|computer)?\s*["\']?([\w.-]+)["\']?',
            text_lower,
        )
        if endpoint_match and not targets:
            targets = [endpoint_match.group(1)]

        return scope, targets

    def _extract_monitor(self, text: str) -> Tuple[Optional[str], Optional[int]]:
        mode = None
        for monitor_type, keywords in MONITOR_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                mode = monitor_type
                break

        if mode is None and any(word in text for word in ["monitor", "watch", "observe", "track"]):
            mode = "dashboard"

        duration = self._extract_duration(text)
        return mode, duration

    def _extract_protocols(self, text: str) -> List[str]:
        protocols: List[str] = []
        for proto, keywords in PROTOCOL_KEYWORDS.items():
            if any(re.search(rf"\b{re.escape(keyword)}\b", text) for keyword in keywords):
                protocols.append(proto)
        if re.search(r"\bhttp\b", text) and "HTTP" not in protocols:
            protocols.append("HTTP")
        if "https" in text and "HTTPS" not in protocols:
            protocols.append("HTTPS")
        if "dns" in text:
            protocols.append("DNS")
        if "ssh" in text:
            protocols.append("SSH")
        if "ftp" in text:
            protocols.append("FTP")
        if "smtp" in text:
            protocols.append("SMTP")
        return self._dedupe(protocols)

    def _extract_auto_expire(self, text: str) -> Optional[int]:
        patterns = [
            r"(?:expire|expires|auto[- ]?expire|timeout|ttl)\s*(?:after|in)?\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?",
            r"(?:temporary|temp)\s*(?:for)?\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?",
            r"(?:for|lasting)\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?\s*(?:only|then)",
            r"\bfor\s+(\d+)\s*(second|sec|minute|min|hour|hr|day)s?\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return self._duration_to_seconds(int(match.group(1)), match.group(2))
        return None

    def _extract_duration(self, text: str) -> Optional[int]:
        match = re.search(r"for\s+(\d+)\s*(second|sec|minute|min|hour|hr|day)s?", text)
        if not match:
            return None
        return self._duration_to_seconds(int(match.group(1)), match.group(2))

    def _duration_to_seconds(self, value: int, unit: str) -> int:
        if unit in ("second", "sec"):
            return value
        if unit in ("minute", "min"):
            return value * 60
        if unit in ("hour", "hr"):
            return value * 3600
        return value * 86400

    def _normalize_domain(self, value: str) -> Optional[str]:
        value = value.strip().strip(".,;:()[]{}<>\"'")
        if not value:
            return None
        if "://" in value:
            parsed = urlparse(value)
            value = parsed.netloc or parsed.path
        value = value.lower()
        if value.startswith("www."):
            value = value[4:]
        if "/" in value:
            value = value.split("/", 1)[0]
        if ":" in value and value.count(":") == 1:
            host, port = value.split(":", 1)
            if port.isdigit():
                value = host
        if value.startswith("*."):
            value = value[2:]
        if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", value):
            return None
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
            return None
        return value

    def _parse_time_token(self, token: str) -> Optional[str]:
        cleaned = " ".join(token.lower().split())
        match = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)?", cleaned)
        if not match:
            return None
        hour = int(match.group(1))
        minute = int(match.group(2) or "0")
        meridiem = match.group(3)
        if meridiem == "pm" and hour < 12:
            hour += 12
        elif meridiem == "am" and hour == 12:
            hour = 0
        hour %= 24
        minute %= 60
        return f"{hour:02d}:{minute:02d}"

    def _dedupe(self, items: List[str]) -> List[str]:
        seen = set()
        result: List[str] = []
        for item in items:
            if item and item not in seen:
                seen.add(item)
                result.append(item)
        return result
