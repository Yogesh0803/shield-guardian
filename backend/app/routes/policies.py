import re
import logging
from fastapi import APIRouter, Depends, HTTPException, status

logger = logging.getLogger(__name__)
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models.policy import Policy
from app.schemas.policy import (
    PolicyCreate,
    PolicyResponse,
    NLPPolicyParse,
    NLPPolicyParseResponse,
)
from app.middleware.auth import get_current_user
from app.models.user import User
from app.services.enforcer import enforcer

router = APIRouter(prefix="/api/policies", tags=["Policies"])


@router.get("/debug/enforcer")
def test_enforcer():
    """Debug endpoint to test enforcer capabilities."""
    import ctypes
    import subprocess as sp
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() if hasattr(ctypes, 'windll') else False
    r = sp.run(
        'netsh advfirewall firewall add rule name=GS_PING_TEST dir=out action=block remoteip=1.2.3.4 protocol=any',
        shell=True, capture_output=True, text=True, timeout=10,
    )
    netsh_ok = r.returncode == 0
    if netsh_ok:
        sp.run('netsh advfirewall firewall delete rule name=GS_PING_TEST', shell=True, capture_output=True, timeout=10)
    resolved = enforcer._resolve_domain_ips(["spotify.com"])
    return {
        "is_admin": is_admin,
        "netsh_works": netsh_ok,
        "netsh_stdout": r.stdout.strip(),
        "netsh_stderr": r.stderr.strip(),
        "resolved_ips": resolved,
        "blocked_domains": {k: v for k, v in list(enforcer.blocked_domains.items())[:3]},
        "blocked_ips": {k: v for k, v in list(enforcer.blocked_ips.items())[:3]},
    }


@router.get("/", response_model=List[PolicyResponse])
def list_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policies = db.query(Policy).all()
    return [PolicyResponse.model_validate(p) for p in policies]


@router.get("/status")
def enforcer_status(current_user: User = Depends(get_current_user)):
    """Return current enforcement status (blocked domains/IPs, admin check)."""
    return enforcer.get_status()


@router.get("/endpoint/{endpoint_id}", response_model=List[PolicyResponse])
def get_policies_by_endpoint(
    endpoint_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policies = db.query(Policy).filter(Policy.endpoint_id == endpoint_id).all()
    return [PolicyResponse.model_validate(p) for p in policies]


def _enforce_policy_background(policy_id: str, policy_name: str, purpose: str, conditions: dict):
    """Run policy enforcement in a background thread so the API responds instantly."""
    try:
        result = enforcer.enforce_policy(policy_id, purpose, conditions)
        logger.info(f"Policy '{policy_name}' enforcement: {result}")
    except Exception as e:
        logger.error(f"Background enforcement failed for '{policy_name}': {e}")


def _unenforce_policy_background(policy_id: str):
    """Run policy unenforcement in a background thread."""
    try:
        enforcer.unenforce_policy(policy_id)
    except Exception as e:
        logger.error(f"Background unenforcement failed for '{policy_id}': {e}")


@router.post("/", response_model=PolicyResponse)
def create_policy(
    policy_data: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = Policy(
        name=policy_data.name,
        description=policy_data.description,
        purpose=policy_data.purpose,
        conditions=policy_data.conditions,
        endpoint_id=policy_data.endpoint_id,
        is_active=policy_data.is_active,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    # Enforce synchronously so the user gets immediate feedback
    if policy.is_active and policy.conditions and policy.purpose:
        try:
            result = enforcer.enforce_policy(
                policy.id, policy.purpose, policy.conditions
            )
            logger.info(f"Policy '{policy.name}' enforcement result: {result}")
            if not result.get("enforced"):
                logger.warning(
                    f"Policy '{policy.name}' was NOT enforced. "
                    f"Ensure backend runs as Administrator. Details: {result}"
                )
        except Exception as e:
            logger.error(f"Enforcement failed for '{policy.name}': {e}")

    return PolicyResponse.model_validate(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    # Remove enforcement FIRST (before deleting from DB) so if this fails,
    # the policy record still exists and can be retried.
    try:
        enforcer.unenforce_policy(policy_id)
    except Exception as e:
        logger.error(f"Unenforcement failed for '{policy_id}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove firewall rules: {e}",
        )

    db.delete(policy)
    db.commit()


@router.patch("/{policy_id}/toggle", response_model=PolicyResponse)
def toggle_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )
    policy.is_active = not policy.is_active
    db.commit()
    db.refresh(policy)

    # Enforce or unenforce synchronously based on new state
    try:
        if policy.is_active and policy.conditions and policy.purpose:
            result = enforcer.enforce_policy(
                policy.id, policy.purpose, policy.conditions
            )
            logger.info(f"Toggle ON '{policy.name}': {result}")
        else:
            enforcer.unenforce_policy(policy.id)
            logger.info(f"Toggle OFF '{policy.name}'")
    except Exception as e:
        logger.error(f"Toggle enforcement failed for '{policy.name}': {e}")

    return PolicyResponse.model_validate(policy)


# Known apps and their process names
KNOWN_APPS = {
    "chrome": "chrome", "firefox": "firefox", "edge": "msedge",
    "safari": "safari", "brave": "brave", "opera": "opera",
    "slack": "slack", "discord": "discord", "teams": "teams",
    "zoom": "zoom", "spotify": "spotify", "vscode": "code",
    "node": "node", "python": "python", "docker": "docker",
    "nginx": "nginx", "postgres": "postgres", "redis": "redis",
}

# Known domains
KNOWN_DOMAINS = {
    "youtube": ["youtube.com"],
    "google": ["google.com"],
    "facebook": ["facebook.com", "fbcdn.net"],
    "twitter": ["twitter.com", "x.com"],
    "x.com": ["x.com", "twitter.com"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "reddit": ["reddit.com"],
    "tiktok": ["tiktok.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com"],
    "github": ["github.com"],
    "stackoverflow": ["stackoverflow.com"],
    "linkedin": ["linkedin.com"],
    "whatsapp": ["whatsapp.com", "web.whatsapp.com", "whatsapp.net", "static.whatsapp.net"],
    "telegram": ["telegram.org", "t.me", "web.telegram.org", "api.telegram.org", "core.telegram.org"],
    "spotify": ["spotify.com", "open.spotify.com", "apresolve.spotify.com", "spclient.wg.spotify.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "gateway.discord.gg"],
    "zoom": ["zoom.us", "zoom.com"],
    "slack": ["slack.com"],
    "chatgpt": ["chatgpt.com", "chat.openai.com", "openai.com", "cdn.oaistatic.com", "files.oaiusercontent.com"],
    "openai": ["openai.com", "chatgpt.com", "chat.openai.com", "cdn.oaistatic.com"],
    "snapchat": ["snapchat.com", "snap.com"],
    "pinterest": ["pinterest.com"],
    "twitch": ["twitch.tv"],
    "tumblr": ["tumblr.com"],
    "skype": ["skype.com", "web.skype.com"],
    "signal": ["signal.org"],
    "bing": ["bing.com"],
    "yahoo": ["yahoo.com"],
    "wikipedia": ["wikipedia.org", "en.wikipedia.org"],
    "pornhub": ["pornhub.com"],
    "xvideos": ["xvideos.com"],
    "gambling": ["bet365.com", "pokerstars.com", "draftkings.com"],
    "steam": ["steampowered.com", "store.steampowered.com", "steamcommunity.com"],
    "epic games": ["epicgames.com", "fortnite.com"],
    "roblox": ["roblox.com"],
    "messenger": ["messenger.com", "www.messenger.com"],
    "claude": ["claude.ai", "anthropic.com"],
    "gemini": ["gemini.google.com"],
    "copilot": ["copilot.microsoft.com"],
    "perplexity": ["perplexity.ai"],
}

COUNTRY_CODES = {
    "russia": "RU", "russian": "RU", "china": "CN", "chinese": "CN",
    "iran": "IR", "north korea": "KP", "india": "IN", "indian": "IN",
    "us": "US", "usa": "US", "american": "US", "uk": "GB", "british": "GB",
    "germany": "DE", "german": "DE", "france": "FR", "french": "FR",
    "japan": "JP", "japanese": "JP", "brazil": "BR", "australia": "AU",
}

# Attack type keywords for classification-based rules
ATTACK_KEYWORDS = {
    "DDoS": ["ddos", "distributed denial"],
    "DoS": ["dos", "denial of service"],
    "BruteForce": ["brute force", "bruteforce", "brute-force", "credential stuffing"],
    "PortScan": ["port scan", "portscan", "port-scan", "port sweep"],
    "WebAttack": ["web attack", "sql injection", "xss", "cross-site", "rfi", "lfi"],
    "Botnet": ["botnet", "bot net", "command and control", "c2", "c&c"],
    "Infiltration": ["infiltration", "intrusion", "lateral movement"],
    "Phishing": ["phishing", "phish", "spear phishing"],
    "Malware": ["malware", "virus", "trojan", "ransomware", "worm"],
}

# Severity keywords
SEVERITY_KEYWORDS = {
    "critical": ["critical", "severe", "emergency", "urgent", "p0", "p1"],
    "high": ["high", "important", "major", "dangerous", "serious"],
    "medium": ["medium", "moderate", "normal", "standard"],
    "low": ["low", "minor", "informational", "info", "minimal"],
}


@router.post("/parse", response_model=NLPPolicyParseResponse)
def parse_natural_language_policy(
    nlp_request: NLPPolicyParse,
    current_user: User = Depends(get_current_user),
):
    """Parse natural language into a structured policy with intelligent firewall actions."""
    text = (nlp_request.natural_language or nlp_request.input or "").strip()
    text_lower = text.lower()

    capabilities_used = []

    # ── Determine action (expanded with new action types) ──
    purpose = "block"
    if any(w in text_lower for w in ["rate limit", "rate-limit", "throttle", "cap requests"]):
        purpose = "rate_limit"
        capabilities_used.append("rate_limiting")
    elif any(w in text_lower for w in ["isolate", "quarantine", "sandbox", "contain", "segregate"]):
        purpose = "isolate"
        capabilities_used.append("endpoint_isolation")
    elif any(w in text_lower for w in ["monitor", "watch", "observe", "track", "log", "audit"]):
        purpose = "monitor"
        capabilities_used.append("monitoring")
    elif any(w in text_lower for w in ["alert", "notify", "warn", "flag", "alarm", "escalate"]):
        purpose = "alert"
        capabilities_used.append("alerting")
    elif any(w in text_lower for w in ["allow", "permit", "enable"]):
        purpose = "unblock"
    # else: stays "block"

    # ── Extract apps ──
    app_names = []
    for keyword, app in KNOWN_APPS.items():
        if keyword in text_lower:
            app_names.append(app)

    # ── Extract domains ──
    domains = []
    for keyword, domain_list in KNOWN_DOMAINS.items():
        if keyword in text_lower:
            for d in domain_list:
                if d not in domains:
                    domains.append(d)
    domain_matches = re.findall(r'[\w.-]+\.\w{2,}', text)
    for d in domain_matches:
        d = re.sub(r'^(https?://|www\.)', '', d).rstrip('/')
        if d and d not in domains and d.count('.') >= 1 and not d[0].isdigit():
            domains.append(d)

    # ── Extract IPs ──
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)

    # ── Extract ports ──
    ports = []
    port_matches = re.findall(r'port\s*(\d+)', text_lower)
    for p in port_matches:
        ports.append({"port": int(p), "protocol": ["TCP"]})

    # ── Extract countries ──
    geo_countries = []
    for keyword, code in COUNTRY_CODES.items():
        if keyword in text_lower and code not in geo_countries:
            geo_countries.append(code)

    # ── Extract time ranges (enhanced) ──
    time_range = None
    days_of_week = None

    if "business hours" in text_lower:
        if "outside" in text_lower or "after" in text_lower:
            time_range = {"start": "18:00", "end": "09:00"}
        else:
            time_range = {"start": "09:00", "end": "18:00"}
        capabilities_used.append("time_based_access")
    if "night" in text_lower or "late night" in text_lower:
        time_range = {"start": "22:00", "end": "06:00"}
        capabilities_used.append("time_based_access")

    time_match = re.search(r'after\s+(\d{1,2})\s*(pm|am)?', text_lower)
    if time_match:
        hour = int(time_match.group(1))
        if time_match.group(2) == 'pm' and hour < 12:
            hour += 12
        time_range = {"start": f"{hour:02d}:00", "end": "23:59"}
        if "time_based_access" not in capabilities_used:
            capabilities_used.append("time_based_access")

    time_match2 = re.search(r'before\s+(\d{1,2})\s*(pm|am)?', text_lower)
    if time_match2:
        hour = int(time_match2.group(1))
        if time_match2.group(2) == 'pm' and hour < 12:
            hour += 12
        time_range = {"start": "00:00", "end": f"{hour:02d}:00"}
        if "time_based_access" not in capabilities_used:
            capabilities_used.append("time_based_access")

    between_match = re.search(
        r'between\s+(\d{1,2})\s*(pm|am)?\s*(?:and|to|-)\s*(\d{1,2})\s*(pm|am)?',
        text_lower,
    )
    if between_match:
        h1 = int(between_match.group(1))
        if between_match.group(2) == 'pm' and h1 < 12:
            h1 += 12
        h2 = int(between_match.group(3))
        if between_match.group(4) == 'pm' and h2 < 12:
            h2 += 12
        time_range = {"start": f"{h1:02d}:00", "end": f"{h2:02d}:00"}
        if "time_based_access" not in capabilities_used:
            capabilities_used.append("time_based_access")

    # Days of week
    day_map = {
        "weekday": [0, 1, 2, 3, 4], "weekdays": [0, 1, 2, 3, 4],
        "weekend": [5, 6], "weekends": [5, 6],
        "monday": [0], "tuesday": [1], "wednesday": [2],
        "thursday": [3], "friday": [4], "saturday": [5], "sunday": [6],
    }
    for day_kw, day_nums in day_map.items():
        if day_kw in text_lower:
            days_of_week = day_nums
            if "time_based_access" not in capabilities_used:
                capabilities_used.append("time_based_access")
            break

    # ── Extract anomaly threshold ──
    anomaly_threshold = None
    anomaly_patterns = [
        r'anomaly\s*(?:score)?\s*(?:above|over|greater than|>)\s*(\d*\.?\d+)',
        r'threshold\s*(?:of|:)?\s*(\d*\.?\d+)',
        r'score\s*>\s*(\d*\.?\d+)',
    ]
    for pattern in anomaly_patterns:
        match = re.search(pattern, text_lower)
        if match:
            anomaly_threshold = float(match.group(1))
            capabilities_used.append("anomaly_score")
            break

    # ── Extract confidence threshold ──
    confidence_threshold = None
    conf_patterns = [
        r'confidence\s*(?:above|over|greater than|>|threshold)?\s*(\d*\.?\d+)',
        r'(?:ml|model)\s*confidence\s*(?:>|above|over)?\s*(\d*\.?\d+)',
        r'(?:at least|minimum)\s*(\d*\.?\d+)\s*confidence',
    ]
    for pattern in conf_patterns:
        match = re.search(pattern, text_lower)
        if match:
            val = float(match.group(1))
            confidence_threshold = val / 100.0 if val > 1.0 else val
            if "anomaly_score" not in capabilities_used:
                capabilities_used.append("anomaly_score")
            break

    # ── Extract attack types ──
    attack_types = []
    for attack_type, keywords in ATTACK_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                if attack_type not in attack_types:
                    attack_types.append(attack_type)
                if "attack_classification" not in capabilities_used:
                    capabilities_used.append("attack_classification")
                break

    # ── Extract rate limit ──
    rate_limit = None
    rate_limit_window = None
    rate_limit_action = None
    rate_patterns = [
        r'(?:rate|request)\s*(?:limit)?\s*(?:>|above|over|exceeds?)\s*(\d+)',
        r'more than (\d+)\s*(?:requests?|connections?)\s*(?:per|/)',
        r'(\d+)\s*(?:requests?|connections?)\s*(?:per|/)',
        r'limit\s*(?:to)?\s*(\d+)\s*(?:requests?|connections?)',
    ]
    for pattern in rate_patterns:
        match = re.search(pattern, text_lower)
        if match:
            rate_limit = int(match.group(1))
            if "rate_limiting" not in capabilities_used:
                capabilities_used.append("rate_limiting")
            break

    if rate_limit:
        # Extract window
        window_match = re.search(
            r'(?:per|/)\s*(?:(\d+)\s*)?(second|sec|minute|min|hour|hr)s?',
            text_lower,
        )
        if window_match:
            multiplier = int(window_match.group(1)) if window_match.group(1) else 1
            unit = window_match.group(2)
            if unit in ("second", "sec"):
                rate_limit_window = multiplier
            elif unit in ("minute", "min"):
                rate_limit_window = multiplier * 60
            elif unit in ("hour", "hr"):
                rate_limit_window = multiplier * 3600
        else:
            rate_limit_window = 60  # default per minute

        # Extract overflow action
        if "throttle" in text_lower or "slow" in text_lower:
            rate_limit_action = "throttle"
        elif "alert" in text_lower or "warn" in text_lower:
            rate_limit_action = "alert"
        else:
            rate_limit_action = "block"

    # ── Extract severity ──
    severity = None
    for sev, keywords in SEVERITY_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                severity = sev
                break
        if severity:
            break

    # ── Extract isolation scope ──
    isolation_scope = None
    isolation_targets = []
    if purpose == "isolate":
        if any(w in text_lower for w in ["subnet", "network", "vlan", "segment"]):
            isolation_scope = "subnet"
        else:
            isolation_scope = "endpoint"
        isolation_targets = ips.copy()
        endpoint_match = re.search(
            r'(?:isolate|quarantine|disconnect)\s+(?:endpoint|device|host)?\s*["\']?([\w.-]+)["\']?',
            text_lower,
        )
        if endpoint_match and not isolation_targets:
            isolation_targets = [endpoint_match.group(1)]

    # ── Extract monitoring mode ──
    monitor_mode = None
    monitor_duration = None
    if purpose in ("monitor", "alert"):
        if any(w in text_lower for w in ["log only", "just log", "logging only", "silent"]):
            monitor_mode = "log_only"
        elif any(w in text_lower for w in ["alert admin", "notify admin", "notify team", "send alert"]):
            monitor_mode = "alert_admin"
        elif any(w in text_lower for w in ["webhook", "push notification"]):
            monitor_mode = "webhook"
        else:
            monitor_mode = "dashboard"

        dur_match = re.search(r'for\s+(\d+)\s*(second|sec|minute|min|hour|hr|day)s?', text_lower)
        if dur_match:
            value = int(dur_match.group(1))
            unit = dur_match.group(2)
            if unit in ("second", "sec"):
                monitor_duration = value
            elif unit in ("minute", "min"):
                monitor_duration = value * 60
            elif unit in ("hour", "hr"):
                monitor_duration = value * 3600
            elif unit == "day":
                monitor_duration = value * 86400

    # ── Extract protocols ──
    protocols = []
    proto_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
    for kw, proto in proto_map.items():
        if kw in text_lower:
            protocols.append(proto)
    if "http " in text_lower or text_lower.endswith("http"):
        protocols.append("HTTP")
    if "https" in text_lower:
        protocols.append("HTTPS")
    if "dns" in text_lower:
        protocols.append("DNS")
    if "ssh" in text_lower:
        protocols.append("SSH")

    # ── Extract auto-expire ──
    auto_expire = None
    expire_patterns = [
        r'(?:expire|auto[- ]?expire|timeout|ttl)\s*(?:after|in)?\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?',
        r'(?:temporary|temp)\s*(?:for)?\s*(\d+)\s*(second|sec|minute|min|hour|hr|day)s?',
    ]
    for pattern in expire_patterns:
        match = re.search(pattern, text_lower)
        if match:
            value = int(match.group(1))
            unit = match.group(2)
            if unit in ("second", "sec"):
                auto_expire = value
            elif unit in ("minute", "min"):
                auto_expire = value * 60
            elif unit in ("hour", "hr"):
                auto_expire = value * 3600
            elif unit == "day":
                auto_expire = value * 86400
            break

    # ── Build conditions ──
    parsed = {
        "domains": domains,
        "ips": ips,
        "ports": ports,
        "app_names": app_names,
    }
    if time_range:
        parsed["time_range"] = time_range
    if days_of_week:
        parsed["days_of_week"] = days_of_week
    if geo_countries:
        parsed["geo_countries"] = geo_countries
    if anomaly_threshold is not None:
        parsed["anomaly_threshold"] = anomaly_threshold
    if confidence_threshold is not None:
        parsed["confidence_threshold"] = confidence_threshold
    if attack_types:
        parsed["attack_types"] = attack_types
    if rate_limit is not None:
        parsed["rate_limit"] = rate_limit
        parsed["rate_limit_window"] = rate_limit_window
        parsed["rate_limit_action"] = rate_limit_action
    if severity:
        parsed["severity"] = severity
    if isolation_scope:
        parsed["isolation_scope"] = isolation_scope
        parsed["isolation_targets"] = isolation_targets
    if monitor_mode:
        parsed["monitor_mode"] = monitor_mode
    if monitor_duration:
        parsed["monitor_duration"] = monitor_duration
    if protocols:
        parsed["protocols"] = protocols
    if auto_expire:
        parsed["auto_expire"] = auto_expire
    if time_range and days_of_week:
        parsed["schedule"] = {"days": days_of_week, "time_range": time_range}

    # ── Determine rule type ──
    if capabilities_used:
        # Pick the primary rule type based on most specific capability
        priority = [
            "endpoint_isolation", "rate_limiting", "attack_classification",
            "anomaly_score", "monitoring", "alerting", "time_based_access",
        ]
        rule_type = "basic"
        for cap in priority:
            if cap in capabilities_used:
                rule_type = {
                    "endpoint_isolation": "isolation",
                    "rate_limiting": "rate_limit",
                    "attack_classification": "attack",
                    "anomaly_score": "anomaly",
                    "monitoring": "monitor",
                    "alerting": "monitor",
                    "time_based_access": "time_access",
                }.get(cap, "basic")
                break
    else:
        rule_type = "basic"

    # ── Generate explanation ──
    parts = []
    action_words = {
        "block": "Block", "unblock": "Allow", "monitor": "Monitor",
        "alert": "Alert on", "isolate": "Isolate", "rate_limit": "Rate-limit",
    }
    action_word = action_words.get(purpose, "Block")

    if app_names:
        parts.append(f"{action_word} {', '.join(app_names)}")
    elif isolation_targets:
        parts.append(f"{action_word} endpoint(s) {', '.join(isolation_targets)}")
    else:
        parts.append(f"{action_word} traffic")

    if domains:
        parts.append(f"to/from {', '.join(domains[:5])}")
        if len(domains) > 5:
            parts.append(f"(+{len(domains) - 5} more)")
    if ips:
        parts.append(f"to/from IPs {', '.join(ips)}")
    if ports:
        parts.append(f"on port(s) {', '.join(str(p['port']) for p in ports)}")
    if geo_countries:
        parts.append(f"from countries {', '.join(geo_countries)}")
    if time_range:
        parts.append(f"during {time_range['start']}-{time_range['end']}")
    if days_of_week is not None:
        day_names = {0: "Mon", 1: "Tue", 2: "Wed", 3: "Thu", 4: "Fri", 5: "Sat", 6: "Sun"}
        parts.append(f"on {', '.join(day_names.get(d, str(d)) for d in days_of_week)}")
    if anomaly_threshold is not None:
        parts.append(f"when anomaly score > {anomaly_threshold}")
    if confidence_threshold is not None:
        parts.append(f"with ML confidence >= {confidence_threshold}")
    if attack_types:
        parts.append(f"for attack types: {', '.join(attack_types)}")
    if rate_limit is not None:
        window_str = f"{rate_limit_window}s" if rate_limit_window else "60s"
        parts.append(f"if > {rate_limit} requests/{window_str}")
    if severity:
        parts.append(f"[severity: {severity}]")
    if monitor_mode:
        parts.append(f"[mode: {monitor_mode}]")
    if auto_expire:
        parts.append(f"[expires in {auto_expire}s]")

    explanation = " ".join(parts)

    # ── Confidence calculation ──
    extracted_count = sum([
        bool(app_names), bool(domains), bool(ips), bool(ports),
        bool(geo_countries), bool(time_range), bool(days_of_week),
        bool(anomaly_threshold is not None), bool(confidence_threshold is not None),
        bool(attack_types), bool(rate_limit is not None),
        bool(severity), bool(isolation_scope), bool(monitor_mode),
        bool(protocols), bool(auto_expire),
    ])
    confidence = min(0.95, 0.5 + extracted_count * 0.1)

    return NLPPolicyParseResponse(
        name=f"{action_word}: {text[:60]}",
        description=text,
        purpose=purpose,
        parsed=parsed,
        confidence=round(confidence, 2),
        explanation=explanation,
        rule_type=rule_type,
        capabilities_used=capabilities_used,
    )
