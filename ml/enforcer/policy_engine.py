"""
Policy engine: combines user-defined rules with ML predictions.
Decides whether to allow, block, alert, monitor, isolate, or rate-limit a flow.
"""

import logging
import time
from typing import Dict, List, Optional
from collections import defaultdict
from dataclasses import dataclass, field

from ..context.context_engine import FlowContext
from ..config import config

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """A user-defined firewall policy rule."""
    id: str
    name: str
    purpose: str  # "block", "unblock", "monitor", "alert", "isolate", "rate_limit"
    is_active: bool
    # Conditions
    domains: List[str]
    ips: List[str]
    ports: List[dict]  # [{"port": 80, "protocol": ["TCP"]}]
    app_names: List[str]
    time_range: Optional[dict] = None  # {"start": "09:00", "end": "18:00"}
    days_of_week: Optional[List[int]] = None  # [0,1,2,3,4] = Mon-Fri
    geo_countries: Optional[List[str]] = None  # ["CN", "RU"]
    anomaly_threshold: Optional[float] = None
    attack_types: Optional[List[str]] = None
    rate_limit: Optional[int] = None  # max requests per window
    # --- Extended fields ---
    confidence_threshold: Optional[float] = None
    severity: Optional[str] = None  # "low", "medium", "high", "critical"
    isolation_scope: Optional[str] = None  # "endpoint", "subnet"
    isolation_targets: List[str] = field(default_factory=list)
    monitor_mode: Optional[str] = None  # "log_only", "alert_admin", "dashboard"
    monitor_duration: Optional[int] = None  # seconds
    rate_limit_window: Optional[int] = None  # window in seconds (default 60)
    rate_limit_action: Optional[str] = None  # "block", "alert", "throttle"
    protocols: List[str] = field(default_factory=list)
    schedule: Optional[dict] = None
    auto_expire: Optional[int] = None  # seconds until policy auto-expires
    created_at: Optional[float] = None


# Maps purpose strings to the action the policy engine should return.
_PURPOSE_TO_ACTION = {
    "block": "block",
    "unblock": "allow",
    "monitor": "monitor",
    "alert": "alert",
    "isolate": "isolate",
    "rate_limit": "rate_limit",
}


class PolicyEngine:
    """Evaluates flows against user policies and ML predictions."""

    def __init__(self):
        self.policies: List[PolicyRule] = []
        # Rate-limit tracking: key -> list of timestamps
        self._rate_counters: Dict[str, List[float]] = defaultdict(list)

    def load_policies(self, policies: List[dict]):
        """Load policies from the backend API."""
        self.policies = []
        now = time.time()
        for p in policies:
            conditions = p.get("conditions", {})
            rule = PolicyRule(
                id=p["id"],
                name=p["name"],
                purpose=p["purpose"],
                is_active=p.get("is_active", True),
                domains=conditions.get("domains", []),
                ips=conditions.get("ips", []),
                ports=conditions.get("ports", []),
                app_names=conditions.get("app_names", []),
                time_range=conditions.get("time_range"),
                days_of_week=conditions.get("days_of_week"),
                geo_countries=conditions.get("geo_countries"),
                anomaly_threshold=conditions.get("anomaly_threshold"),
                attack_types=conditions.get("attack_types"),
                rate_limit=conditions.get("rate_limit"),
                confidence_threshold=conditions.get("confidence_threshold"),
                severity=conditions.get("severity"),
                isolation_scope=conditions.get("isolation_scope"),
                isolation_targets=conditions.get("isolation_targets", []),
                monitor_mode=conditions.get("monitor_mode"),
                monitor_duration=conditions.get("monitor_duration"),
                rate_limit_window=conditions.get("rate_limit_window", 60),
                rate_limit_action=conditions.get("rate_limit_action", "block"),
                protocols=conditions.get("protocols", []),
                schedule=conditions.get("schedule"),
                auto_expire=conditions.get("auto_expire"),
                created_at=p.get("created_at", now),
            )
            self.policies.append(rule)
        logger.info(f"Loaded {len(self.policies)} policies")

    def evaluate(
        self,
        context: FlowContext,
        anomaly_score: float,
        attack_type: str,
        confidence: float,
    ) -> dict:
        """
        Evaluate a flow against all policies.

        Returns a dict with:
            action: "allow", "block", "alert", "monitor", "isolate", "rate_limit"
            matched_policy: name of the matched policy (or None)
            details: additional info (severity, monitor_mode, isolation_scope, etc.)
        """
        now = time.time()

        # 1. Check user-defined policies first (highest priority)
        for policy in self.policies:
            if not policy.is_active:
                continue

            # Auto-expire check
            if policy.auto_expire and policy.created_at:
                if now - policy.created_at > policy.auto_expire:
                    policy.is_active = False
                    logger.info(f"Policy '{policy.name}' auto-expired")
                    continue

            if self._matches_policy(policy, context, anomaly_score, attack_type, confidence):
                action = _PURPOSE_TO_ACTION.get(policy.purpose, "block")

                # Handle rate limiting specially
                if action == "rate_limit" or policy.rate_limit:
                    rate_result = self._check_rate_limit(policy, context)
                    if rate_result:
                        overflow_action = policy.rate_limit_action or "block"
                        logger.debug(
                            f"Rate limit exceeded for policy '{policy.name}': {overflow_action}"
                        )
                        return {
                            "action": overflow_action,
                            "matched_policy": policy.name,
                            "details": {
                                "reason": "rate_limit_exceeded",
                                "rate_limit": policy.rate_limit,
                                "window": policy.rate_limit_window,
                                "severity": policy.severity,
                            },
                        }
                    # Rate not exceeded — let flow through (or monitor)
                    if action == "rate_limit":
                        continue

                logger.debug(f"Policy '{policy.name}' matched: {action}")
                return {
                    "action": action,
                    "matched_policy": policy.name,
                    "details": {
                        "severity": policy.severity,
                        "monitor_mode": policy.monitor_mode,
                        "isolation_scope": policy.isolation_scope,
                        "isolation_targets": policy.isolation_targets,
                    },
                }

        # 2. ML-informed decision (if no policy matched)
        ml_action = self._ml_decision(anomaly_score, confidence, attack_type)
        return {
            "action": ml_action,
            "matched_policy": None,
            "details": {"reason": "ml_inference"},
        }

    def evaluate_simple(
        self,
        context: FlowContext,
        anomaly_score: float,
        attack_type: str,
        confidence: float,
    ) -> str:
        """Backward-compatible evaluate that returns just the action string."""
        result = self.evaluate(context, anomaly_score, attack_type, confidence)
        action = result["action"]
        # Map extended actions to legacy actions for callers that expect only
        # "allow" / "block" / "alert"
        if action in ("monitor", "rate_limit"):
            return "alert"
        if action == "isolate":
            return "block"
        return action

    def _ml_decision(self, anomaly_score: float, confidence: float, attack_type: str) -> str:
        """ML-informed decision (when no policy matched)."""
        if anomaly_score > config.anomaly_threshold_high and confidence > 0.8:
            return "block"
        elif anomaly_score > config.anomaly_threshold_high:
            return "alert"
        elif anomaly_score > config.anomaly_threshold_medium:
            if attack_type in ("DDoS", "DoS", "BruteForce", "PortScan") and confidence > 0.7:
                return "block"
            return "alert"
        return "allow"

    def _check_rate_limit(self, policy: PolicyRule, ctx: FlowContext) -> bool:
        """Check if rate limit is exceeded. Returns True if exceeded."""
        if not policy.rate_limit:
            return False

        window = policy.rate_limit_window or 60
        now = time.time()
        key = f"{policy.id}:{ctx.src_ip}"

        # Clean old entries
        self._rate_counters[key] = [
            t for t in self._rate_counters[key] if now - t < window
        ]
        # Add current request
        self._rate_counters[key].append(now)

        return len(self._rate_counters[key]) > policy.rate_limit

    def _matches_policy(
        self,
        policy: PolicyRule,
        ctx: FlowContext,
        anomaly_score: float,
        attack_type: str,
        confidence: float = 0.0,
    ) -> bool:
        """Check if a flow matches a policy's conditions."""
        # All conditions must match (AND logic)
        checks = []

        # IP match
        if policy.ips:
            checks.append(ctx.dst_ip in policy.ips or ctx.src_ip in policy.ips)

        # Port match
        if policy.ports:
            port_match = False
            for p in policy.ports:
                if ctx.dst_port == p.get("port"):
                    protocols = p.get("protocol", [])
                    if not protocols or ctx.protocol in protocols:
                        port_match = True
                        break
            checks.append(port_match)

        # App name match
        if policy.app_names:
            checks.append(
                ctx.app_name.lower() in [a.lower() for a in policy.app_names]
            )

        # Time range (with schedule support)
        active_time_range = policy.time_range
        active_days = policy.days_of_week
        if policy.schedule:
            active_time_range = policy.schedule.get("time_range", active_time_range)
            active_days = policy.schedule.get("days", active_days)

        if active_time_range:
            start = int(active_time_range.get("start", "0").split(":")[0])
            end = int(active_time_range.get("end", "24").split(":")[0])
            if start <= end:
                checks.append(start <= ctx.hour < end)
            else:
                # Wraps midnight (e.g., 22:00 - 06:00)
                checks.append(ctx.hour >= start or ctx.hour < end)

        # Days of week
        if active_days:
            checks.append(ctx.day_of_week in active_days)

        # Geo countries
        if policy.geo_countries:
            checks.append(ctx.dest_country_code in policy.geo_countries)

        # Anomaly threshold
        if policy.anomaly_threshold is not None:
            checks.append(anomaly_score > policy.anomaly_threshold)

        # Confidence threshold
        if policy.confidence_threshold is not None:
            checks.append(confidence >= policy.confidence_threshold)

        # Attack types
        if policy.attack_types:
            checks.append(attack_type in policy.attack_types)

        # Protocol match
        if policy.protocols:
            checks.append(ctx.protocol in policy.protocols)

        # Isolation targets (match src or dst IP against targets)
        if policy.isolation_targets:
            checks.append(
                ctx.src_ip in policy.isolation_targets
                or ctx.dst_ip in policy.isolation_targets
            )

        # If no conditions specified, policy doesn't match anything
        if not checks:
            return False

        return all(checks)
