"""
Centralized structured security logger for Guardian Shield.

Produces JSON-formatted log entries consumable by SIEM systems
(Splunk, Elastic SIEM, Azure Sentinel, etc.).

All security-relevant events should go through this module so that:
  - Format is consistent across backend, ML engine, and enforcer.
  - Timestamps are ISO-8601 UTC.
  - Each event carries machine-readable fields for automated alerting.

Usage:
    from backend.app.utils.security_logger import security_log

    security_log.log_event("packet_blocked", source_ip="10.0.0.1", ...)
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# Dedicated logger that writes JSON lines.  Handlers can be added
# externally (e.g. file handler for /var/log/guardian-shield.jsonl).
_json_logger = logging.getLogger("guardian-shield.security")


class SecurityLogger:
    """Structured security event logger.

    Each event is a JSON object with at least:
        timestamp, event_type, severity

    Additional keyword fields are merged in, so callers can attach
    arbitrary context (IPs, ports, model names, scores, etc.).
    """

    # Known event types — kept as a set for documentation; unknown
    # types are still accepted to avoid breaking callers.
    KNOWN_EVENTS = frozenset({
        "packet_blocked",
        "anomaly_detected",
        "policy_triggered",
        "ip_blocked",
        "ip_unblocked",
        "model_prediction",
        "rate_limit_exceeded",
        "threat_intel_hit",
        "model_drift_warning",
        "endpoint_isolated",
        "endpoint_unisolated",
    })

    def __init__(self, logger: Optional[logging.Logger] = None):
        self._logger = logger or _json_logger

    # ------------------------------------------------------------------
    # Core logging method
    # ------------------------------------------------------------------

    def log_event(
        self,
        event_type: str,
        severity: str = "info",
        **fields: Any,
    ) -> Dict[str, Any]:
        """Emit a structured security event.

        Args:
            event_type: Machine-readable event identifier.
            severity: One of "debug", "info", "warning", "critical".
            **fields: Arbitrary key-value pairs merged into the event.

        Returns:
            The fully-formed event dict (useful for testing).
        """
        event: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
        }
        event.update(fields)

        # Serialize — use default=str so datetimes / enums don't crash
        line = json.dumps(event, default=str)

        # Map severity to stdlib log level
        level = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "critical": logging.CRITICAL,
        }.get(severity, logging.INFO)

        self._logger.log(level, line)
        return event

    # ------------------------------------------------------------------
    # Convenience helpers — one per common event type
    # ------------------------------------------------------------------

    def packet_blocked(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: str = "",
        prediction: str = "",
        model: str = "",
        confidence: float = 0.0,
        policy_triggered: str = "",
        **extra: Any,
    ) -> Dict[str, Any]:
        return self.log_event(
            "packet_blocked",
            severity="warning",
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            prediction=prediction,
            model=model,
            confidence=confidence,
            policy_triggered=policy_triggered,
            **extra,
        )

    def anomaly_detected(
        self,
        source_ip: str,
        destination_ip: str,
        anomaly_score: float,
        attack_type: str = "",
        confidence: float = 0.0,
        **extra: Any,
    ) -> Dict[str, Any]:
        return self.log_event(
            "anomaly_detected",
            severity="warning",
            source_ip=source_ip,
            destination_ip=destination_ip,
            anomaly_score=anomaly_score,
            attack_type=attack_type,
            confidence=confidence,
            **extra,
        )

    def policy_triggered(
        self,
        policy_name: str,
        action: str,
        source_ip: str = "",
        destination_ip: str = "",
        **extra: Any,
    ) -> Dict[str, Any]:
        return self.log_event(
            "policy_triggered",
            severity="info",
            policy_name=policy_name,
            action=action,
            source_ip=source_ip,
            destination_ip=destination_ip,
            **extra,
        )

    def ip_blocked(
        self,
        ip: str,
        reason: str = "",
        duration: Optional[int] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        return self.log_event(
            "ip_blocked",
            severity="warning",
            ip=ip,
            reason=reason,
            duration_seconds=duration,
            **extra,
        )

    def ip_unblocked(self, ip: str, **extra: Any) -> Dict[str, Any]:
        return self.log_event(
            "ip_unblocked",
            severity="info",
            ip=ip,
            **extra,
        )

    def model_prediction(
        self,
        source_ip: str,
        destination_ip: str,
        anomaly_score: float,
        attack_type: str,
        confidence: float,
        action: str,
        model: str = "",
        **extra: Any,
    ) -> Dict[str, Any]:
        return self.log_event(
            "model_prediction",
            severity="info" if action == "allow" else "warning",
            source_ip=source_ip,
            destination_ip=destination_ip,
            anomaly_score=anomaly_score,
            attack_type=attack_type,
            confidence=confidence,
            action=action,
            model=model,
            **extra,
        )

    def rate_limit_exceeded(
        self,
        source_ip: str,
        request_count: int,
        window_seconds: int,
        limit: int,
        **extra: Any,
    ) -> Dict[str, Any]:
        return self.log_event(
            "rate_limit_exceeded",
            severity="warning",
            source_ip=source_ip,
            request_count=request_count,
            window_seconds=window_seconds,
            limit=limit,
            **extra,
        )

    def threat_intel_hit(
        self,
        ip: str,
        risk_score: float,
        source: str = "",
        **extra: Any,
    ) -> Dict[str, Any]:
        return self.log_event(
            "threat_intel_hit",
            severity="critical" if risk_score > 80 else "warning",
            ip=ip,
            risk_score=risk_score,
            source=source,
            **extra,
        )


# Module-level singleton for easy import
security_log = SecurityLogger()
