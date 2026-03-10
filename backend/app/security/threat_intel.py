"""
Threat intelligence integration for Guardian Shield.

Provides IP reputation lookups via the AbuseIPDB API with an in-memory
TTL cache to avoid redundant lookups.

Architecture decisions:
    - The cache uses a simple dict + TTL approach (no external dependency
      like Redis) to keep the module self-contained.
    - HTTP calls are made with a short timeout to avoid blocking the
      enforcement pipeline.
    - The module degrades gracefully when the API key is not set or the
      service is unreachable — it returns a neutral score instead of
      raising.

Configuration flags:
    Set THREAT_INTEL_ENABLED=true and ABUSEIPDB_API_KEY=<key> in the
    environment (or .env) to activate.

Usage:
    from backend.app.security.threat_intel import threat_intel

    result = threat_intel.check_ip_reputation("1.2.3.4")
    if result["risk_score"] > 80:
        ...  # block or raise alert
"""

import os
import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional

import requests as _requests

logger = logging.getLogger("guardian-shield.threat-intel")


@dataclass
class ThreatIntelConfig:
    """Configuration for the threat-intel module."""
    # Feature toggle
    enabled: bool = os.getenv("THREAT_INTEL_ENABLED", "false").lower() == "true"

    # AbuseIPDB
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    abuseipdb_max_age_days: int = 90

    # Cache TTL (seconds) — avoid re-querying the same IP repeatedly
    cache_ttl: int = 3600  # 1 hour

    # Request timeout (seconds)
    request_timeout: int = 5

    # Auto-block threshold — IPs above this score are flagged for blocking
    auto_block_threshold: int = 80

    # Anomaly weight boost — multiplier applied to the ML anomaly score
    # when the IP has a high reputation risk score.
    anomaly_weight_boost: float = 0.2


@dataclass
class _CacheEntry:
    """Cached reputation result."""
    risk_score: float
    is_whitelisted: bool
    total_reports: int
    country_code: str
    fetched_at: float


class ThreatIntelProvider:
    """IP reputation checker backed by AbuseIPDB."""

    def __init__(self, config: Optional[ThreatIntelConfig] = None):
        self.config = config or ThreatIntelConfig()
        self._cache: Dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_ip_reputation(self, ip: str) -> dict:
        """Look up the reputation of an IP address.

        Returns a dict with at least:
            risk_score (0-100), is_whitelisted, total_reports,
            country_code, cached, source, should_block
        """
        if not self.config.enabled or not self.config.abuseipdb_api_key:
            return self._neutral_result(ip, reason="disabled")

        # Check cache first
        cached = self._get_cached(ip)
        if cached is not None:
            return self._format_result(ip, cached, from_cache=True)

        # Query AbuseIPDB
        try:
            result = self._query_abuseipdb(ip)
            if result:
                with self._lock:
                    self._cache[ip] = result
                return self._format_result(ip, result, from_cache=False)
        except Exception as e:
            logger.warning(f"Threat intel lookup failed for {ip}: {e}")

        return self._neutral_result(ip, reason="lookup_failed")

    def get_cached_score(self, ip: str) -> Optional[float]:
        """Return the cached risk score for an IP, or None if not cached.

        This is a lightweight check intended for the hot path — it never
        makes network calls.
        """
        cached = self._get_cached(ip)
        return cached.risk_score if cached else None

    def adjust_anomaly_score(
        self, ip: str, base_score: float
    ) -> float:
        """Boost anomaly score if the IP has a bad reputation.

        Uses cached data only (no network call).  Returns the adjusted
        score, clamped to [0, 1].
        """
        risk = self.get_cached_score(ip)
        if risk is None or risk < 50:
            return base_score

        # Scale boost linearly with risk (50 → 0%, 100 → full boost)
        boost = self.config.anomaly_weight_boost * ((risk - 50) / 50.0)
        adjusted = min(base_score + boost, 1.0)
        return adjusted

    def get_cache_stats(self) -> dict:
        """Return cache statistics for monitoring."""
        with self._lock:
            return {
                "cached_ips": len(self._cache),
                "enabled": self.config.enabled,
                "has_api_key": bool(self.config.abuseipdb_api_key),
                "auto_block_threshold": self.config.auto_block_threshold,
            }

    def clear_cache(self):
        """Clear the reputation cache."""
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_cached(self, ip: str) -> Optional[_CacheEntry]:
        """Return a cache entry if it exists and hasn't expired."""
        with self._lock:
            entry = self._cache.get(ip)
            if entry and (time.time() - entry.fetched_at) < self.config.cache_ttl:
                return entry
            if entry:
                # Expired — remove
                del self._cache[ip]
        return None

    def _query_abuseipdb(self, ip: str) -> Optional[_CacheEntry]:
        """Query the AbuseIPDB API."""
        headers = {
            "Key": self.config.abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(self.config.abuseipdb_max_age_days),
        }

        resp = _requests.get(
            self.config.abuseipdb_url,
            headers=headers,
            params=params,
            timeout=self.config.request_timeout,
        )
        resp.raise_for_status()

        data = resp.json().get("data", {})
        return _CacheEntry(
            risk_score=data.get("abuseConfidenceScore", 0),
            is_whitelisted=data.get("isWhitelisted", False),
            total_reports=data.get("totalReports", 0),
            country_code=data.get("countryCode", ""),
            fetched_at=time.time(),
        )

    def _format_result(
        self, ip: str, entry: _CacheEntry, from_cache: bool
    ) -> dict:
        return {
            "ip": ip,
            "risk_score": entry.risk_score,
            "is_whitelisted": entry.is_whitelisted,
            "total_reports": entry.total_reports,
            "country_code": entry.country_code,
            "cached": from_cache,
            "source": "abuseipdb",
            "should_block": entry.risk_score >= self.config.auto_block_threshold,
        }

    @staticmethod
    def _neutral_result(ip: str, reason: str = "") -> dict:
        return {
            "ip": ip,
            "risk_score": 0,
            "is_whitelisted": False,
            "total_reports": 0,
            "country_code": "",
            "cached": False,
            "source": reason,
            "should_block": False,
        }


# Module-level singleton
threat_intel = ThreatIntelProvider()
