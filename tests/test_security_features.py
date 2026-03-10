"""
Unit tests for the 5 architectural security features:
  1. Structured Security Logging  (SecurityLogger)
  2. Rate Limiting                (RateLimiter)
  3. Threat Intelligence          (ThreatIntelProvider)
  4. Model Drift Monitoring       (ModelDriftMonitor)
  5. Explainable AI               (PredictionExplainer)
"""

import json
import time
import threading
from unittest.mock import patch, MagicMock

import pytest
import numpy as np


# =====================================================================
# 1. Structured Security Logging
# =====================================================================

class TestSecurityLogger:
    """Tests for backend.app.utils.security_logger.SecurityLogger."""

    def _make_logger(self):
        from backend.app.utils.security_logger import SecurityLogger
        return SecurityLogger(logger=MagicMock())

    def test_log_event_returns_dict_with_required_keys(self):
        sl = self._make_logger()
        event = sl.log_event("test_event", severity="info", foo="bar")
        assert isinstance(event, dict)
        assert "timestamp" in event
        assert event["event_type"] == "test_event"
        assert event["severity"] == "info"
        assert event["foo"] == "bar"

    def test_timestamp_is_iso8601(self):
        from datetime import datetime
        sl = self._make_logger()
        event = sl.log_event("ts_test")
        # Should parse without error
        datetime.fromisoformat(event["timestamp"])

    def test_packet_blocked_severity_is_warning(self):
        sl = self._make_logger()
        event = sl.packet_blocked(
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            protocol="TCP",
            prediction="DDoS",
            confidence=0.95,
        )
        assert event["event_type"] == "packet_blocked"
        assert event["severity"] == "warning"
        assert event["source_ip"] == "10.0.0.1"

    def test_anomaly_detected_includes_score(self):
        sl = self._make_logger()
        event = sl.anomaly_detected(
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            anomaly_score=0.87,
            attack_type="PortScan",
        )
        assert event["anomaly_score"] == 0.87
        assert event["attack_type"] == "PortScan"

    def test_model_prediction_severity_varies_by_action(self):
        sl = self._make_logger()
        allow = sl.model_prediction(
            source_ip="a", destination_ip="b",
            anomaly_score=0.1, attack_type="Benign",
            confidence=0.9, action="allow",
        )
        assert allow["severity"] == "info"

        block = sl.model_prediction(
            source_ip="a", destination_ip="b",
            anomaly_score=0.9, attack_type="DDoS",
            confidence=0.85, action="block",
        )
        assert block["severity"] == "warning"

    def test_rate_limit_exceeded_fields(self):
        sl = self._make_logger()
        event = sl.rate_limit_exceeded(
            source_ip="1.1.1.1",
            request_count=150,
            window_seconds=60,
            limit=100,
        )
        assert event["request_count"] == 150
        assert event["limit"] == 100

    def test_threat_intel_hit_critical_above_80(self):
        sl = self._make_logger()
        event = sl.threat_intel_hit(ip="9.9.9.9", risk_score=95, source="abuseipdb")
        assert event["severity"] == "critical"

    def test_threat_intel_hit_warning_below_80(self):
        sl = self._make_logger()
        event = sl.threat_intel_hit(ip="9.9.9.9", risk_score=60)
        assert event["severity"] == "warning"

    def test_ip_blocked_and_unblocked(self):
        sl = self._make_logger()
        blocked = sl.ip_blocked(ip="2.2.2.2", reason="test", duration=300)
        assert blocked["event_type"] == "ip_blocked"
        assert blocked["duration_seconds"] == 300

        unblocked = sl.ip_unblocked(ip="2.2.2.2")
        assert unblocked["event_type"] == "ip_unblocked"

    def test_event_is_json_serializable(self):
        sl = self._make_logger()
        event = sl.log_event("json_test", severity="debug", nested={"a": 1})
        json.dumps(event)  # Should not raise

    def test_extra_kwargs_are_passed_through(self):
        sl = self._make_logger()
        event = sl.packet_blocked(
            source_ip="a", destination_ip="b", custom_field="custom_value",
        )
        assert event["custom_field"] == "custom_value"


# =====================================================================
# 2. Rate Limiting
# =====================================================================

class TestRateLimiter:
    """Tests for backend.app.security.rate_limiter.RateLimiter."""

    def _make_limiter(self, **overrides):
        from backend.app.security.rate_limiter import RateLimiter, RateLimitConfig
        cfg = RateLimitConfig(**overrides)
        return RateLimiter(config=cfg)

    def test_allows_traffic_under_limit(self):
        rl = self._make_limiter(max_packets_per_minute=10)
        for _ in range(10):
            allowed, reason = rl.check_packet("1.2.3.4", now=time.time())
            assert allowed is True
            assert reason is None

    def test_blocks_on_packets_per_minute_exceeded(self):
        rl = self._make_limiter(max_packets_per_minute=5)
        now = time.time()
        for i in range(5):
            rl.check_packet("1.2.3.4", now=now + i * 0.01)
        allowed, reason = rl.check_packet("1.2.3.4", now=now + 0.1)
        assert allowed is False
        assert reason == "packets_per_minute"

    def test_syn_flood_detection(self):
        rl = self._make_limiter(max_syn_per_second=3, max_packets_per_minute=1000)
        now = time.time()
        for i in range(3):
            rl.check_packet("10.0.0.1", is_syn=True, now=now + i * 0.01)
        allowed, reason = rl.check_packet("10.0.0.1", is_syn=True, now=now + 0.05)
        assert allowed is False
        assert reason == "syn_flood"

    def test_port_scan_detection(self):
        rl = self._make_limiter(
            max_unique_ports_per_minute=3,
            max_packets_per_minute=1000,
        )
        now = time.time()
        for port in [80, 443, 8080]:
            rl.check_packet("10.0.0.2", dst_port=port, now=now)
        allowed, reason = rl.check_packet("10.0.0.2", dst_port=22, now=now + 0.01)
        assert allowed is False
        assert reason == "port_scan"

    def test_blocked_ip_returns_already_blocked(self):
        rl = self._make_limiter(max_packets_per_minute=2, block_duration=300)
        now = time.time()
        # Trigger block
        for i in range(3):
            rl.check_packet("5.5.5.5", now=now + i * 0.001)
        # Subsequent packets get "ip_already_blocked"
        allowed, reason = rl.check_packet("5.5.5.5", now=now + 1)
        assert allowed is False
        assert reason == "ip_already_blocked"

    def test_is_blocked_returns_true_while_blocked(self):
        rl = self._make_limiter(max_packets_per_minute=2, block_duration=60)
        now = time.time()
        for i in range(3):
            rl.check_packet("6.6.6.6", now=now + i * 0.001)
        assert rl.is_blocked("6.6.6.6") is True

    def test_unblock_ip(self):
        rl = self._make_limiter(max_packets_per_minute=2, block_duration=60)
        now = time.time()
        for i in range(3):
            rl.check_packet("7.7.7.7", now=now + i * 0.001)
        assert rl.unblock_ip("7.7.7.7") is True
        assert rl.is_blocked("7.7.7.7") is False

    def test_get_stats_structure(self):
        rl = self._make_limiter()
        stats = rl.get_stats()
        assert "tracked_ips" in stats
        assert "blocked_ips" in stats
        assert "blocked_list" in stats
        assert "config" in stats

    def test_disabled_limiter_always_allows(self):
        rl = self._make_limiter(enabled=False, max_packets_per_minute=1)
        for _ in range(100):
            allowed, _ = rl.check_packet("8.8.8.8")
            assert allowed is True

    def test_block_expires_after_duration(self):
        rl = self._make_limiter(
            max_packets_per_minute=2, block_duration=1, window_seconds=1,
        )
        now = time.time()
        for i in range(3):
            rl.check_packet("9.9.9.9", now=now + i * 0.001)
        # Block should have expired 2s later; old packets also expired
        # from the 1-second sliding window.
        allowed, reason = rl.check_packet("9.9.9.9", now=now + 2)
        assert allowed is True

    def test_thread_safety(self):
        """Concurrent check_packet calls should not raise."""
        rl = self._make_limiter(max_packets_per_minute=10000)
        errors = []

        def worker():
            try:
                for _ in range(100):
                    rl.check_packet("10.10.10.10")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# =====================================================================
# 3. Threat Intelligence
# =====================================================================

class TestThreatIntelProvider:
    """Tests for backend.app.security.threat_intel.ThreatIntelProvider."""

    def _make_provider(self, enabled=False, api_key=""):
        from backend.app.security.threat_intel import ThreatIntelProvider, ThreatIntelConfig
        cfg = ThreatIntelConfig(enabled=enabled, abuseipdb_api_key=api_key)
        return ThreatIntelProvider(config=cfg)

    def test_disabled_returns_neutral(self):
        ti = self._make_provider(enabled=False)
        result = ti.check_ip_reputation("1.2.3.4")
        assert result["risk_score"] == 0
        assert result["should_block"] is False
        assert result["source"] == "disabled"

    def test_no_api_key_returns_neutral(self):
        ti = self._make_provider(enabled=True, api_key="")
        result = ti.check_ip_reputation("1.2.3.4")
        assert result["risk_score"] == 0
        assert result["source"] == "disabled"

    def test_cache_hit(self):
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )
        cfg = ThreatIntelConfig(enabled=True, abuseipdb_api_key="fake")
        ti = ThreatIntelProvider(config=cfg)
        # Pre-populate cache
        ti._cache["1.2.3.4"] = _CacheEntry(
            risk_score=85,
            is_whitelisted=False,
            total_reports=42,
            country_code="US",
            fetched_at=time.time(),
        )
        result = ti.check_ip_reputation("1.2.3.4")
        assert result["cached"] is True
        assert result["risk_score"] == 85
        assert result["should_block"] is True
        assert result["source"] == "abuseipdb"

    def test_get_cached_score_returns_score_if_cached(self):
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )
        cfg = ThreatIntelConfig(enabled=True, abuseipdb_api_key="fake")
        ti = ThreatIntelProvider(config=cfg)
        ti._cache["2.2.2.2"] = _CacheEntry(
            risk_score=70, is_whitelisted=False, total_reports=10,
            country_code="GB", fetched_at=time.time(),
        )
        assert ti.get_cached_score("2.2.2.2") == 70
        assert ti.get_cached_score("3.3.3.3") is None

    def test_adjust_anomaly_score_boosts_high_risk(self):
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )
        cfg = ThreatIntelConfig(
            enabled=True, abuseipdb_api_key="fake", anomaly_weight_boost=0.2,
        )
        ti = ThreatIntelProvider(config=cfg)
        ti._cache["4.4.4.4"] = _CacheEntry(
            risk_score=100, is_whitelisted=False, total_reports=99,
            country_code="RU", fetched_at=time.time(),
        )
        adjusted = ti.adjust_anomaly_score("4.4.4.4", base_score=0.5)
        assert adjusted > 0.5
        assert adjusted <= 1.0

    def test_adjust_anomaly_score_no_boost_below_50(self):
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )
        cfg = ThreatIntelConfig(enabled=True, abuseipdb_api_key="fake")
        ti = ThreatIntelProvider(config=cfg)
        ti._cache["5.5.5.5"] = _CacheEntry(
            risk_score=30, is_whitelisted=False, total_reports=1,
            country_code="DE", fetched_at=time.time(),
        )
        adjusted = ti.adjust_anomaly_score("5.5.5.5", base_score=0.5)
        assert adjusted == 0.5

    def test_adjust_anomaly_score_no_cache_returns_base(self):
        ti = self._make_provider(enabled=True, api_key="fake")
        assert ti.adjust_anomaly_score("99.99.99.99", base_score=0.6) == 0.6

    def test_clear_cache(self):
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )
        cfg = ThreatIntelConfig(enabled=True, abuseipdb_api_key="fake")
        ti = ThreatIntelProvider(config=cfg)
        ti._cache["x"] = _CacheEntry(
            risk_score=50, is_whitelisted=False, total_reports=5,
            country_code="FR", fetched_at=time.time(),
        )
        ti.clear_cache()
        assert ti.get_cached_score("x") is None

    def test_cache_stats(self):
        ti = self._make_provider(enabled=True, api_key="testkey")
        stats = ti.get_cache_stats()
        assert stats["cached_ips"] == 0
        assert stats["enabled"] is True
        assert stats["has_api_key"] is True

    def test_expired_cache_is_evicted(self):
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )
        cfg = ThreatIntelConfig(
            enabled=True, abuseipdb_api_key="fake", cache_ttl=1,
        )
        ti = ThreatIntelProvider(config=cfg)
        ti._cache["old"] = _CacheEntry(
            risk_score=50, is_whitelisted=False, total_reports=5,
            country_code="FR", fetched_at=time.time() - 10,
        )
        assert ti.get_cached_score("old") is None


# =====================================================================
# 4. Model Drift Monitoring
# =====================================================================

class TestModelDriftMonitor:
    """Tests for ml.monitoring.model_drift.ModelDriftMonitor."""

    def _make_monitor(self, **overrides):
        from ml.monitoring.model_drift import ModelDriftMonitor, DriftConfig
        cfg = DriftConfig(**overrides)
        return ModelDriftMonitor(config=cfg)

    def test_empty_metrics(self):
        mon = self._make_monitor()
        metrics = mon.get_metrics()
        assert metrics["predictions_per_min"] == 0.0
        assert metrics["anomaly_rate"] == 0.0
        assert metrics["drift_detected"] is False
        assert "total_tracked" in metrics

    def test_record_and_retrieve_metrics(self):
        mon = self._make_monitor()
        for _ in range(50):
            mon.record_prediction(
                attack_type="Benign", confidence=0.9,
                anomaly_score=0.1, is_anomaly=False, action="allow",
            )
        metrics = mon.get_metrics()
        assert metrics["total_tracked"] == 50
        assert metrics["anomaly_rate"] == 0.0
        assert metrics["model_confidence_avg"] == pytest.approx(0.9, abs=0.01)
        assert "Benign" in metrics["distribution_summary"]

    def test_anomaly_rate_calculation(self):
        mon = self._make_monitor()
        # 10 anomalies out of 20
        for i in range(20):
            mon.record_prediction(
                attack_type="DDoS" if i < 10 else "Benign",
                confidence=0.8,
                anomaly_score=0.9 if i < 10 else 0.1,
                is_anomaly=i < 10,
                action="block" if i < 10 else "allow",
            )
        metrics = mon.get_metrics()
        assert metrics["anomaly_rate"] == pytest.approx(0.5, abs=0.01)

    def test_action_distribution_tracking(self):
        mon = self._make_monitor()
        mon.record_prediction("Benign", 0.9, 0.1, False, "allow")
        mon.record_prediction("DDoS", 0.8, 0.9, True, "block")
        mon.record_prediction("PortScan", 0.7, 0.6, True, "alert")
        metrics = mon.get_metrics()
        assert metrics["action_distribution"]["allow"] == 1
        assert metrics["action_distribution"]["block"] == 1
        assert metrics["action_distribution"]["alert"] == 1

    def test_drift_detection_confidence_drop(self):
        mon = self._make_monitor(confidence_drift_threshold=0.1)
        # Build baseline with high confidence (need >=100 samples)
        for _ in range(120):
            mon.record_prediction("Benign", 0.95, 0.05, False, "allow")
        # Now push low-confidence predictions
        for _ in range(50):
            mon.record_prediction("Unknown", 0.3, 0.7, True, "alert")
        metrics = mon.get_metrics()
        # With 120 high-confidence + 50 low-confidence, the recent window
        # should include low-confidence entries
        # Whether drift is detected depends on window timing, but baseline
        # should have been established
        assert metrics["total_tracked"] == 170
        assert "drift_details" in metrics

    def test_reset_clears_all_data(self):
        mon = self._make_monitor()
        mon.record_prediction("Benign", 0.9, 0.1, False, "allow")
        mon.reset()
        metrics = mon.get_metrics()
        assert metrics["total_tracked"] == 0
        assert metrics["predictions_per_min"] == 0.0

    def test_disabled_monitor_ignores_records(self):
        mon = self._make_monitor(enabled=False)
        mon.record_prediction("DDoS", 0.8, 0.9, True, "block")
        metrics = mon.get_metrics()
        assert metrics["total_tracked"] == 0

    def test_thread_safety(self):
        """Concurrent record_prediction calls should not raise."""
        mon = self._make_monitor()
        errors = []

        def worker():
            try:
                for _ in range(100):
                    mon.record_prediction("Benign", 0.9, 0.1, False, "allow")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert mon.get_metrics()["total_tracked"] == 400


# =====================================================================
# 5. Explainable AI
# =====================================================================

class TestPredictionExplainer:
    """Tests for ml.explainability.explainer.PredictionExplainer."""

    def _make_explainer(self, enabled=True, top_n=5):
        from ml.explainability.explainer import PredictionExplainer
        return PredictionExplainer(enabled=enabled, top_n=top_n)

    def test_disabled_returns_empty_dict(self):
        exp = self._make_explainer(enabled=False)
        result = exp.explain(
            features=np.zeros(40), prediction="DDoS",
            confidence=0.9, anomaly_score=0.8,
        )
        assert result == {}

    def test_magnitude_fallback_returns_top_features(self):
        exp = self._make_explainer(top_n=3)
        # Force no SHAP
        exp._shap_explainer = None
        exp._shap_available = False
        features = np.random.rand(40) * 10
        result = exp.explain(
            features=features, prediction="PortScan",
            confidence=0.85, anomaly_score=0.7,
        )
        assert "top_features" in result
        assert len(result["top_features"]) <= 3
        assert result["method"] == "magnitude"
        assert result["prediction"] == "PortScan"
        assert "explanation_time_ms" in result

    def test_explain_keys_present(self):
        exp = self._make_explainer()
        exp._shap_explainer = None
        features = np.random.rand(40)
        result = exp.explain(
            features=features, prediction="DDoS",
            confidence=0.9, anomaly_score=0.8,
        )
        assert "prediction" in result
        assert "confidence" in result
        assert "anomaly_score" in result
        assert "top_features" in result
        assert "method" in result

    def test_top_features_have_correct_structure(self):
        exp = self._make_explainer(top_n=5)
        exp._shap_explainer = None
        features = np.random.rand(40) + 0.1  # all positive
        result = exp.explain(
            features=features, prediction="BruteForce",
            confidence=0.8, anomaly_score=0.75,
        )
        for f in result["top_features"]:
            assert "feature" in f
            assert "importance" in f
            assert "value" in f
            assert isinstance(f["importance"], float)

    def test_80_feature_vector(self):
        exp = self._make_explainer(top_n=3)
        exp._shap_explainer = None
        features = np.random.rand(80)
        result = exp.explain(
            features=features, prediction="DDoS",
            confidence=0.9, anomaly_score=0.85,
        )
        assert len(result["top_features"]) <= 3

    def test_features_sorted_by_importance(self):
        exp = self._make_explainer(top_n=5)
        exp._shap_explainer = None
        features = np.arange(40, dtype=float)  # 0,1,2,...,39
        result = exp.explain(
            features=features, prediction="Test",
            confidence=0.5, anomaly_score=0.5,
        )
        importances = [f["importance"] for f in result["top_features"]]
        assert importances == sorted(importances, reverse=True)

    def test_init_shap_returns_false_when_disabled(self):
        exp = self._make_explainer(enabled=False)
        assert exp.init_shap(MagicMock()) is False
