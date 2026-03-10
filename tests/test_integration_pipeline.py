"""
Integration test: simulates the full security-feature pipeline.

Creates a mock flow, pushes it through rate limiter → ML inference →
drift monitoring → explainability → security logging, and verifies
that each stage produces the expected artefacts.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
import numpy as np


class TestFullPipelineIntegration:
    """End-to-end integration of all 5 security features."""

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _make_flow(src_ip="192.168.1.100", dst_ip="10.0.0.1",
                   src_port=54321, dst_port=80, protocol="TCP"):
        """Return a minimal Flow-like object for testing."""
        flow = MagicMock()
        flow.flow_id = "test-flow-001"
        flow.src_ip = src_ip
        flow.dst_ip = dst_ip
        flow.src_port = src_port
        flow.dst_port = dst_port
        flow.protocol = protocol
        flow.tcp_flags = ""
        flow.packet_count = 10
        flow.total_bytes = 5000
        flow.duration = 1.5
        flow.packets = []
        return flow

    # ── Stage 1: Rate limiter + security logger ─────────────────────

    def test_rate_limiter_blocks_and_logs(self):
        """Rate limiter blocks abusive IP; security logger records it."""
        from backend.app.security.rate_limiter import RateLimiter, RateLimitConfig
        from backend.app.utils.security_logger import SecurityLogger

        rl = RateLimiter(config=RateLimitConfig(max_packets_per_minute=3))
        sl = SecurityLogger(logger=MagicMock())
        now = time.time()

        # Send 3 packets (under limit)
        for i in range(3):
            allowed, _ = rl.check_packet("192.168.1.100", now=now + i * 0.01)
            assert allowed

        # 4th packet should be blocked
        allowed, reason = rl.check_packet("192.168.1.100", now=now + 0.05)
        assert not allowed
        assert reason == "packets_per_minute"

        # Log the rate-limit event
        event = sl.rate_limit_exceeded(
            source_ip="192.168.1.100",
            request_count=4,
            window_seconds=60,
            limit=3,
            reason=reason,
        )
        assert event["event_type"] == "rate_limit_exceeded"
        assert event["source_ip"] == "192.168.1.100"

    # ── Stage 2: Threat intel enrichment ────────────────────────────

    def test_threat_intel_enriches_anomaly_score(self):
        """Cached threat-intel score should boost the anomaly score."""
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )

        cfg = ThreatIntelConfig(
            enabled=True, abuseipdb_api_key="fake",
            anomaly_weight_boost=0.2,
        )
        ti = ThreatIntelProvider(config=cfg)

        # Inject a bad-reputation cache entry
        ti._cache["192.168.1.100"] = _CacheEntry(
            risk_score=90, is_whitelisted=False, total_reports=50,
            country_code="US", fetched_at=time.time(),
        )

        base_score = 0.6
        adjusted = ti.adjust_anomaly_score("192.168.1.100", base_score)
        assert adjusted > base_score
        assert adjusted <= 1.0

    # ── Stage 3: Drift monitoring records predictions ───────────────

    def test_drift_monitor_records_and_reports(self):
        """Drift monitor tracks predictions and produces metrics."""
        from ml.monitoring.model_drift import ModelDriftMonitor, DriftConfig

        mon = ModelDriftMonitor(config=DriftConfig(window_seconds=600))

        # Simulate a batch of predictions
        for _ in range(30):
            mon.record_prediction("Benign", 0.92, 0.08, False, "allow")
        for _ in range(10):
            mon.record_prediction("DDoS", 0.85, 0.91, True, "block")

        metrics = mon.get_metrics()
        assert metrics["total_tracked"] == 40
        assert metrics["anomaly_rate"] == pytest.approx(0.25, abs=0.01)
        assert "DDoS" in metrics["distribution_summary"]
        assert "block" in metrics["action_distribution"]

    # ── Stage 4: Explainer produces explanations ────────────────────

    def test_explainer_generates_explanation(self):
        """Explainer should return top features via magnitude fallback."""
        from ml.explainability.explainer import PredictionExplainer

        exp = PredictionExplainer(enabled=True, top_n=5)
        exp._shap_explainer = None  # force magnitude fallback

        features = np.random.rand(40).astype(np.float32) * 10
        result = exp.explain(
            features=features, prediction="DDoS",
            confidence=0.85, anomaly_score=0.91,
        )
        assert result["prediction"] == "DDoS"
        assert len(result["top_features"]) > 0
        assert result["method"] == "magnitude"

    # ── Stage 5: Full flow → all stages combined ────────────────────

    def test_end_to_end_flow(self):
        """
        Simulate the full path a malicious flow takes through the system:
        1. Rate limiter allows it (under limit)
        2. Threat intel adjusts score
        3. Drift monitor records prediction
        4. Explainer produces explanation
        5. Security logger records the event
        """
        from backend.app.security.rate_limiter import RateLimiter, RateLimitConfig
        from backend.app.security.threat_intel import (
            ThreatIntelProvider, ThreatIntelConfig, _CacheEntry,
        )
        from ml.monitoring.model_drift import ModelDriftMonitor, DriftConfig
        from ml.explainability.explainer import PredictionExplainer
        from backend.app.utils.security_logger import SecurityLogger

        # -- Setup --
        rl = RateLimiter(config=RateLimitConfig(max_packets_per_minute=100))
        ti = ThreatIntelProvider(config=ThreatIntelConfig(
            enabled=True, abuseipdb_api_key="test",
            anomaly_weight_boost=0.2,
        ))
        ti._cache["10.0.0.99"] = _CacheEntry(
            risk_score=85, is_whitelisted=False, total_reports=30,
            country_code="CN", fetched_at=time.time(),
        )
        mon = ModelDriftMonitor(config=DriftConfig())
        exp = PredictionExplainer(enabled=True, top_n=5)
        exp._shap_explainer = None
        sl = SecurityLogger(logger=MagicMock())

        # -- Step 1: Rate limiter allows --
        allowed, _ = rl.check_packet("10.0.0.99", dst_port=80)
        assert allowed

        # -- Step 2: Threat intel adjustment --
        base_score = 0.7
        adjusted = ti.adjust_anomaly_score("10.0.0.99", base_score)
        assert adjusted > base_score

        # -- Step 3: Record prediction in drift monitor --
        mon.record_prediction(
            attack_type="DDoS", confidence=0.88,
            anomaly_score=adjusted, is_anomaly=True, action="block",
        )
        metrics = mon.get_metrics()
        assert metrics["total_tracked"] == 1
        assert metrics["anomaly_rate"] == 1.0

        # -- Step 4: Explain prediction --
        features = np.random.rand(40).astype(np.float32)
        explanation = exp.explain(
            features=features, prediction="DDoS",
            confidence=0.88, anomaly_score=adjusted,
        )
        assert "top_features" in explanation
        assert explanation["prediction"] == "DDoS"

        # -- Step 5: Security log --
        event = sl.model_prediction(
            source_ip="10.0.0.99", destination_ip="192.168.1.1",
            anomaly_score=adjusted, attack_type="DDoS",
            confidence=0.88, action="block", model="ensemble",
        )
        assert event["event_type"] == "model_prediction"
        assert event["action"] == "block"

        block_event = sl.ip_blocked(
            ip="10.0.0.99",
            reason="DDoS (score: {:.2f})".format(adjusted),
            duration=300,
        )
        assert block_event["event_type"] == "ip_blocked"

    # ── Cross-feature interaction tests ─────────────────────────────

    def test_rate_limited_ip_skips_remaining_pipeline(self):
        """When rate limiter blocks, ML pipeline should NOT run."""
        from backend.app.security.rate_limiter import RateLimiter, RateLimitConfig
        from ml.monitoring.model_drift import ModelDriftMonitor, DriftConfig

        rl = RateLimiter(config=RateLimitConfig(max_packets_per_minute=2))
        mon = ModelDriftMonitor(config=DriftConfig())

        now = time.time()
        for i in range(3):
            allowed, reason = rl.check_packet("attacker.ip", now=now + i * 0.001)
            if allowed:
                # Only record if allowed (mimics ml/main.py logic)
                mon.record_prediction("Benign", 0.9, 0.1, False, "allow")

        # Only 2 predictions recorded (3rd was rate-limited)
        assert mon.get_metrics()["total_tracked"] == 2

    def test_drift_metrics_match_api_schema(self):
        """Drift metrics should contain all keys expected by the API."""
        from ml.monitoring.model_drift import ModelDriftMonitor

        mon = ModelDriftMonitor()
        mon.record_prediction("Benign", 0.9, 0.1, False, "allow")
        metrics = mon.get_metrics()

        expected_keys = {
            "predictions_per_min", "anomaly_rate", "model_confidence_avg",
            "distribution_summary", "action_distribution", "drift_detected",
            "drift_details", "window_seconds", "total_tracked",
        }
        assert expected_keys.issubset(set(metrics.keys()))
