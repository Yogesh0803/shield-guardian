"""
Model drift monitoring for Guardian Shield ML engine.

Tracks prediction distribution, confidence averages, and anomaly rates
over sliding time windows.  Exposes metrics through a simple API that
the backend can query and forward to the dashboard.

Architecture decision:
    All state is kept in-memory using deques with configurable window
    sizes.  This avoids DB writes on the prediction hot path.  The
    backend polls metrics via GET /api/ml/metrics and serves them to
    the dashboard.

Thread safety:
    A threading.Lock guards all mutable collections so this module
    can be called safely from the ML engine's capture threads.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger("guardian-shield.model-drift")


@dataclass
class DriftConfig:
    """Configuration for drift monitoring."""
    # Sliding window size (seconds) for rate calculations
    window_seconds: int = 300  # 5 minutes

    # Maximum entries to keep (prevents unbounded memory growth)
    max_entries: int = 50_000

    # Confidence drop threshold — if avg confidence drops below this
    # compared to the running baseline, a drift warning is emitted.
    confidence_drift_threshold: float = 0.15

    # Anomaly rate spike threshold — if the anomaly rate exceeds this
    # multiple of the baseline, a drift warning is emitted.
    anomaly_rate_spike_factor: float = 3.0

    # Feature toggle
    enabled: bool = True


@dataclass
class _PredictionEntry:
    """Lightweight record of a single prediction for drift tracking."""
    timestamp: float
    attack_type: str
    confidence: float
    anomaly_score: float
    is_anomaly: bool
    action: str


class ModelDriftMonitor:
    """Tracks ML prediction distribution and detects model drift."""

    def __init__(self, config: Optional[DriftConfig] = None):
        self.config = config or DriftConfig()
        self._entries: deque = deque(maxlen=self.config.max_entries)
        self._lock = threading.Lock()

        # Running baselines (updated periodically)
        self._baseline_confidence: float = 0.0
        self._baseline_anomaly_rate: float = 0.0
        self._baseline_samples: int = 0

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_prediction(
        self,
        attack_type: str,
        confidence: float,
        anomaly_score: float,
        is_anomaly: bool,
        action: str,
    ):
        """Record a prediction for drift tracking.

        Called from the inference pipeline after every prediction.
        Must be fast — O(1) amortized.
        """
        if not self.config.enabled:
            return

        entry = _PredictionEntry(
            timestamp=time.time(),
            attack_type=attack_type,
            confidence=confidence,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            action=action,
        )

        with self._lock:
            self._entries.append(entry)
            # Update running baseline (exponential moving average)
            n = self._baseline_samples + 1
            self._baseline_confidence = (
                self._baseline_confidence * self._baseline_samples + confidence
            ) / n
            self._baseline_anomaly_rate = (
                self._baseline_anomaly_rate * self._baseline_samples
                + (1.0 if is_anomaly else 0.0)
            ) / n
            self._baseline_samples = min(n, 100_000)  # cap to prevent drift in EMA

    # ------------------------------------------------------------------
    # Metrics retrieval
    # ------------------------------------------------------------------

    def get_metrics(self) -> dict:
        """Return current drift metrics for the API.

        Returns dict with:
            predictions_per_min, anomaly_rate, model_confidence_avg,
            distribution_summary, drift_detected, drift_details
        """
        now = time.time()
        window_start = now - self.config.window_seconds

        with self._lock:
            recent = [e for e in self._entries if e.timestamp >= window_start]

        if not recent:
            return {
                "predictions_per_min": 0.0,
                "anomaly_rate": 0.0,
                "model_confidence_avg": 0.0,
                "distribution_summary": {},
                "drift_detected": False,
                "drift_details": [],
                "window_seconds": self.config.window_seconds,
                "total_tracked": len(self._entries),
            }

        # Predictions per minute
        elapsed_min = max((now - recent[0].timestamp) / 60.0, 1 / 60)
        predictions_per_min = round(len(recent) / elapsed_min, 1)

        # Anomaly rate
        anomaly_count = sum(1 for e in recent if e.is_anomaly)
        anomaly_rate = round(anomaly_count / len(recent), 4)

        # Confidence average
        confidence_avg = round(
            sum(e.confidence for e in recent) / len(recent), 4
        )

        # Distribution summary
        distribution: Dict[str, int] = defaultdict(int)
        for e in recent:
            distribution[e.attack_type] += 1
        distribution_summary = dict(distribution)

        # Action distribution
        action_dist: Dict[str, int] = defaultdict(int)
        for e in recent:
            action_dist[e.action] += 1

        # Drift detection
        drift_detected, drift_details = self._check_drift(
            anomaly_rate, confidence_avg
        )

        return {
            "predictions_per_min": predictions_per_min,
            "anomaly_rate": anomaly_rate,
            "model_confidence_avg": confidence_avg,
            "distribution_summary": distribution_summary,
            "action_distribution": dict(action_dist),
            "drift_detected": drift_detected,
            "drift_details": drift_details,
            "window_seconds": self.config.window_seconds,
            "total_tracked": len(self._entries),
        }

    # ------------------------------------------------------------------
    # Drift detection
    # ------------------------------------------------------------------

    def _check_drift(
        self, current_anomaly_rate: float, current_confidence: float
    ) -> tuple:
        """Compare current window metrics against running baseline.

        Returns (drift_detected: bool, details: list[str]).
        """
        details = []

        if self._baseline_samples < 100:
            # Not enough data for a meaningful baseline
            return False, details

        # Confidence drop
        confidence_drop = self._baseline_confidence - current_confidence
        if confidence_drop > self.config.confidence_drift_threshold:
            details.append(
                f"Confidence dropped by {confidence_drop:.3f} "
                f"(baseline: {self._baseline_confidence:.3f}, "
                f"current: {current_confidence:.3f})"
            )

        # Anomaly rate spike
        if self._baseline_anomaly_rate > 0:
            spike_factor = current_anomaly_rate / max(self._baseline_anomaly_rate, 0.001)
            if spike_factor > self.config.anomaly_rate_spike_factor:
                details.append(
                    f"Anomaly rate spiked {spike_factor:.1f}x "
                    f"(baseline: {self._baseline_anomaly_rate:.3f}, "
                    f"current: {current_anomaly_rate:.3f})"
                )

        return len(details) > 0, details

    def reset(self):
        """Clear all tracked data and baselines."""
        with self._lock:
            self._entries.clear()
            self._baseline_confidence = 0.0
            self._baseline_anomaly_rate = 0.0
            self._baseline_samples = 0


# Module-level singleton
drift_monitor = ModelDriftMonitor()
