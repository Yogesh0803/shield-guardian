"""
Full inference pipeline: Flow → Context → ML Models → Decision.
This is the main entry point for analyzing network traffic.
"""

import logging
import time
import threading
from dataclasses import dataclass
from typing import Optional

import numpy as np

from ..capture.packet_capture import Flow
from ..context.context_engine import ContextEngine, FlowContext
from ..models.anomaly_detector import AnomalyDetector
from ..models.attack_classifier import AttackClassifier
from ..models.lstm_cnn import LSTMCNNDetector
from ..config import config

logger = logging.getLogger(__name__)


@dataclass
class Prediction:
    """Result of analyzing a network flow."""
    anomaly_score: float  # 0.0 - 1.0
    is_anomaly: bool
    attack_type: str  # "Benign", "DDoS", etc.
    confidence: float  # 0.0 - 1.0
    action: str  # "allow", "block", "alert"
    context: FlowContext
    timestamp: float

    def to_dict(self) -> dict:
        return {
            "anomaly_score": round(self.anomaly_score, 4),
            "attack_type": self.attack_type,
            "confidence": round(self.confidence, 4),
            "action": self.action,
            "app_name": self.context.app_name,
            "src_ip": self.context.src_ip,
            "dst_ip": self.context.dst_ip,
            "src_port": self.context.src_port,
            "dst_port": self.context.dst_port,
            "protocol": self.context.protocol,
            "context": self.context.to_dict(),
            "timestamp": self.timestamp,
        }


class InferencePipeline:
    """
    Orchestrates the full ML inference pipeline:
    1. Build context from flow
    2. Run anomaly detection (Isolation Forest + Autoencoder + LSTM+CNN)
    3. Run attack classification (XGBoost)
    4. Combine scores and make decision
    """

    def __init__(self):
        self.context_engine = ContextEngine()
        self.anomaly_detector = AnomalyDetector()
        self.attack_classifier = AttackClassifier()
        self.lstm_cnn = LSTMCNNDetector()

        # Stats (guarded by _stats_lock for cross-thread access)
        self._stats_lock = threading.Lock()
        self.total_predictions = 0
        self.total_blocked = 0
        self.total_alerts = 0
        self.total_anomalies_detected = 0
        self.total_attacks_classified = 0
        self._start_time = time.time()

    def load_models(self) -> dict:
        """Load all ML models. Returns status dict."""
        results = {}
        results["anomaly_detector"] = self.anomaly_detector.load()
        results["attack_classifier"] = self.attack_classifier.load()
        results["lstm_cnn"] = self.lstm_cnn.load()
        logger.info(f"Model load results: {results}")
        return results

    @property
    def models_loaded(self) -> list:
        """List of loaded model keys.

        Returns machine-readable identifiers that match the frontend
        ``modelInfo`` keys so the dashboard can map them to UI cards.
        """
        loaded = []
        if self.anomaly_detector.is_loaded:
            # The anomaly detector bundles Isolation Forest + Autoencoder;
            # expose both as separate keys for the frontend.
            loaded.append("isolation_forest")
            loaded.append("autoencoder")
        if self.attack_classifier.is_loaded:
            loaded.append("xgboost")
        if self.lstm_cnn.is_loaded:
            loaded.append("lstm_cnn")
        return loaded

    @property
    def predictions_per_minute(self) -> float:
        elapsed = (time.time() - self._start_time) / 60.0
        with self._stats_lock:
            count = self.total_predictions
        return count / max(elapsed, 0.01)

    def analyze(self, flow: Flow) -> Prediction:
        """
        Analyze a network flow through the full pipeline.

        Returns a Prediction with anomaly score, attack type, and recommended action.
        Exceptions are intentionally NOT caught here so callers see failures.
        """
        # 1. Build context
        logger.debug(
            f"Analyzing flow {flow.flow_id} "
            f"({flow.packet_count} pkts, {flow.total_bytes} bytes)"
        )
        context = self.context_engine.build_context(flow)

        # Use flow-only features for ML models (matches CICIDS2017 training layout)
        model_features = context.to_model_features()

        # 2. Run anomaly detection ensemble
        #    Weights are normalised so the score reaches full [0, 1]
        #    even when some ML models are not loaded.
        raw_scores = []
        total_weight = 0.0

        # Isolation Forest + Autoencoder
        if self.anomaly_detector.is_loaded:
            iso_ae_score, _ = self.anomaly_detector.predict(model_features)
            raw_scores.append((iso_ae_score, 0.4))
            total_weight += 0.4

        # LSTM+CNN
        if self.lstm_cnn.is_loaded:
            lstm_score, _ = self.lstm_cnn.predict(model_features)
            raw_scores.append((lstm_score, 0.3))
            total_weight += 0.3

        # Context-based anomaly score (from behavioral deviations)
        context_score = self._context_anomaly_score(context)
        raw_scores.append((context_score, 0.3))
        total_weight += 0.3

        # Normalise weights so they sum to 1.0 regardless of which
        # models are loaded.  This ensures context-only mode can
        # still reach anomaly_threshold_medium / _high.
        if total_weight > 0:
            anomaly_score = sum(s * w for s, w in raw_scores) / total_weight
        else:
            anomaly_score = context_score
        anomaly_score = min(max(anomaly_score, 0.0), 1.0)
        is_anomaly = anomaly_score > config.anomaly_threshold_medium

        # 3. Run attack classification (only if anomalous)
        attack_type = "Benign"
        confidence = 1.0 - anomaly_score

        if is_anomaly and self.attack_classifier.is_loaded:
            attack_type, confidence = self.attack_classifier.predict(model_features)
        elif is_anomaly:
            attack_type = "Unknown"
            confidence = anomaly_score

        # 4. Determine action
        action = self._determine_action(anomaly_score, confidence, attack_type, context)

        # Update stats
        with self._stats_lock:
            self.total_predictions += 1
            if is_anomaly:
                self.total_anomalies_detected += 1
            if is_anomaly and attack_type != "Benign" and attack_type != "Unknown":
                self.total_attacks_classified += 1
            if action == "block":
                self.total_blocked += 1
            elif action == "alert":
                self.total_alerts += 1

        logger.debug(
            f"Prediction #{self.total_predictions}: "
            f"score={anomaly_score:.3f}, type={attack_type}, "
            f"action={action}, confidence={confidence:.3f}"
        )

        return Prediction(
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            attack_type=attack_type,
            confidence=confidence,
            action=action,
            context=context,
            timestamp=time.time(),
        )

    def _context_anomaly_score(self, ctx: FlowContext) -> float:
        """Calculate anomaly score based on context features alone."""
        score = 0.0

        # High behavioral deviation
        if ctx.rate_deviation > 3.0:
            score += 0.2
        if ctx.size_deviation > 3.0:
            score += 0.15

        # New destination
        if ctx.destination_novelty > 0.8:
            score += 0.15

        # Geo anomaly
        if ctx.is_geo_anomaly:
            score += 0.15

        # Low trust app
        if ctx.app_trust_score < 0.4:
            score += 0.1

        # Late night activity
        if not ctx.is_business_hours and (ctx.hour < 6 or ctx.hour > 22):
            score += 0.1

        # Unknown app
        if ctx.app_name == "unknown":
            score += 0.15

        return min(score, 1.0)

    def _determine_action(
        self, anomaly_score: float, confidence: float, attack_type: str, ctx: FlowContext
    ) -> str:
        """Determine enforcement action based on ML results + context."""
        # High confidence threat
        if anomaly_score > config.anomaly_threshold_high and confidence > 0.8:
            return "block"

        # High anomaly but lower confidence
        if anomaly_score > config.anomaly_threshold_high:
            return "alert"

        # Medium anomaly
        if anomaly_score > config.anomaly_threshold_medium:
            # Block if it's a known dangerous attack type with decent confidence
            if attack_type in ("DDoS", "DoS", "BruteForce", "PortScan") and confidence > 0.7:
                return "block"
            return "alert"

        return "allow"

    def get_status(self) -> dict:
        """Get ML engine status with live metrics."""
        with self._stats_lock:
            total = self.total_predictions
            blocked = self.total_blocked
            alerts = self.total_alerts
            anomalies = self.total_anomalies_detected
            attacks = self.total_attacks_classified

        # Compute detection rates from actual predictions
        if total > 0:
            anomaly_detection_rate = round(anomalies / total, 4)
            classification_rate = round(attacks / max(anomalies, 1), 4)
        else:
            anomaly_detection_rate = 0.0
            classification_rate = 0.0

        return {
            "is_running": True,
            "models_loaded": self.models_loaded,
            "predictions_per_minute": round(self.predictions_per_minute, 1),
            "total_predictions": total,
            "total_blocked": blocked,
            "total_alerts": alerts,
            "total_anomalies_detected": anomalies,
            "total_attacks_classified": attacks,
            "detection_rates": {
                "anomaly_detection_rate": anomaly_detection_rate,
                "attack_classification_rate": classification_rate,
            },
            "last_retrain": None,
        }
