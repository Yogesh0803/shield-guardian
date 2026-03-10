"""
Explainable AI module for Guardian Shield ML predictions.

Provides feature-importance explanations for anomaly/attack predictions
so security analysts can understand WHY a flow was flagged.

Architecture decisions:
    - Uses SHAP (TreeExplainer) when the model is XGBoost, since it is
      optimised for tree-based models and runs in milliseconds.
    - Falls back to a lightweight feature-magnitude approach when SHAP
      is unavailable or the model doesn't support it.
    - Explanation is optional and gated by a config flag.  When disabled
      the module returns an empty explanation dict with zero overhead.
    - Explanation data is attached to the Prediction dataclass so it
      flows through the existing pipeline to alerts and the dashboard.

Performance:
    SHAP TreeExplainer for XGBoost typically takes <5 ms per sample.
    The fallback magnitude method takes <1 ms.  Neither should impact
    real-time processing at the expected throughput (~30 flows/min).
"""

import logging
import time
from typing import Dict, List, Optional, Any

import numpy as np

logger = logging.getLogger("guardian-shield.explainer")

# Feature names matching CICIDS2017 layout (first 40 = flow features).
# Must stay in sync with capture/feature_extractor.py FEATURE_NAMES.
FEATURE_NAMES = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_length_fwd", "total_length_bwd",
    "fwd_packet_length_max", "fwd_packet_length_min",
    "fwd_packet_length_mean", "fwd_packet_length_std",
    "bwd_packet_length_max", "bwd_packet_length_min",
    "bwd_packet_length_mean", "bwd_packet_length_std",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_header_length", "bwd_header_length",
    "fwd_packets_per_sec", "bwd_packets_per_sec",
    "packet_length_mean", "packet_length_std", "packet_length_variance",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count",
]

# Pad to 80 features if models use zero-padded context features
FEATURE_NAMES_80 = FEATURE_NAMES + [
    f"context_feature_{i}" for i in range(40, 80)
]


class PredictionExplainer:
    """Generates human-readable explanations for ML predictions."""

    def __init__(self, enabled: bool = True, top_n: int = 5):
        self.enabled = enabled
        self.top_n = top_n
        self._shap_explainer = None
        self._shap_available = False

        # Try to import SHAP lazily to avoid hard dependency
        try:
            import shap  # noqa: F401
            self._shap_available = True
        except ImportError:
            logger.info(
                "SHAP not installed — using feature-magnitude fallback. "
                "Install with: pip install shap"
            )

    def init_shap(self, model) -> bool:
        """Initialize SHAP TreeExplainer for an XGBoost model.

        Called once after model loading.  Returns True on success.
        """
        if not self.enabled or not self._shap_available:
            return False

        try:
            import shap
            self._shap_explainer = shap.TreeExplainer(model)
            logger.info("SHAP TreeExplainer initialized for attack classifier")
            return True
        except Exception as e:
            logger.warning(f"SHAP init failed (falling back to magnitude): {e}")
            self._shap_explainer = None
            return False

    def explain(
        self,
        features: np.ndarray,
        prediction: str,
        confidence: float,
        anomaly_score: float,
        scaler=None,
    ) -> Dict[str, Any]:
        """Generate explanation for a single prediction.

        Args:
            features: Raw feature vector (40 or 80 elements).
            prediction: Attack type string ("DDoS", "Benign", etc.).
            confidence: Model confidence (0-1).
            anomaly_score: Anomaly score (0-1).
            scaler: Optional sklearn scaler used by the classifier.

        Returns:
            Dict with prediction, confidence, and top_features list.
            Returns empty dict if explainability is disabled.
        """
        if not self.enabled:
            return {}

        start = time.time()

        # Select appropriate feature names
        n_features = len(features)
        names = FEATURE_NAMES_80[:n_features] if n_features > 40 else FEATURE_NAMES[:n_features]

        # Try SHAP first, then fall back to magnitude
        top_features = self._explain_shap(features, names, scaler)
        if not top_features:
            top_features = self._explain_magnitude(features, names, scaler)

        elapsed_ms = (time.time() - start) * 1000
        if elapsed_ms > 50:
            logger.warning(
                f"Explanation took {elapsed_ms:.1f}ms — consider disabling "
                "for high-throughput deployments"
            )

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
            "top_features": top_features,
            "method": "shap" if self._shap_explainer else "magnitude",
            "explanation_time_ms": round(elapsed_ms, 2),
        }

    # ------------------------------------------------------------------
    # SHAP-based explanation (preferred for XGBoost)
    # ------------------------------------------------------------------

    def _explain_shap(
        self, features: np.ndarray, names: List[str], scaler=None
    ) -> List[Dict[str, Any]]:
        """Use SHAP TreeExplainer to get feature importances."""
        if self._shap_explainer is None:
            return []

        try:
            features_2d = features.reshape(1, -1)
            if scaler is not None:
                features_2d = scaler.transform(features_2d)
            features_2d = np.clip(features_2d, -10, 10)

            shap_values = self._shap_explainer.shap_values(features_2d)

            # shap_values may be a list (one per class) or a 2D array
            if isinstance(shap_values, list):
                # Average absolute SHAP across classes
                combined = np.mean(
                    [np.abs(sv) for sv in shap_values], axis=0
                )[0]
            else:
                combined = np.abs(shap_values[0])

            return self._top_features_from_importances(combined, names, features)

        except Exception as e:
            logger.debug(f"SHAP explanation failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Magnitude-based fallback (no external dependency)
    # ------------------------------------------------------------------

    def _explain_magnitude(
        self, features: np.ndarray, names: List[str], scaler=None
    ) -> List[Dict[str, Any]]:
        """Rank features by their scaled absolute magnitude.

        This is a simple heuristic: features with high absolute values
        after scaling are more likely to have influenced the prediction.
        """
        try:
            vals = features.copy().astype(float)
            if scaler is not None:
                vals = scaler.transform(vals.reshape(1, -1))[0]
            abs_vals = np.abs(vals)
            return self._top_features_from_importances(abs_vals, names, features)
        except Exception as e:
            logger.debug(f"Magnitude explanation failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Shared formatting
    # ------------------------------------------------------------------

    def _top_features_from_importances(
        self,
        importances: np.ndarray,
        names: List[str],
        raw_features: np.ndarray,
    ) -> List[Dict[str, Any]]:
        """Return the top-N features sorted by importance."""
        top_idx = np.argsort(importances)[::-1][: self.top_n]
        result = []
        for idx in top_idx:
            if idx < len(names) and importances[idx] > 0:
                result.append({
                    "feature": names[idx],
                    "importance": round(float(importances[idx]), 4),
                    "value": round(float(raw_features[idx]), 4)
                    if idx < len(raw_features)
                    else None,
                })
        return result


# Module-level singleton
explainer = PredictionExplainer()
