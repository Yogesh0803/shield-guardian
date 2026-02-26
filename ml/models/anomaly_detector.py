"""
Anomaly detection using Isolation Forest + Autoencoder ensemble.
Trained on normal traffic, flags deviations as anomalies.
"""

import os
import logging
import numpy as np
from typing import Optional, Tuple

import joblib
import torch
import torch.nn as nn

from ..config import config

logger = logging.getLogger(__name__)


# ======================== Autoencoder Model ========================

class Autoencoder(nn.Module):
    """Neural network autoencoder for anomaly detection via reconstruction error."""

    def __init__(self, input_dim: int = 80):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, 16),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Compute MSE reconstruction error per sample."""
        with torch.no_grad():
            reconstructed = self.forward(x)
            error = torch.mean((x - reconstructed) ** 2, dim=1)
        return error


# ======================== Anomaly Detector ========================

class AnomalyDetector:
    """
    Ensemble anomaly detector combining:
    1. Isolation Forest (fast, lightweight)
    2. Autoencoder (deep learning, captures nonlinear patterns)
    """

    def __init__(self):
        self.isolation_forest = None
        self.autoencoder: Optional[Autoencoder] = None
        self.ae_threshold: float = 0.1  # reconstruction error threshold
        self.scaler = None  # StandardScaler for normalization
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._loaded = False
        # Percentile-based IsoForest calibration (computed during training)
        self.iso_baseline: float = 0.0   # median IF score on benign data
        self.iso_scale: float = 1.0      # P99 - median spread

    def load(self) -> bool:
        """Load pre-trained models from disk."""
        model_dir = config.model_dir

        try:
            # Load Isolation Forest
            iso_path = os.path.join(model_dir, "isolation_forest.joblib")
            if os.path.exists(iso_path):
                self.isolation_forest = joblib.load(iso_path)
                logger.info("Isolation Forest loaded")

            # Load scaler
            scaler_path = os.path.join(model_dir, "scaler.joblib")
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)

            # Load Autoencoder
            ae_path = os.path.join(model_dir, "autoencoder.pth")
            if os.path.exists(ae_path):
                self.autoencoder = Autoencoder(input_dim=config.total_features).to(self.device)
                self.autoencoder.load_state_dict(torch.load(ae_path, map_location=self.device))
                self.autoencoder.eval()
                logger.info("Autoencoder loaded")

            # Load threshold
            thresh_path = os.path.join(model_dir, "ae_threshold.joblib")
            if os.path.exists(thresh_path):
                self.ae_threshold = joblib.load(thresh_path)

            # Load IsoForest calibration (percentile-based)
            cal_path = os.path.join(model_dir, "iso_calibration.joblib")
            if os.path.exists(cal_path):
                cal = joblib.load(cal_path)
                self.iso_baseline = cal["baseline"]
                self.iso_scale = cal["scale"]
                logger.info(f"IF calibration loaded: baseline={self.iso_baseline:.4f}, scale={self.iso_scale:.4f}")

            self._loaded = bool(self.isolation_forest or self.autoencoder)
            return self._loaded

        except Exception as e:
            logger.error(f"Failed to load anomaly detector: {e}")
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def predict(self, features: np.ndarray) -> Tuple[float, bool]:
        """
        Predict anomaly score for a feature vector.

        Returns:
            (anomaly_score, is_anomaly) where score is 0.0-1.0
        """
        if not self._loaded:
            return 0.0, False

        scores = []

        # Normalize features
        if self.scaler is not None:
            features_scaled = self.scaler.transform(features.reshape(1, -1))
        else:
            features_scaled = features.reshape(1, -1)

        # Clamp to prevent extreme OOD inputs from saturating models
        features_scaled = np.clip(features_scaled, -10, 10)

        # Isolation Forest score (percentile-calibrated)
        if self.isolation_forest is not None:
            iso_score = -self.isolation_forest.score_samples(features_scaled)[0]
            # Map so that: median benign → 0, P99 benign → 0.5,
            # true anomalies (above P99) → 0.5-1.0
            if self.iso_scale > 1e-10:
                iso_normalized = (iso_score - self.iso_baseline) / (self.iso_scale * 2)
            else:
                iso_normalized = 0.0
            iso_normalized = max(0.0, min(1.0, iso_normalized))
            scores.append(iso_normalized)

        # Autoencoder reconstruction error
        if self.autoencoder is not None:
            tensor = torch.FloatTensor(features_scaled).to(self.device)
            error = self.autoencoder.reconstruction_error(tensor).item()
            # Normalize against threshold
            ae_normalized = min(error / (self.ae_threshold * 2), 1.0)
            scores.append(ae_normalized)

        if not scores:
            return 0.0, False

        # Weighted average
        anomaly_score = np.mean(scores)
        is_anomaly = anomaly_score > config.anomaly_threshold_medium

        return float(anomaly_score), is_anomaly

    def save(self, model_dir: str = ""):
        """Save trained models to disk."""
        save_dir = model_dir or config.model_dir
        os.makedirs(save_dir, exist_ok=True)

        if self.isolation_forest:
            joblib.dump(self.isolation_forest, os.path.join(save_dir, "isolation_forest.joblib"))
        if self.scaler:
            joblib.dump(self.scaler, os.path.join(save_dir, "scaler.joblib"))
        if self.autoencoder:
            torch.save(self.autoencoder.state_dict(), os.path.join(save_dir, "autoencoder.pth"))
        joblib.dump(self.ae_threshold, os.path.join(save_dir, "ae_threshold.joblib"))
        # Save IsoForest calibration
        joblib.dump({"baseline": self.iso_baseline, "scale": self.iso_scale},
                    os.path.join(save_dir, "iso_calibration.joblib"))

        logger.info(f"Anomaly detector models saved to {save_dir}")
