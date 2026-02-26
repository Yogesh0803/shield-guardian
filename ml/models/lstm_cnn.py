"""
LSTM+CNN hybrid model from BharatVigil project.
Processes packet data as image representations for anomaly detection.
"""

import os
import logging
import numpy as np
from typing import Optional, Tuple

import torch
import torch.nn as nn

from ..config import config

logger = logging.getLogger(__name__)


class SqueezeExcitation(nn.Module):
    """Squeeze-and-Excitation attention block."""

    def __init__(self, channels: int, reduction: int = 4):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(channels, channels // reduction),
            nn.ReLU(),
            nn.Linear(channels // reduction, channels),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        b, c = x.shape[:2]
        # Global average pooling
        y = x.view(b, c, -1).mean(dim=2)
        y = self.fc(y).view(b, c, 1, 1)
        return x * y


class LSTMCNNModel(nn.Module):
    """
    Hybrid LSTM+CNN model for packet-level anomaly detection.
    Based on BharatVigil's architecture.

    Input: Feature vector (reshaped to image-like format)
    Output: Binary classification (0=normal, 1=anomalous)
    """

    def __init__(self, input_dim: int = 80, img_size: int = 8):
        super().__init__()
        self.input_dim = input_dim
        self.img_size = img_size  # reshape features to img_size x img_size-ish

        # LSTM branch
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=64,
            num_layers=2,
            batch_first=True,
            dropout=0.2,
            bidirectional=True,
        )
        self.lstm_fc = nn.Linear(128, 64)  # 128 because bidirectional

        # CNN branch (features reshaped as 1-channel image)
        rows = 8
        cols = (input_dim + rows - 1) // rows  # ceil division
        self.padded_dim = rows * cols

        self.cnn = nn.Sequential(
            nn.Conv2d(1, 32, kernel_size=3, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(),
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(),
            nn.MaxPool2d(2),
            SqueezeExcitation(64),
            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(),
            nn.AdaptiveAvgPool2d(1),
        )
        self.cnn_fc = nn.Linear(128, 64)

        # Fusion
        self.classifier = nn.Sequential(
            nn.Linear(128, 64),  # 64 from LSTM + 64 from CNN
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        batch_size = x.shape[0]

        # LSTM branch: treat features as a sequence
        lstm_in = x.unsqueeze(1)  # (batch, 1, features)
        lstm_out, _ = self.lstm(lstm_in)
        lstm_feat = self.lstm_fc(lstm_out[:, -1, :])  # last hidden state

        # CNN branch: reshape features to 2D image
        padded = torch.zeros(batch_size, self.padded_dim, device=x.device)
        padded[:, :self.input_dim] = x
        rows = 8
        cols = self.padded_dim // rows
        cnn_in = padded.view(batch_size, 1, rows, cols)  # (batch, 1, H, W)
        cnn_out = self.cnn(cnn_in).view(batch_size, -1)
        cnn_feat = self.cnn_fc(cnn_out)

        # Fuse both branches
        combined = torch.cat([lstm_feat, cnn_feat], dim=1)
        output = self.classifier(combined)
        return output.squeeze(1)


class LSTMCNNDetector:
    """Wrapper for LSTM+CNN model inference."""

    def __init__(self):
        self.model: Optional[LSTMCNNModel] = None
        self.scaler = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._loaded = False

    def load(self) -> bool:
        """Load pre-trained model and its scaler.

        Both artifacts are required for accurate predictions.  If the
        scaler is missing the model is still marked as loaded but a
        prominent warning is emitted because unscaled input will
        silently degrade accuracy.
        """
        import joblib
        model_path = os.path.join(config.model_dir, "lstm_cnn.pth")
        scaler_path = os.path.join(config.model_dir, "lstm_cnn_scaler.joblib")
        try:
            if not os.path.exists(model_path):
                logger.info("LSTM+CNN model file not found — skipping")
                return False

            self.model = LSTMCNNModel(input_dim=config.total_features).to(self.device)
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            self.model.eval()
            logger.info("LSTM+CNN model loaded")

            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info("LSTM+CNN scaler loaded")
            else:
                logger.warning(
                    "LSTM+CNN scaler not found — the model will receive "
                    "unscaled features and predictions WILL be inaccurate. "
                    "Re-train with 'python -m ml.pipeline.training --model lstm_cnn' "
                    "to generate the scaler."
                )

            self._loaded = True
            return True
        except Exception as e:
            logger.error(f"Failed to load LSTM+CNN model: {e}")
        return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def predict(self, features: np.ndarray) -> Tuple[float, bool]:
        """
        Predict anomaly probability.

        Returns:
            (anomaly_probability, is_anomalous)
        """
        if not self._loaded:
            return 0.0, False

        features_2d = features.reshape(1, -1)

        # Apply scaler if available (matches training preprocessing)
        if self.scaler is not None:
            features_2d = self.scaler.transform(features_2d)

        # Clamp to prevent extreme OOD inputs from saturating the model
        features_2d = np.clip(features_2d, -10, 10)

        tensor = torch.FloatTensor(features_2d).to(self.device)
        with torch.no_grad():
            prob = self.model(tensor).item()

        return prob, prob > 0.5

    def save(self, model_dir: str = ""):
        """Save model and scaler to disk."""
        import joblib
        save_dir = model_dir or config.model_dir
        os.makedirs(save_dir, exist_ok=True)
        if self.model:
            torch.save(self.model.state_dict(), os.path.join(save_dir, "lstm_cnn.pth"))
        if self.scaler is not None:
            joblib.dump(self.scaler, os.path.join(save_dir, "lstm_cnn_scaler.joblib"))
        logger.info(f"LSTM+CNN model saved to {save_dir}")
