"""
Generate synthetic pre-trained model artifacts so the ML pipeline can
start in "loaded" mode without requiring a real CICIDS2017 training run.

The models are initialised with random weights / default parameters and
then saved in the exact format that each loader expects.  This is
sufficient for the dashboard to show models as loaded and for the
inference pipeline to produce (uncalibrated) predictions.

Usage:
    python -m ml.models.generate_pretrained
"""

import os
import sys
import logging
import numpy as np

import joblib
import torch
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Ensure the project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ml.config import config
from ml.models.anomaly_detector import Autoencoder
from ml.models.lstm_cnn import LSTMCNNModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def generate_all(save_dir: str | None = None):
    save_dir = save_dir or config.model_dir
    os.makedirs(save_dir, exist_ok=True)
    logger.info(f"Generating pretrained model stubs in: {save_dir}")

    n_features = config.total_features  # 80

    # ── 1. Isolation Forest ──────────────────────────────────────────
    logger.info("Generating Isolation Forest …")
    X_dummy = np.random.randn(500, n_features).astype(np.float32)
    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso.fit(X_dummy)
    joblib.dump(iso, os.path.join(save_dir, "isolation_forest.joblib"))

    # ── 2. Scaler (shared by anomaly detector) ───────────────────────
    logger.info("Generating anomaly scaler …")
    scaler_ad = StandardScaler()
    scaler_ad.fit(X_dummy)
    joblib.dump(scaler_ad, os.path.join(save_dir, "scaler.joblib"))

    # ── 3. Autoencoder ───────────────────────────────────────────────
    logger.info("Generating Autoencoder …")
    ae = Autoencoder(input_dim=n_features)
    # One quick forward pass so batchnorm stats are initialised
    ae.eval()
    with torch.no_grad():
        ae(torch.randn(2, n_features))
    torch.save(ae.state_dict(), os.path.join(save_dir, "autoencoder.pth"))

    # Threshold (95th percentile placeholder)
    joblib.dump(0.1, os.path.join(save_dir, "ae_threshold.joblib"))

    # ── 4. XGBoost Classifier ────────────────────────────────────────
    logger.info("Generating XGBoost classifier …")
    try:
        from xgboost import XGBClassifier
    except ImportError:
        # Fallback to sklearn GradientBoosting if xgboost is unavailable
        from sklearn.ensemble import GradientBoostingClassifier as XGBClassifier
        logger.warning("xgboost not installed – using sklearn GradientBoosting as fallback")

    labels = config.attack_labels  # ["Benign", "DoS", "DDoS", ...]
    n_classes = len(labels)
    y_dummy = np.random.randint(0, n_classes, size=500)
    le = LabelEncoder()
    le.fit(labels)
    y_dummy_labels = le.inverse_transform(y_dummy % n_classes)
    y_dummy_encoded = le.transform(y_dummy_labels)

    clf_scaler = StandardScaler()
    X_clf = clf_scaler.fit_transform(X_dummy)

    try:
        xgb = XGBClassifier(
            n_estimators=50,
            max_depth=4,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
        )
        xgb.fit(X_clf, y_dummy_encoded)
    except TypeError:
        # sklearn fallback doesn't accept xgboost-specific args
        xgb = XGBClassifier(n_estimators=50, max_depth=4, random_state=42)
        xgb.fit(X_clf, y_dummy_encoded)

    joblib.dump(xgb, os.path.join(save_dir, "xgboost_classifier.joblib"))
    joblib.dump(clf_scaler, os.path.join(save_dir, "classifier_scaler.joblib"))
    joblib.dump(le, os.path.join(save_dir, "label_encoder.joblib"))

    # ── 5. LSTM+CNN ──────────────────────────────────────────────────
    logger.info("Generating LSTM+CNN …")
    lstm_cnn = LSTMCNNModel(input_dim=n_features)
    lstm_cnn.eval()
    with torch.no_grad():
        lstm_cnn(torch.randn(2, n_features))
    torch.save(lstm_cnn.state_dict(), os.path.join(save_dir, "lstm_cnn.pth"))

    lstm_scaler = StandardScaler()
    lstm_scaler.fit(X_dummy)
    joblib.dump(lstm_scaler, os.path.join(save_dir, "lstm_cnn_scaler.joblib"))

    logger.info("✓ All model artifacts generated successfully.")
    logger.info(f"  Directory: {save_dir}")
    for f in sorted(os.listdir(save_dir)):
        size_kb = os.path.getsize(os.path.join(save_dir, f)) / 1024
        logger.info(f"  {f:40s} {size_kb:>8.1f} KB")


if __name__ == "__main__":
    generate_all()
