"""
Comprehensive ML model evaluation for the Guardian Shield firewall.

Evaluates all models against firewall-relevant metrics:
  - Detection Rate (True Positive Rate / Recall for malicious)
  - False Positive Rate (benign flagged as malicious)
  - False Negative Rate (malicious passing as benign)
  - Precision, Recall, F1-score (per-class and weighted)
  - Confusion matrix
  - Inference latency (real-time suitability)

Usage:
    python -m ml.pipeline.evaluate
    python -m ml.pipeline.evaluate --data ml/data/cicids2017
"""

import os
import sys
import time
import logging
import argparse
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
    accuracy_score,
)
from sklearn.preprocessing import StandardScaler, LabelEncoder, label_binarize
from sklearn.model_selection import train_test_split

import torch
import joblib

from ..config import config
from ..models.anomaly_detector import AnomalyDetector, Autoencoder
from ..models.attack_classifier import AttackClassifier
from ..models.lstm_cnn import LSTMCNNDetector, LSTMCNNModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# Data loading (shared with training.py)
# ─────────────────────────────────────────────────────────────────────

def load_data(data_path: str) -> pd.DataFrame:
    """Load CSV dataset from the given directory."""
    dfs = []
    for f in os.listdir(data_path):
        if f.endswith(".csv"):
            df = pd.read_csv(os.path.join(data_path, f), low_memory=False)
            dfs.append(df)
    if not dfs:
        raise FileNotFoundError(f"No CSV files found in {data_path}")
    data = pd.concat(dfs, ignore_index=True)
    data.columns = data.columns.str.strip()

    non_feature_cols = {
        "Flow ID", "Source IP", "Destination IP", "Timestamp",
        "Source Port", "Destination Port", "Protocol",
    }
    cols_to_drop = [c for c in data.columns if c in non_feature_cols]
    if cols_to_drop:
        data.drop(columns=cols_to_drop, inplace=True)

    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    data.dropna(inplace=True)
    return data


def prepare_features(data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (X_padded_80, y_labels_str, y_binary) from the dataset."""
    label_col = "Label" if "Label" in data.columns else data.columns[-1]
    feature_cols = [c for c in data.columns if c != label_col]

    X = data[feature_cols].values.astype(np.float32)[:, :config.feature_count]
    if X.shape[1] < config.total_features:
        X = np.hstack([X, np.zeros((X.shape[0], config.total_features - X.shape[1]))])

    y_str = data[label_col].str.strip().values
    y_binary = np.array([0 if str(l).upper() == "BENIGN" else 1 for l in y_str], dtype=np.int32)
    return X, y_str, y_binary


# ─────────────────────────────────────────────────────────────────────
# Firewall-specific metrics
# ─────────────────────────────────────────────────────────────────────

def firewall_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    """Compute firewall-centric binary metrics (normal=0, malicious=1)."""
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))

    detection_rate = tp / max(tp + fn, 1)          # recall for malicious
    false_positive_rate = fp / max(fp + tn, 1)     # benign wrongly blocked
    false_negative_rate = fn / max(fn + tp, 1)     # malicious not caught
    precision = tp / max(tp + fp, 1)
    recall = detection_rate
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "detection_rate": round(detection_rate, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def print_metrics(name: str, metrics: Dict[str, float]):
    """Pretty-print firewall metrics."""
    print(f"\n{'=' * 60}")
    print(f"  {name}")
    print(f"{'=' * 60}")
    print(f"  Detection Rate (TPR):    {metrics['detection_rate']:.4f}")
    print(f"  False Positive Rate:     {metrics['false_positive_rate']:.4f}")
    print(f"  False Negative Rate:     {metrics['false_negative_rate']:.4f}")
    print(f"  Precision:               {metrics['precision']:.4f}")
    print(f"  Recall:                  {metrics['recall']:.4f}")
    print(f"  F1-Score:                {metrics['f1_score']:.4f}")
    print(f"  Accuracy:                {metrics['accuracy']:.4f}")
    print(f"  TP={metrics['true_positives']}  TN={metrics['true_negatives']}  "
          f"FP={metrics['false_positives']}  FN={metrics['false_negatives']}")
    print(f"{'=' * 60}")


# ─────────────────────────────────────────────────────────────────────
# Model evaluators
# ─────────────────────────────────────────────────────────────────────

def evaluate_anomaly_detector(X_test: np.ndarray, y_binary: np.ndarray) -> Dict:
    """Evaluate Isolation Forest + Autoencoder ensemble."""
    detector = AnomalyDetector()
    if not detector.load():
        logger.warning("Anomaly detector not loaded — skipping evaluation")
        return {}

    y_pred = np.zeros(len(X_test), dtype=np.int32)
    scores = np.zeros(len(X_test), dtype=np.float32)

    start = time.time()
    for i in range(len(X_test)):
        score, is_anomaly = detector.predict(X_test[i])
        scores[i] = score
        y_pred[i] = int(is_anomaly)
    elapsed = time.time() - start
    latency_ms = (elapsed / len(X_test)) * 1000

    metrics = firewall_binary_metrics(y_binary, y_pred)
    metrics["avg_inference_latency_ms"] = round(latency_ms, 3)
    print_metrics("Anomaly Detector (Isolation Forest + Autoencoder)", metrics)
    print(f"  Avg inference latency:   {latency_ms:.3f} ms/sample")
    return metrics


def evaluate_lstm_cnn(X_test: np.ndarray, y_binary: np.ndarray) -> Dict:
    """Evaluate LSTM+CNN binary detector."""
    detector = LSTMCNNDetector()
    if not detector.load():
        logger.warning("LSTM+CNN not loaded — skipping evaluation")
        return {}

    y_pred = np.zeros(len(X_test), dtype=np.int32)
    scores = np.zeros(len(X_test), dtype=np.float32)

    start = time.time()
    for i in range(len(X_test)):
        prob, is_anomaly = detector.predict(X_test[i])
        scores[i] = prob
        y_pred[i] = int(is_anomaly)
    elapsed = time.time() - start
    latency_ms = (elapsed / len(X_test)) * 1000

    metrics = firewall_binary_metrics(y_binary, y_pred)
    metrics["avg_inference_latency_ms"] = round(latency_ms, 3)
    print_metrics("LSTM+CNN Binary Detector", metrics)
    print(f"  Avg inference latency:   {latency_ms:.3f} ms/sample")
    return metrics


def evaluate_attack_classifier(X_test: np.ndarray, y_str: np.ndarray) -> Dict:
    """Evaluate XGBoost multi-class attack classifier."""
    classifier = AttackClassifier()
    if not classifier.load():
        logger.warning("Attack classifier not loaded — skipping evaluation")
        return {}

    y_pred_labels = []
    start = time.time()
    for i in range(len(X_test)):
        label, conf = classifier.predict(X_test[i])
        y_pred_labels.append(label)
    elapsed = time.time() - start
    latency_ms = (elapsed / len(X_test)) * 1000

    y_pred_labels = np.array(y_pred_labels)

    # Multi-class classification report
    report = classification_report(y_str, y_pred_labels, zero_division=0)
    print(f"\n{'=' * 60}")
    print("  XGBoost Attack Classifier — Multi-Class Report")
    print(f"{'=' * 60}")
    print(report)

    # Also compute binary metrics (benign vs any-attack)
    y_true_bin = np.array([str(l).upper() != "BENIGN" for l in y_str], dtype=np.int32)
    y_pred_bin = np.array([str(l).upper() != "BENIGN" for l in y_pred_labels], dtype=np.int32)
    binary_metrics = firewall_binary_metrics(y_true_bin, y_pred_bin)
    print_metrics("XGBoost (binary: benign vs attack)", binary_metrics)
    print(f"  Avg inference latency:   {latency_ms:.3f} ms/sample")

    # Per-class precision/recall/F1
    precision, recall, f1, support = precision_recall_fscore_support(
        y_str, y_pred_labels, average=None, zero_division=0,
        labels=np.unique(y_str),
    )
    per_class = {}
    for lbl, p, r, f, s in zip(np.unique(y_str), precision, recall, f1, support):
        per_class[lbl] = {"precision": round(float(p), 4), "recall": round(float(r), 4),
                          "f1": round(float(f), 4), "support": int(s)}

    return {"binary": binary_metrics, "per_class": per_class,
            "avg_inference_latency_ms": round(latency_ms, 3)}


def evaluate_ensemble(X_test: np.ndarray, y_binary: np.ndarray) -> Dict:
    """
    Evaluate the full ensemble pipeline (mimics InferencePipeline logic):
      weighted combination of anomaly detector + LSTM+CNN scores.
    """
    detector = AnomalyDetector()
    lstm = LSTMCNNDetector()
    detector_loaded = detector.load()
    lstm_loaded = lstm.load()

    if not detector_loaded and not lstm_loaded:
        logger.warning("No models loaded for ensemble — skipping")
        return {}

    y_pred = np.zeros(len(X_test), dtype=np.int32)

    start = time.time()
    for i in range(len(X_test)):
        raw_scores: List[Tuple[float, float]] = []
        total_weight = 0.0

        if detector_loaded:
            s, _ = detector.predict(X_test[i])
            raw_scores.append((s, 0.6))
            total_weight += 0.6
        if lstm_loaded:
            s, _ = lstm.predict(X_test[i])
            raw_scores.append((s, 0.4))
            total_weight += 0.4

        if total_weight > 0:
            score = sum(s * w for s, w in raw_scores) / total_weight
        else:
            score = 0.0
        score = min(max(score, 0.0), 1.0)
        y_pred[i] = int(score > config.anomaly_threshold_medium)

    elapsed = time.time() - start
    latency_ms = (elapsed / len(X_test)) * 1000

    metrics = firewall_binary_metrics(y_binary, y_pred)
    metrics["avg_inference_latency_ms"] = round(latency_ms, 3)
    print_metrics("Ensemble (Anomaly Detector + LSTM+CNN)", metrics)
    print(f"  Avg inference latency:   {latency_ms:.3f} ms/sample")
    return metrics


# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Evaluate Guardian Shield ML models")
    parser.add_argument("--data", default=config.training_data_path,
                        help="Path to CICIDS2017-format CSV directory")
    args = parser.parse_args()

    # Load data
    data = load_data(args.data)
    X, y_str, y_binary = prepare_features(data)

    # Use the same train/test split seed as training.py for fair eval
    _, X_test, _, y_str_test = train_test_split(X, y_str, test_size=0.2, random_state=42)
    _, _, _, y_bin_test = train_test_split(X, y_binary, test_size=0.2, random_state=42)

    # Scale using saved scalers where available
    scaler_path = os.path.join(config.model_dir, "scaler.joblib")
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
        X_test_scaled = scaler.transform(X_test)
    else:
        scaler = StandardScaler().fit(X_test)
        X_test_scaled = scaler.transform(X_test)

    print(f"\nDataset: {args.data}")
    print(f"Test samples: {len(X_test)}")
    print(f"  Benign: {int(np.sum(y_bin_test == 0))}")
    print(f"  Malicious: {int(np.sum(y_bin_test == 1))}")
    label_dist = pd.Series(y_str_test).value_counts()
    print(f"\nLabel distribution:\n{label_dist.to_string()}")

    results = {}

    # Evaluate each model — pass *unscaled* features because each model's
    # predict() applies its own saved scaler internally.
    print("\n" + "=" * 60)
    print("  EVALUATING ALL MODELS")
    print("=" * 60)

    results["anomaly_detector"] = evaluate_anomaly_detector(X_test, y_bin_test)
    results["lstm_cnn"] = evaluate_lstm_cnn(X_test, y_bin_test)
    results["attack_classifier"] = evaluate_attack_classifier(X_test, y_str_test)
    results["ensemble"] = evaluate_ensemble(X_test, y_bin_test)

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY — Firewall Readiness")
    print("=" * 60)

    for name, m in results.items():
        if not m:
            print(f"  {name:30s}  SKIPPED (model not loaded)")
            continue
        bm = m.get("binary", m)  # classifier stores binary inside "binary" key
        lat = m.get("avg_inference_latency_ms", bm.get("avg_inference_latency_ms", "?"))
        print(f"  {name:30s}  F1={bm.get('f1_score','?')}  "
              f"DR={bm.get('detection_rate','?')}  "
              f"FPR={bm.get('false_positive_rate','?')}  "
              f"Latency={lat}ms")

    # Real-time verdict
    all_latencies = [
        m.get("avg_inference_latency_ms",
              m.get("binary", {}).get("avg_inference_latency_ms", None))
        for m in results.values() if m
    ]
    all_latencies = [l for l in all_latencies if l is not None]
    if all_latencies:
        max_lat = max(all_latencies)
        print(f"\n  Max single-model latency: {max_lat:.3f} ms")
        if max_lat < 10:
            print("  ✓ All models suitable for real-time firewall (<10 ms)")
        elif max_lat < 50:
            print("  ~ Models acceptable for near-real-time firewall (<50 ms)")
        else:
            print("  ✗ Some models too slow for real-time use; consider batch mode")

    return results


if __name__ == "__main__":
    main()
