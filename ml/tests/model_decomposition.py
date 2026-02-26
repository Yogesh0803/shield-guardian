"""
Diagnostic decomposition: print each model's individual score
for every synthetic scenario to identify which component is
miscalibrated.
"""

import sys, os, time, logging
import numpy as np

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ml.capture.packet_capture import Flow, PacketInfo
from ml.capture.feature_extractor import FeatureExtractor
from ml.context.context_engine import ContextEngine
from ml.models.anomaly_detector import AnomalyDetector
from ml.models.attack_classifier import AttackClassifier
from ml.models.lstm_cnn import LSTMCNNDetector
from ml.config import config

logging.basicConfig(level=logging.WARNING)

# ---------- Reuse scenario factories from e2e test ----------
from ml.tests.e2e_pipeline_trace import (
    benign_https_browsing, benign_dns_lookup,
    ddos_flood, dos_syn_flood, brute_force_ssh,
    port_scan_sweep, borderline_anomaly,
)


def main():
    # Load models
    ad = AnomalyDetector()
    ad.load()
    lstm = LSTMCNNDetector()
    lstm.load()
    xgb = AttackClassifier()
    xgb.load()
    ctx_engine = ContextEngine()
    extractor = FeatureExtractor()

    scenarios = [
        ("benign_https",  benign_https_browsing,  "benign"),
        ("benign_dns",    benign_dns_lookup,       "benign"),
        ("ddos_flood",    ddos_flood,              "malicious"),
        ("dos_syn",       dos_syn_flood,           "malicious"),
        ("brute_ssh",     brute_force_ssh,         "malicious"),
        ("port_scan",     port_scan_sweep,         "malicious"),
        ("borderline",    borderline_anomaly,      "edge"),
    ]

    header = (
        f"{'Scenario':<16} {'Label':<10} "
        f"{'IsoForest':>10} {'AutoEnc':>10} {'AD_Avg':>10} "
        f"{'LSTM+CNN':>10} {'CtxScore':>10} "
        f"{'Ensemble':>10} {'XGB_Type':<14} {'XGB_Conf':>10}"
    )
    print("=" * len(header))
    print("PER-MODEL SCORE DECOMPOSITION")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for name, factory, label in scenarios:
        flow = factory()
        context = ctx_engine.build_context(flow)
        features = context.to_model_features()  # 80-dim

        # ---- Isolation Forest raw ----
        if ad.scaler is not None:
            feat_scaled = ad.scaler.transform(features.reshape(1, -1))
        else:
            feat_scaled = features.reshape(1, -1)

        iso_raw = None
        iso_norm = None
        ae_raw = None
        ae_norm = None

        if ad.isolation_forest is not None:
            iso_raw_score = -ad.isolation_forest.score_samples(feat_scaled)[0]
            iso_norm = min(max((iso_raw_score + 0.5), 0.0), 1.0)
            iso_raw = iso_raw_score

        if ad.autoencoder is not None:
            import torch
            tensor = torch.FloatTensor(feat_scaled).to(ad.device)
            ae_error = ad.autoencoder.reconstruction_error(tensor).item()
            ae_norm = min(ae_error / (ad.ae_threshold * 2), 1.0)
            ae_raw = ae_error

        ad_score, _ = ad.predict(features)

        # ---- LSTM+CNN ----
        lstm_score, _ = lstm.predict(features)

        # ---- Context score (manual calc matching inference.py) ----
        ctx_score = 0.0
        if context.rate_deviation > 3.0:
            ctx_score += 0.2
        if context.size_deviation > 3.0:
            ctx_score += 0.15
        if context.destination_novelty > 0.8:
            ctx_score += 0.15
        if context.is_geo_anomaly:
            ctx_score += 0.15
        if context.app_trust_score < 0.4:
            ctx_score += 0.1
        if not context.is_business_hours and (context.hour < 6 or context.hour > 22):
            ctx_score += 0.1
        if context.app_name == "unknown":
            ctx_score += 0.15
        ctx_score = min(ctx_score, 1.0)

        # ---- Ensemble (exactly as inference.py) ----
        raw_scores = []
        tw = 0.0
        if ad._loaded:
            raw_scores.append((ad_score, 0.4))
            tw += 0.4
        if lstm.is_loaded:
            raw_scores.append((lstm_score, 0.3))
            tw += 0.3
        raw_scores.append((ctx_score, 0.3))
        tw += 0.3
        ensemble = sum(s * w for s, w in raw_scores) / tw if tw > 0 else ctx_score
        ensemble = min(max(ensemble, 0.0), 1.0)

        # ---- XGBoost (only if anomalous) ----
        xgb_type = "-"
        xgb_conf = 0.0
        if ensemble > config.anomaly_threshold_medium and xgb.is_loaded:
            xgb_type, xgb_conf = xgb.predict(features)

        print(
            f"{name:<16} {label:<10} "
            f"{iso_norm if iso_norm is not None else 'N/A':>10.4f} "
            f"{ae_norm if ae_norm is not None else 'N/A':>10.4f} "
            f"{ad_score:>10.4f} "
            f"{lstm_score:>10.4f} "
            f"{ctx_score:>10.4f} "
            f"{ensemble:>10.4f} "
            f"{xgb_type:<14} {xgb_conf:>10.4f}"
        )

    # ---- Raw score details ----
    print()
    print("KEY OBSERVATIONS:")
    print("  IsoForest: score_samples returns ~0 for normal data")
    print("    After: iso_normalized = clip(-score + 0.5, 0, 1)")
    print("    Normal data gets ~0.5 → already at anomaly_threshold_medium!")
    print()
    print("  If IsoForest≈0.5, AE≈1.0, AD_avg≈0.75")
    print("  Ensemble = 0.75*0.4 + LSTM*0.3 + ctx*0.3")
    print("  Even benign flows reach >0.8 (anomaly_threshold_high)")


if __name__ == "__main__":
    main()
