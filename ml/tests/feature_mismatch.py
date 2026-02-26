"""
Verify feature distribution mismatch between training data (CSV)
and live extraction (FeatureExtractor applied to Flow objects).
"""
import sys, os, logging
import numpy as np

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

logging.basicConfig(level=logging.WARNING)

from ml.capture.feature_extractor import FeatureExtractor
from ml.context.context_engine import ContextEngine
from ml.tests.e2e_pipeline_trace import benign_https_browsing, ddos_flood
from ml.config import config
import joblib

# Load the scaler that was fit on training data
scaler = joblib.load(os.path.join(config.model_dir, "scaler.joblib"))

extractor = FeatureExtractor()
ctx_engine = ContextEngine()

# Extract features from synthetic flows
benign_flow = benign_https_browsing()
ddos_flow = ddos_flood()

benign_raw = extractor.extract(benign_flow)
ddos_raw = extractor.extract(ddos_flow)

# Load a sample of training data for comparison
csv_path = os.path.join(ROOT, "ml", "data", "cicids2017", "training_data.csv")
if os.path.exists(csv_path):
    import pandas as pd
    df = pd.read_csv(csv_path, nrows=500)
    # First 40 columns are features
    train_features = df.iloc[:, :40].values
    train_mean = train_features.mean(axis=0)
    train_std = train_features.std(axis=0)
    train_min = train_features.min(axis=0)
    train_max = train_features.max(axis=0)
else:
    print("Training CSV not found!")
    sys.exit(1)

print("=" * 90)
print("FEATURE DISTRIBUTION: Training Data vs Live Extraction")
print("=" * 90)
print(f"{'Feature':<30} {'Train Mean':>12} {'Train Std':>12} "
      f"{'Benign Live':>12} {'DDoS Live':>12} {'OOD?':>6}")
print("-" * 90)

feature_names = FeatureExtractor.FEATURE_NAMES
ood_count = 0
for i in range(40):
    name = feature_names[i] if i < len(feature_names) else f"feat_{i}"
    t_mean = train_mean[i]
    t_std = train_std[i] if train_std[i] > 0 else 1e-10
    b_val = benign_raw[i]
    d_val = ddos_raw[i]

    # Check if live values are within 5 std devs of training mean
    b_zscore = abs(b_val - t_mean) / t_std
    d_zscore = abs(d_val - t_mean) / t_std
    ood = "YES" if b_zscore > 5 or d_zscore > 5 else ""
    if ood:
        ood_count += 1

    print(f"{name:<30} {t_mean:>12.2f} {t_std:>12.2f} "
          f"{b_val:>12.2f} {d_val:>12.2f} {ood:>6}")

print("-" * 90)
print(f"Out-of-distribution features: {ood_count}/40")

# Show what happens after scaling
benign_padded = np.zeros(80)
benign_padded[:40] = benign_raw
ddos_padded = np.zeros(80)
ddos_padded[:40] = ddos_raw

benign_scaled = scaler.transform(benign_padded.reshape(1, -1))[0]
ddos_scaled = scaler.transform(ddos_padded.reshape(1, -1))[0]

print()
print("POST-SCALING (first 10 features):")
print(f"{'Feature':<30} {'Benign Scaled':>14} {'DDoS Scaled':>14}")
print("-" * 60)
for i in range(10):
    name = feature_names[i] if i < len(feature_names) else f"feat_{i}"
    print(f"{name:<30} {benign_scaled[i]:>14.4f} {ddos_scaled[i]:>14.4f}")
print("...")
print(f"  Benign scaled range: [{benign_scaled[:40].min():.2f}, {benign_scaled[:40].max():.2f}]")
print(f"  DDoS scaled range:   [{ddos_scaled[:40].min():.2f}, {ddos_scaled[:40].max():.2f}]")
