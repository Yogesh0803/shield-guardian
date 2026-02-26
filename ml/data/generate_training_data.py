"""
Generate synthetic training data using the actual FeatureExtractor.

By generating raw Flow objects (with PacketInfo) and extracting features
through the same FeatureExtractor used at inference time, we guarantee
that training and inference see identical feature distributions.

The previous generator produced hand-crafted feature vectors with
CICFlowMeter unit conventions (millisecond times, per-packet header
lengths) that did NOT match the FeatureExtractor output (second times,
summed header lengths), causing all models to saturate at max anomaly
score on live traffic.

Usage:
    python -m ml.data.generate_training_data
"""

import os
import sys
import time as _time

import numpy as np
import pandas as pd

# Allow standalone execution from the project root
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ml.capture.packet_capture import Flow, PacketInfo
from ml.capture.feature_extractor import FeatureExtractor

np.random.seed(42)

_extractor = FeatureExtractor()
FEATURE_COLUMNS = FeatureExtractor.FEATURE_NAMES


# ======================== Helpers ========================

def _make_pkts(n, src_ip, dst_ip, src_port, dst_port, protocol,
               size_range, flags, start_time, iat_mean, iat_jitter=0.3):
    """Create *n* synthetic PacketInfo objects."""
    pkts = []
    t = start_time
    hdr = 40 if protocol == "TCP" else 20
    for i in range(n):
        sz = int(np.random.randint(size_range[0], size_range[1] + 1))
        f = flags(i, n) if callable(flags) else flags
        pkts.append(PacketInfo(
            timestamp=t,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=protocol, length=sz, flags=f,
            payload_size=max(0, sz - hdr),
            ttl=64, header_length=hdr,
        ))
        t += max(iat_mean * (1 + np.random.uniform(-iat_jitter, iat_jitter)), 1e-8)
    return pkts


def _build_flow(fwd, bwd, src_ip, dst_ip, src_port, dst_port, proto="TCP"):
    """Merge fwd + bwd packets into a Flow."""
    flow = Flow(
        flow_id=f"syn_{np.random.randint(0, 10 ** 7)}",
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=proto,
    )
    for p in sorted(fwd + bwd, key=lambda x: x.timestamp):
        flow.add_packet(p)
    return flow


def _flow_features(flow):
    return _extractor.extract(flow)


# ======================== Traffic Generators ========================

def generate_benign(n):
    """Normal browsing / API / DNS traffic."""
    rows = []
    for i in range(n):
        # ~15 % DNS/NTP (UDP), rest TCP browsing
        if np.random.random() < 0.15:
            fwd_n = np.random.randint(1, 4)
            bwd_n = np.random.randint(1, 3)
            dur = np.random.exponential(0.05) + 0.005
            iat = dur / max(fwd_n + bwd_n - 1, 1)
            sp = np.random.randint(1024, 65536)
            dp = int(np.random.choice([53, 123, 5353]))
            src, dst = "10.0.0.1", "192.168.1.1"
            fwd = _make_pkts(fwd_n, src, dst, sp, dp, "UDP",
                             (60, 200), "", 0.0, iat)
            bwd = _make_pkts(bwd_n, dst, src, dp, sp, "UDP",
                             (60, 512), "", iat * 0.5, iat)
            flow = _build_flow(fwd, bwd, src, dst, sp, dp, "UDP")
        else:
            fwd_n = np.random.randint(3, 51)
            bwd_n = np.random.randint(2, min(fwd_n + 10, 41))
            dur = np.random.exponential(5.0) + 0.5
            iat = dur / max(fwd_n + bwd_n - 1, 1)
            sp = np.random.randint(1024, 65536)
            dp = int(np.random.choice([80, 443, 8080, 8443, 3000]))
            src, dst = "10.0.0.1", "192.168.1.1"

            def _ff(idx, tot):
                if idx == 0:
                    return "S"
                if idx == tot - 1:
                    return "FA"
                return "PA" if np.random.random() < 0.3 else "A"

            def _bf(idx, tot):
                return "SA" if idx == 0 else "A"

            fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                             (60, 1500), _ff, 0.0, iat)
            bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                             (60, 1500), _bf, iat * 0.5, iat)
            flow = _build_flow(fwd, bwd, src, dst, sp, dp)

        rows.append(_flow_features(flow))
        if (i + 1) % 5000 == 0:
            print(f"    BENIGN: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "BENIGN"
    return df


def generate_dos(n):
    """DoS SYN flood — high packet rate, small packets, unidirectional."""
    rows = []
    for i in range(n):
        fwd_n = np.random.randint(50, 501)
        bwd_n = np.random.randint(0, 6)
        dur = np.random.exponential(0.5) + 0.01
        iat = dur / max(fwd_n + bwd_n - 1, 1)
        sp = np.random.randint(1024, 65536)
        dp = int(np.random.choice([80, 443, 22, 3389]))
        src, dst = "10.0.0.1", "192.168.1.1"

        fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                         (40, 100), "S", 0.0, iat)
        bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                         (40, 80), "RA", iat * 0.5, iat * 3)
        flow = _build_flow(fwd, bwd, src, dst, sp, dp)
        rows.append(_flow_features(flow))

        if (i + 1) % 1000 == 0:
            print(f"    DoS: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "DoS"
    return df


def generate_ddos(n):
    """DDoS — even higher volume, shorter duration, more uniform sizes."""
    rows = []
    for i in range(n):
        fwd_n = np.random.randint(200, 1001)
        bwd_n = np.random.randint(0, 4)
        dur = np.random.exponential(0.2) + 0.005
        iat = dur / max(fwd_n + bwd_n - 1, 1)
        sp = np.random.randint(1024, 65536)
        dp = int(np.random.choice([80, 443, 53]))
        proto = np.random.choice(["TCP", "UDP"], p=[0.7, 0.3])
        src, dst = "10.0.0.1", "192.168.1.1"

        if proto == "TCP":
            fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                             (40, 65), "S", 0.0, iat, iat_jitter=0.1)
            bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                             (40, 60), "RA", iat * 0.3, iat * 5)
        else:
            fwd = _make_pkts(fwd_n, src, dst, sp, dp, "UDP",
                             (40, 150), "", 0.0, iat, iat_jitter=0.1)
            bwd = _make_pkts(bwd_n, dst, src, dp, sp, "UDP",
                             (40, 60), "", iat * 0.3, iat * 5)

        flow = _build_flow(fwd, bwd, src, dst, sp, dp, proto)
        rows.append(_flow_features(flow))

        if (i + 1) % 500 == 0:
            print(f"    DDoS: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "DDoS"
    return df


def generate_portscan(n):
    """Port scan — very short probes, SYN-only."""
    rows = []
    for i in range(n):
        fwd_n = np.random.randint(1, 4)
        bwd_n = np.random.randint(0, 2)
        dur = np.random.exponential(0.01) + 0.001
        iat = dur / max(fwd_n + bwd_n - 1, 1)
        sp = np.random.randint(1024, 65536)
        dp = np.random.randint(1, 1025)
        src, dst = "10.0.0.1", "192.168.1.1"

        fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                         (40, 60), "S", 0.0, iat)
        bf = "RA" if np.random.random() < 0.6 else "SA"
        bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                         (40, 60), bf, iat * 0.4, iat)
        flow = _build_flow(fwd, bwd, src, dst, sp, dp)
        rows.append(_flow_features(flow))

        if (i + 1) % 1000 == 0:
            print(f"    PortScan: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "PortScan"
    return df


def generate_bruteforce(n):
    """SSH / RDP brute-force — repeated auth attempts."""
    rows = []
    for i in range(n):
        fwd_n = np.random.randint(3, 21)
        bwd_n = np.random.randint(2, 16)
        dur = np.random.exponential(3.0) + 0.5
        iat = dur / max(fwd_n + bwd_n - 1, 1)
        sp = np.random.randint(40000, 65536)
        dp = int(np.random.choice([22, 23, 3389, 5900]))
        src, dst = "10.0.0.1", "192.168.1.1"

        def _ff(idx, tot):
            if idx == 0:
                return "S"
            return "PA"

        def _bf(idx, tot):
            if idx == 0:
                return "SA"
            return "RA" if np.random.random() < 0.3 else "A"

        fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                         (60, 200), _ff, 0.0, iat)
        bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                         (40, 150), _bf, iat * 0.5, iat)
        flow = _build_flow(fwd, bwd, src, dst, sp, dp)
        rows.append(_flow_features(flow))

        if (i + 1) % 500 == 0:
            print(f"    BruteForce: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "BruteForce"
    return df


def generate_webattack(n):
    """SQL injection / XSS — large forward payloads, many headers."""
    rows = []
    for i in range(n):
        fwd_n = np.random.randint(5, 41)
        bwd_n = np.random.randint(3, 31)
        dur = np.random.exponential(5.0) + 1.0
        iat = dur / max(fwd_n + bwd_n - 1, 1)
        sp = np.random.randint(1024, 65536)
        dp = int(np.random.choice([80, 443, 8080, 8443]))
        src, dst = "10.0.0.1", "192.168.1.1"

        def _ff(idx, tot):
            if idx == 0:
                return "S"
            return "PA"

        def _bf(idx, tot):
            if idx == 0:
                return "SA"
            return "PA" if np.random.random() < 0.5 else "A"

        fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                         (200, 1500), _ff, 0.0, iat)
        bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                         (100, 2000), _bf, iat * 0.5, iat)
        flow = _build_flow(fwd, bwd, src, dst, sp, dp)
        rows.append(_flow_features(flow))

        if (i + 1) % 500 == 0:
            print(f"    WebAttack: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "WebAttack"
    return df


def generate_botnet(n):
    """C&C beacon — few periodic packets, long-lived connections."""
    rows = []
    for i in range(n):
        fwd_n = np.random.randint(1, 9)
        bwd_n = np.random.randint(1, 6)
        dur = np.random.exponential(30.0) + 5.0
        iat = dur / max(fwd_n + bwd_n - 1, 1)
        sp = np.random.randint(1024, 65536)
        dp = int(np.random.choice([443, 8443, 4444, 5555, 6667]))
        src, dst = "10.0.0.1", "192.168.1.1"

        # Periodic beacons = very low jitter
        fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                         (50, 200), "PA", 0.0, iat, iat_jitter=0.1)
        bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                         (50, 300), "A", iat * 0.5, iat, iat_jitter=0.1)
        flow = _build_flow(fwd, bwd, src, dst, sp, dp)
        rows.append(_flow_features(flow))

        if (i + 1) % 500 == 0:
            print(f"    Botnet: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "Botnet"
    return df


def generate_infiltration(n):
    """Data exfiltration — bulk outbound transfer near MTU."""
    rows = []
    for i in range(n):
        fwd_n = np.random.randint(10, 101)
        bwd_n = np.random.randint(2, 11)
        dur = np.random.exponential(5.0) + 1.0
        iat = dur / max(fwd_n + bwd_n - 1, 1)
        sp = np.random.randint(1024, 65536)
        dp = int(np.random.choice([443, 80, 21, 22]))
        src, dst = "10.0.0.1", "192.168.1.1"

        fwd = _make_pkts(fwd_n, src, dst, sp, dp, "TCP",
                         (500, 1460), "PA", 0.0, iat)
        bwd = _make_pkts(bwd_n, dst, src, dp, sp, "TCP",
                         (40, 80), "A", iat * 0.5, iat * 3)
        flow = _build_flow(fwd, bwd, src, dst, sp, dp)
        rows.append(_flow_features(flow))

        if (i + 1) % 200 == 0:
            print(f"    Infiltration: {i + 1}/{n}")

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["Label"] = "Infiltration"
    return df


# ======================== Main ========================

def main():
    output_dir = os.path.join(os.path.dirname(__file__), "cicids2017")
    os.makedirs(output_dir, exist_ok=True)

    print("Generating synthetic training data via FeatureExtractor...")
    print("(This ensures training features match live inference exactly)\n")

    samples = {
        "BENIGN": 50000,
        "DoS": 8000,
        "DDoS": 5000,
        "PortScan": 5000,
        "BruteForce": 3000,
        "WebAttack": 2000,
        "Botnet": 1500,
        "Infiltration": 1000,
    }

    generators = {
        "BENIGN": generate_benign,
        "DoS": generate_dos,
        "DDoS": generate_ddos,
        "PortScan": generate_portscan,
        "BruteForce": generate_bruteforce,
        "WebAttack": generate_webattack,
        "Botnet": generate_botnet,
        "Infiltration": generate_infiltration,
    }

    all_data = []
    for label, count in samples.items():
        print(f"  Generating {count:>6} {label} samples...")
        t0 = _time.time()
        df = generators[label](count)
        elapsed = _time.time() - t0
        print(f"    Done in {elapsed:.1f}s")
        all_data.append(df)

    combined = pd.concat(all_data, ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    # Ensure no negative values
    for col in FEATURE_COLUMNS:
        combined[col] = combined[col].clip(lower=0)

    output_path = os.path.join(output_dir, "training_data.csv")
    combined.to_csv(output_path, index=False)

    print(f"\nGenerated {len(combined)} total samples")
    print(f"Saved to: {output_path}")
    print(f"\nClass distribution:")
    print(combined["Label"].value_counts().to_string())

    print(f"\nFeature summary (first 5):")
    for col in FEATURE_COLUMNS[:5]:
        print(f"  {col:30s}: mean={combined[col].mean():12.4f}  "
              f"std={combined[col].std():12.4f}")


if __name__ == "__main__":
    main()
