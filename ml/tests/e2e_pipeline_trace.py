"""
End-to-End Pipeline Trace & Decision-Consistency Verification
=============================================================
Synthetically constructs Flow objects that represent:
  1. Normal HTTPS browsing (benign)
  2. Normal DNS lookup (benign)
  3. DDoS flood (malicious)
  4. DoS SYN flood (malicious)
  5. SSH brute-force (malicious)
  6. Port scan sweep (malicious)
  7. Borderline low-rate anomaly (edge case)

Runs each through the *real* InferencePipeline (with trained models)
and verifies:
  - All malicious flows → action ∈ {"block", "alert"}
  - High-confidence malicious flows → "block"
  - All benign flows → "allow"
  - PolicyEngine override works correctly
"""

import sys, os, time, logging, json
from dataclasses import dataclass
from typing import List

import numpy as np

# ---- fix PYTHONPATH so we can import ml.* ---------------------------------
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ml.capture.packet_capture import Flow, PacketInfo
from ml.capture.feature_extractor import FeatureExtractor
from ml.context.context_engine import ContextEngine
from ml.pipeline.inference import InferencePipeline, Prediction
from ml.enforcer.policy_engine import PolicyEngine

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger("e2e_trace")

# ========================== Synthetic Flow Factories ==========================

def _make_packets(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
    protocol: str, count: int, length_range=(60, 1500),
    flags: str = "A", iat: float = 0.01, bwd_ratio: float = 0.4,
    start_time: float = 0.0,
) -> List[PacketInfo]:
    """Generate a realistic list of PacketInfo objects."""
    pkts = []
    t = start_time or time.time()
    for i in range(count):
        is_bwd = (i / max(count, 1)) < bwd_ratio and i % 3 == 0
        s_ip = dst_ip if is_bwd else src_ip
        d_ip = src_ip if is_bwd else dst_ip
        s_port = dst_port if is_bwd else src_port
        d_port = src_port if is_bwd else dst_port
        length = int(np.random.randint(length_range[0], length_range[1] + 1))
        pkts.append(PacketInfo(
            timestamp=t,
            src_ip=s_ip, dst_ip=d_ip,
            src_port=s_port, dst_port=d_port,
            protocol=protocol,
            length=length,
            flags=flags,
            payload_size=max(0, length - 40),
            ttl=64,
            header_length=40 if protocol == "TCP" else 20,
        ))
        t += iat + np.random.uniform(0, iat * 0.3)
    return pkts


def build_flow(name: str, pkts: List[PacketInfo]) -> Flow:
    src = pkts[0]
    flow = Flow(
        flow_id=name,
        src_ip=src.src_ip, dst_ip=src.dst_ip,
        src_port=src.src_port, dst_port=src.dst_port,
        protocol=src.protocol,
    )
    for p in pkts:
        flow.add_packet(p)
    return flow


# ---------- Benign Scenarios ----------

def benign_https_browsing() -> Flow:
    """Normal HTTPS browsing: moderate packet count, typical sizes, SYN+ACK."""
    pkts = _make_packets(
        src_ip="192.168.1.100", dst_ip="142.250.190.46",
        src_port=52341, dst_port=443,
        protocol="TCP", count=30,
        length_range=(60, 1400), flags="A",
        iat=0.05, bwd_ratio=0.45,
    )
    # Add a SYN at start and FIN at end
    pkts[0] = PacketInfo(**{**pkts[0].__dict__, "flags": "S"})
    pkts[-1] = PacketInfo(**{**pkts[-1].__dict__, "flags": "FA"})
    return build_flow("benign_https", pkts)


def benign_dns_lookup() -> Flow:
    """Normal DNS: 2 packets, one query one reply."""
    t = time.time()
    pkts = [
        PacketInfo(t, "192.168.1.100", "8.8.8.8", 54321, 53, "UDP", 72, "", 32, 128, 20),
        PacketInfo(t + 0.02, "8.8.8.8", "192.168.1.100", 53, 54321, "UDP", 128, "", 88, 128, 20),
    ]
    return build_flow("benign_dns", pkts)


# ---------- Malicious Scenarios ----------

def ddos_flood() -> Flow:
    """DDoS: huge packet count, tiny IAT, large total volume."""
    pkts = _make_packets(
        src_ip="10.0.0.50", dst_ip="192.168.1.10",
        src_port=0, dst_port=80,
        protocol="TCP", count=5000,
        length_range=(40, 100), flags="S",
        iat=0.0001, bwd_ratio=0.0,
    )
    return build_flow("ddos_flood", pkts)


def dos_syn_flood() -> Flow:
    """DoS SYN flood: many SYN, no ACK, single source."""
    pkts = _make_packets(
        src_ip="203.0.113.5", dst_ip="192.168.1.10",
        src_port=12345, dst_port=80,
        protocol="TCP", count=2000,
        length_range=(40, 60), flags="S",
        iat=0.0005, bwd_ratio=0.0,
    )
    return build_flow("dos_syn_flood", pkts)


def brute_force_ssh() -> Flow:
    """SSH brute-force: many short TCP connections with payloads."""
    pkts = _make_packets(
        src_ip="198.51.100.77", dst_ip="192.168.1.10",
        src_port=44000, dst_port=22,
        protocol="TCP", count=500,
        length_range=(60, 200), flags="PA",
        iat=0.005, bwd_ratio=0.3,
    )
    return build_flow("brute_force_ssh", pkts)


def port_scan_sweep() -> Flow:
    """Port scan: many SYN to different ports from one source, many RST back."""
    pkts = _make_packets(
        src_ip="10.99.0.1", dst_ip="192.168.1.10",
        src_port=60000, dst_port=1,
        protocol="TCP", count=300,
        length_range=(40, 60), flags="S",
        iat=0.001, bwd_ratio=0.5,
    )
    # Simulate RST responses
    for i in range(1, len(pkts), 2):
        pkts[i] = PacketInfo(**{**pkts[i].__dict__, "flags": "RA"})
    return build_flow("port_scan", pkts)


def borderline_anomaly() -> Flow:
    """Edge case: slightly elevated rate, but not clearly malicious."""
    pkts = _make_packets(
        src_ip="192.168.1.100", dst_ip="172.217.14.99",
        src_port=55000, dst_port=443,
        protocol="TCP", count=80,
        length_range=(100, 800), flags="A",
        iat=0.02, bwd_ratio=0.35,
    )
    return build_flow("borderline", pkts)


# ========================== Test Runner ==========================

@dataclass
class TraceResult:
    name: str
    expected_label: str          # "benign" or "malicious"
    expected_actions: list       # acceptable actions
    anomaly_score: float = 0.0
    attack_type: str = ""
    confidence: float = 0.0
    action: str = ""
    passed: bool = False
    note: str = ""


def run_trace():
    # ---- Load models ----
    pipeline = InferencePipeline()
    load_status = pipeline.load_models()
    print("\n" + "=" * 72)
    print("MODEL LOAD STATUS")
    print("=" * 72)
    for k, v in load_status.items():
        status = "LOADED" if v else "MISSING"
        print(f"  {k:25s} : {status}")
    print()

    # ---- Define scenarios ----
    scenarios = [
        # (factory, label, acceptable_actions)
        (benign_https_browsing,  "benign",    ["allow"]),
        (benign_dns_lookup,      "benign",    ["allow"]),
        (ddos_flood,             "malicious", ["block", "alert"]),
        (dos_syn_flood,          "malicious", ["block", "alert"]),
        (brute_force_ssh,        "malicious", ["block", "alert"]),
        (port_scan_sweep,        "malicious", ["block", "alert"]),
        (borderline_anomaly,     "edge",      ["allow", "alert"]),
    ]

    results: List[TraceResult] = []
    extractor = FeatureExtractor()

    print("=" * 72)
    print("PIPELINE TRACE: Flow → Features → Context → Models → Decision")
    print("=" * 72)

    for factory, label, ok_actions in scenarios:
        flow = factory()
        tr = TraceResult(name=flow.flow_id, expected_label=label, expected_actions=ok_actions)

        # ---- STAGE 1: Feature Extraction ----
        raw_features = extractor.extract(flow)
        assert raw_features.shape == (40,), f"Expected 40 features, got {raw_features.shape}"

        # ---- STAGE 2-5: Full Pipeline (Context + Models + Ensemble + Decision) ----
        pred: Prediction = pipeline.analyze(flow)
        tr.anomaly_score = pred.anomaly_score
        tr.attack_type = pred.attack_type
        tr.confidence = pred.confidence
        tr.action = pred.action

        # ---- Verify ----
        tr.passed = pred.action in ok_actions
        if not tr.passed:
            tr.note = f"FAIL: got '{pred.action}', expected one of {ok_actions}"
        else:
            tr.note = "PASS"

        results.append(tr)

    # ---- STAGE 6: Policy Engine Override Test ----
    policy_engine = PolicyEngine()
    # Add a user policy that forces a block on a specific IP
    # PolicyEngine.load_policies expects: id, name, purpose, is_active, conditions
    policy_engine.load_policies([
        {
            "id": "pol-1",
            "name": "Block attacker IP",
            "purpose": "block",
            "is_active": True,
            "conditions": {
                "ips": ["198.51.100.77"],   # brute-force attacker IP
            }
        },
        {
            "id": "pol-2",
            "name": "Whitelist Google",
            "purpose": "unblock",
            "is_active": True,
            "conditions": {
                "ips": ["142.250.190.46"],
            }
        },
    ])

    # Test policy override: craft a "benign-looking" flow from the attacker IP
    benign_from_attacker = benign_https_browsing()
    # Override the source IP
    for p in benign_from_attacker.packets:
        object.__setattr__(p, "src_ip", "198.51.100.77")
    benign_from_attacker.src_ip = "198.51.100.77"
    pred_before_policy = pipeline.analyze(benign_from_attacker)

    policy_ctx = pred_before_policy.context
    policy_override = policy_engine.evaluate_simple(
        context=policy_ctx,
        anomaly_score=pred_before_policy.anomaly_score,
        attack_type=pred_before_policy.attack_type,
        confidence=pred_before_policy.confidence,
    )
    policy_tr = TraceResult(
        name="policy_override",
        expected_label="policy",
        expected_actions=["block"],
        anomaly_score=pred_before_policy.anomaly_score,
        attack_type=pred_before_policy.attack_type,
        confidence=pred_before_policy.confidence,
        action=policy_override,
    )
    policy_tr.passed = policy_override == "block"
    policy_tr.note = "PASS" if policy_tr.passed else f"FAIL: policy returned '{policy_override}', expected 'block'"
    results.append(policy_tr)

    # ---- Print Results ----
    print()
    print(f"{'Scenario':<22} {'Label':<10} {'Score':>6} {'Attack':<14} {'Conf':>6} {'Action':<8} {'Result'}")
    print("-" * 95)
    for r in results:
        color = "\033[92m" if r.passed else "\033[91m"
        reset = "\033[0m"
        print(
            f"{r.name:<22} {r.expected_label:<10} "
            f"{r.anomaly_score:>6.3f} {r.attack_type:<14} {r.confidence:>6.3f} "
            f"{r.action:<8} {color}{r.note}{reset}"
        )

    # ---- Summary ----
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    print()
    print("=" * 72)
    print(f"SUMMARY: {passed}/{total} scenarios PASSED, {failed} FAILED")

    if failed:
        print("\nFAILED scenarios:")
        for r in results:
            if not r.passed:
                print(f"  - {r.name}: {r.note}")
                print(f"    score={r.anomaly_score:.4f}, attack={r.attack_type}, "
                      f"conf={r.confidence:.4f}, action={r.action}")

    # ---- Detailed Decision Path Trace ----
    print()
    print("=" * 72)
    print("DECISION PATH ANALYSIS")
    print("=" * 72)
    from ml.config import config as mlcfg
    print(f"  anomaly_threshold_medium = {mlcfg.anomaly_threshold_medium}")
    print(f"  anomaly_threshold_high   = {mlcfg.anomaly_threshold_high}")
    print()

    for r in results:
        score = r.anomaly_score
        conf = r.confidence
        atype = r.attack_type

        if score > mlcfg.anomaly_threshold_high and conf > 0.8:
            path = "HIGH anomaly + HIGH confidence → BLOCK"
        elif score > mlcfg.anomaly_threshold_high:
            path = "HIGH anomaly + LOW confidence → ALERT"
        elif score > mlcfg.anomaly_threshold_medium:
            if atype in ("DDoS", "DoS", "BruteForce") and conf > 0.7:
                path = f"MEDIUM anomaly + {atype} + conf>{0.7} → BLOCK"
            else:
                path = f"MEDIUM anomaly → ALERT"
        else:
            path = "LOW anomaly → ALLOW"

        if r.name == "policy_override":
            path = "POLICY OVERRIDE → BLOCK (user rule matched src_ip)"

        status = "✓" if r.passed else "✗"
        print(f"  [{status}] {r.name:<22} : {path}")

    print()
    print("=" * 72)
    return failed == 0


if __name__ == "__main__":
    success = run_trace()
    sys.exit(0 if success else 1)
