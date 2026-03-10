"""
Guardian Shield ML Engine — Main Entry Point.

Captures live network traffic, analyzes it through the ML pipeline,
enforces firewall rules, and reports results to the backend API.

Usage:
    python -m ml.main
    python -m ml.main --interface eth0
    python -m ml.main --no-enforce  (analysis only, no blocking)
    python -m ml.main --simulate    (synthetic traffic, no Npcap needed)
"""

import os
import sys
import time
import json
import logging
import argparse
import threading
import traceback
from typing import Optional

import requests

from .capture.packet_capture import PacketCapture, Flow
from .capture.simulator import TrafficSimulator
from .pipeline.inference import InferencePipeline, Prediction
from .enforcer.policy_engine import PolicyEngine
from .enforcer.firewall_rules import FirewallEnforcer
from .config import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("guardian-shield")


class GuardianShieldEngine:
    """Main ML engine that ties capture, inference, and enforcement together."""

    def __init__(self, interface: str = "", enforce: bool = True, simulate: bool = False):
        self.simulate = simulate
        if simulate:
            self.capture = TrafficSimulator(
                flows_per_minute=30.0,
                attack_ratio=0.15,
            )
        else:
            self.capture = PacketCapture(
                interface=interface or config.interface,
                flow_timeout=config.flow_timeout,
                buffer_size=config.buffer_size,
            )
        self.pipeline = InferencePipeline()
        self.policy_engine = PolicyEngine()
        self.enforce = enforce
        # Start the WinDivert packet filter when enforcement is enabled.
        # The filter excludes loopback (127.0.0.1) so it won't interfere
        # with the engine's own HTTP reports to the backend.
        if self.enforce:
            self.enforcer = FirewallEnforcer(default_block_duration=config.block_duration)
        else:
            self.enforcer = None

        self._running = False
        self._predictions: list = []
        self._lock = threading.Lock()

    def start(self):
        """Start the ML engine."""
        logger.info("=" * 60)
        logger.info("  Guardian Shield — Context-Aware ML Firewall Engine")
        logger.info("=" * 60)

        # Pre-flight: log environment
        logger.info(f"Backend URL: {config.backend_url}")
        logger.info(f"ML_API_KEY set: {'yes' if os.getenv('ML_API_KEY') else 'using default'}")
        logger.info(f"Mode: {'SIMULATION' if self.simulate else 'LIVE CAPTURE'}")
        if not self.simulate:
            logger.info(f"Interface: {self.capture.interface or '(auto-detect)'}")
        logger.info(f"Flow timeout: {config.flow_timeout}s")

        # Load ML models
        logger.info("Loading ML models...")
        load_results = self.pipeline.load_models()
        loaded_count = sum(1 for v in load_results.values() if v)
        logger.info(f"Models loaded: {loaded_count}/{len(load_results)}")

        if loaded_count == 0:
            logger.warning(
                "No pre-trained models found. The engine will run with context-based "
                "anomaly detection only. Train models with: python -m ml.pipeline.training"
            )

        # Load policies from backend
        self._load_policies()

        # Register flow callback
        self.capture.on_flow_complete(self._on_flow_complete)

        # Start capture (performs pre-flight checks internally)
        self._running = True
        self.capture.start()

        if not self.capture._running:
            # If live capture failed, auto-fallback to simulation
            if not self.simulate:
                logger.warning(
                    "Live capture failed — auto-falling back to SIMULATION mode. "
                    "Install Npcap and run as Administrator for live capture."
                )
                self.capture = TrafficSimulator(
                    flows_per_minute=30.0,
                    attack_ratio=0.15,
                )
                self.capture.on_flow_complete(self._on_flow_complete)
                self.capture.start()
                self.simulate = True
                self.enforce = False
            else:
                logger.critical(
                    "Simulator failed to start — cannot produce predictions."
                )
                self._running = False
                return

        # Start background threads
        report_t = threading.Thread(
            target=self._report_loop, daemon=True, name="report-thread"
        )
        report_t.start()
        logger.info(f"Report thread started (tid={report_t.ident})")

        policy_t = threading.Thread(
            target=self._policy_refresh_loop, daemon=True, name="policy-thread"
        )
        policy_t.start()

        health_t = threading.Thread(
            target=self._health_check_loop, daemon=True, name="health-thread"
        )
        health_t.start()

        logger.info(f"Engine started. Mode: {'SIMULATION' if self.simulate else 'LIVE on ' + str(self.capture.interface)}")
        logger.info(f"Enforcement: {'ENABLED' if self.enforce else 'DISABLED (analysis only)'}")
        logger.info("Press Ctrl+C to stop.\n")

        # Keep main thread alive
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop the ML engine gracefully."""
        logger.info("Shutting down...")
        self._running = False
        self.capture.stop()
        if self.enforcer:
            self.enforcer.cleanup()
        logger.info("Engine stopped.")

    def _on_flow_complete(self, flow: Flow):
        """Called when a network flow is complete. Runs ML analysis."""
        try:
            # Run inference pipeline
            prediction = self.pipeline.analyze(flow)

            # Log prediction counter periodically
            pred_count = self.pipeline.total_predictions
            if pred_count == 1:
                logger.info(
                    "[MILESTONE] First prediction generated! "
                    "Pipeline is operational."
                )
            elif pred_count % 50 == 0:
                logger.info(
                    f"[COUNTER] {pred_count} total predictions | "
                    f"{self.pipeline.predictions_per_minute:.1f}/min | "
                    f"blocked={self.pipeline.total_blocked}, "
                    f"alerts={self.pipeline.total_alerts}"
                )

            # Override action with policy engine (user-defined rules take priority)
            if self.policy_engine.policies:
                original_action = prediction.action
                policy_action = self.policy_engine.evaluate_simple(
                    context=prediction.context,
                    anomaly_score=prediction.anomaly_score,
                    attack_type=prediction.attack_type,
                    confidence=prediction.confidence,
                )
                if policy_action != original_action:
                    # Reconcile pipeline stats so they reflect the final
                    # (post-policy) action rather than the pre-policy one.
                    if original_action == "block":
                        self.pipeline.total_blocked -= 1
                    elif original_action == "alert":
                        self.pipeline.total_alerts -= 1
                    if policy_action == "block":
                        self.pipeline.total_blocked += 1
                    elif policy_action == "alert":
                        self.pipeline.total_alerts += 1
                    prediction.action = policy_action

            # Log the prediction
            self._log_prediction(prediction)

            # Enforce action
            if self.enforce and prediction.action == "block":
                # For inbound attack types the attacker is the source;
                # for outbound suspicious flows the destination is blocked.
                inbound_attack_types = ("DDoS", "DoS", "BruteForce", "PortScan")
                if prediction.attack_type in inbound_attack_types:
                    block_ip = prediction.context.src_ip
                else:
                    block_ip = prediction.context.dst_ip

                self.enforcer.block_ip(
                    ip=block_ip,
                    app_name=prediction.context.app_name,
                    reason=f"{prediction.attack_type} (score: {prediction.anomaly_score:.2f})",
                )

            # Buffer for reporting to backend
            with self._lock:
                self._predictions.append(prediction.to_dict())
                if len(self._predictions) > 1000:
                    self._predictions = self._predictions[-500:]

        except Exception as e:
            logger.error(
                f"Error analyzing flow {flow.flow_id}: {e}\n"
                f"{traceback.format_exc()}"
            )

    def _log_prediction(self, pred: Prediction):
        """Log prediction with color-coded action."""
        action_colors = {
            "allow": "\033[92m",  # green
            "alert": "\033[93m",  # yellow
            "block": "\033[91m",  # red
        }
        reset = "\033[0m"
        color = action_colors.get(pred.action, "")

        logger.info(
            f"{color}[{pred.action.upper()}]{reset} "
            f"{pred.context.app_name} → {pred.context.dst_ip}:{pred.context.dst_port} "
            f"| Score: {pred.anomaly_score:.3f} "
            f"| Type: {pred.attack_type} ({pred.confidence:.0%}) "
            f"| Country: {pred.context.dest_country}"
        )

    def _report_loop(self):
        """Periodically send predictions and stats to the backend API."""
        api_key = os.getenv("ML_API_KEY", "change-me-in-production")
        headers = {"X-ML-API-Key": api_key}
        _consecutive_failures = 0
        _total_sent = 0
        _empty_cycles = 0

        logger.info(
            f"Report loop started — target: {config.backend_url}/api/ml/predictions"
        )

        while self._running:
            time.sleep(10)
            try:
                # Snapshot the batch under the lock; skip if empty.
                with self._lock:
                    if not self._predictions:
                        _empty_cycles += 1
                        if _empty_cycles == 12:  # ~60 s of empty buffer
                            logger.warning(
                                "[REPORT] No predictions buffered for ~60 s — "
                                "check capture and inference stages"
                            )
                            _empty_cycles = 0
                        continue
                    batch = list(self._predictions[:20])
                _empty_cycles = 0

                # Send to backend — only remove from buffer on success
                logger.debug(
                    f"[REPORT] Sending {len(batch)} predictions to backend..."
                )
                resp = requests.post(
                    f"{config.backend_url}/api/ml/predictions",
                    json={
                        "predictions": batch,
                        "engine_status": {
                            "models_loaded": self.pipeline.models_loaded,
                        },
                    },
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code < 300:
                    with self._lock:
                        # Remove the successfully sent items
                        self._predictions = self._predictions[len(batch):]
                    _consecutive_failures = 0
                    _total_sent += len(batch)
                    logger.info(
                        f"[REPORT] {len(batch)} predictions sent OK "
                        f"(total sent: {_total_sent})"
                    )
                elif resp.status_code == 403:
                    _consecutive_failures += 1
                    logger.error(
                        "Backend returned 403 Forbidden — ML_API_KEY mismatch. "
                        "Ensure the ML engine's ML_API_KEY env var matches the "
                        "backend's ML_API_KEY setting. Predictions will NOT be "
                        "stored until this is fixed. "
                        f"(consecutive failures: {_consecutive_failures})"
                    )
                else:
                    _consecutive_failures += 1
                    logger.warning(
                        f"Backend rejected prediction batch: {resp.status_code} "
                        f"— {resp.text[:200]} "
                        f"(consecutive failures: {_consecutive_failures})"
                    )
            except requests.exceptions.ConnectionError:
                _consecutive_failures += 1
                logger.warning(
                    f"Backend not reachable at {config.backend_url} — "
                    "predictions buffered for retry "
                    f"(consecutive failures: {_consecutive_failures})"
                )
            except Exception as e:
                _consecutive_failures += 1
                logger.warning(
                    f"Failed to report predictions: {e} "
                    f"(consecutive failures: {_consecutive_failures})"
                )

    def _health_check_loop(self):
        """Periodic pipeline health probe — logs stage-by-stage status."""
        # Wait one full flow_timeout cycle before the first check so
        # there is time for at least one flow to complete.
        time.sleep(self.capture.flow_timeout + 5)
        _consecutive_zero_predictions = 0

        while self._running:
            cap = self.capture.get_stats()
            with self._lock:
                buf_len = len(self._predictions)

            logger.info(
                f"[HEALTH] Capture: {cap['total_packets']} pkts, "
                f"{cap['total_flows']} flows, {cap['active_flows']} active | "
                f"Pipeline: {self.pipeline.total_predictions} predictions, "
                f"{self.pipeline.predictions_per_minute:.1f}/min | "
                f"Buffer: {buf_len} pending POST | "
                f"Capture thread: {'alive' if cap.get('capture_alive') else 'DEAD'}"
            )

            # ── Stage-specific diagnostics ──
            if not cap["running"] or not cap.get("capture_alive"):
                logger.critical(
                    "[HEALTH] Capture thread is NOT running — "
                    "check for permission errors or bad interface above"
                )
            elif cap["total_packets"] == 0:
                logger.warning(
                    "[HEALTH] ZERO packets captured — verify interface "
                    f"'{cap['interface']}' and admin privileges"
                )
            elif cap["total_flows"] == 0:
                logger.warning(
                    "[HEALTH] Packets arriving but no flows completed yet — "
                    "waiting for flow_timeout"
                )
            elif self.pipeline.total_predictions == 0:
                _consecutive_zero_predictions += 1
                if _consecutive_zero_predictions >= 3:
                    logger.error(
                        "[HEALTH] Flows completing but ZERO predictions for "
                        f"{_consecutive_zero_predictions} consecutive checks — "
                        "analyze() is consistently failing (check tracebacks above)"
                    )
                else:
                    logger.warning(
                        "[HEALTH] Flows completing but ZERO predictions — "
                        "analyze() is likely throwing exceptions (check logs above)"
                    )
            else:
                _consecutive_zero_predictions = 0

            if buf_len > 100:
                logger.warning(
                    "[HEALTH] Prediction buffer growing (%d items) — backend POST "
                    "may be failing (API key mismatch? backend down?)",
                    buf_len,
                )

            time.sleep(15)

    def _policy_refresh_loop(self):
        """Periodically refresh policies from the backend."""
        while self._running:
            time.sleep(60)
            self._load_policies()

    def _load_policies(self):
        """Load active policies from backend API."""
        try:
            res = requests.get(f"{config.backend_url}/api/policies", timeout=5)
            if res.status_code == 200:
                policies = res.json()
                self.policy_engine.load_policies(policies)
        except Exception:
            logger.debug("Could not load policies from backend (may not be running)")


def main():
    parser = argparse.ArgumentParser(description="Guardian Shield ML Engine")
    parser.add_argument("--interface", "-i", default="", help="Network interface to capture on")
    parser.add_argument("--no-enforce", action="store_true", help="Analysis only, don't block traffic")
    parser.add_argument(
        "--simulate", "-s", action="store_true",
        help="Use simulated traffic instead of live packet capture "
             "(no Npcap or admin rights needed)",
    )
    args = parser.parse_args()

    engine = GuardianShieldEngine(
        interface=args.interface,
        enforce=not args.no_enforce,
        simulate=args.simulate,
    )
    engine.start()


if __name__ == "__main__":
    main()
