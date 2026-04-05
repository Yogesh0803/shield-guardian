"""
Behavioral baseline tracking.
Learns what "normal" looks like per endpoint/app/time bucket and detects
significant changes over the last 7 days.
"""

import time
import math
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class BaselineStats:
    """Rolling statistics for a baseline profile."""
    profile_key: str = ""
    endpoint_key: str = ""
    app_name: str = ""
    time_bucket: str = ""
    request_rate: float = 0.0  # requests per minute
    avg_packet_size: float = 0.0
    avg_bytes_per_flow: float = 0.0
    common_ports: Dict[int, int] = field(default_factory=dict)
    common_destinations: Dict[str, int] = field(default_factory=dict)
    total_observations: int = 0
    last_updated: float = 0.0

    # EMA parameters
    _rate_ema: float = 0.0
    _size_ema: float = 0.0
    _bytes_ema: float = 0.0
    _rate_var: float = 0.0
    _size_var: float = 0.0

    # Day-ordinal -> aggregate metrics for drift checks.
    _daily_aggregates: Dict[int, Dict[str, float]] = field(default_factory=dict)


@dataclass
class BehaviorContext:
    rate_deviation: float  # z-score: how unusual is the request rate
    size_deviation: float  # z-score: how unusual is the packet size
    destination_novelty: float  # 0.0 (seen before) to 1.0 (never seen)
    port_novelty: float  # 0.0 (common port) to 1.0 (never used port)
    baseline_profile_key: str
    baseline_time_bucket: str
    baseline_changed_7d: bool
    baseline_change_score: float
    baseline_change_reason: str


class BehaviorBaseline:
    """Tracks and compares against behavioral baselines per endpoint/app/time bucket."""

    ALPHA = 0.1  # EMA smoothing factor (lower = slower adaptation)
    DRIFT_WINDOW_DAYS = 7
    DRIFT_CHANGE_THRESHOLD = 0.5

    def __init__(self):
        self._baselines: Dict[str, BaselineStats] = {}

    def _time_bucket(self, hour: int) -> str:
        if 0 <= hour < 6:
            return "night"
        if 6 <= hour < 12:
            return "morning"
        if 12 <= hour < 18:
            return "afternoon"
        return "evening"

    def _profile_key(self, endpoint_key: str, app_name: str, hour: int) -> str:
        bucket = self._time_bucket(hour)
        return f"{endpoint_key}|{app_name.lower()}|{bucket}"

    def _update_daily_aggregate(
        self,
        baseline: BaselineStats,
        ts: float,
        current_rate: float,
        packet_size: float,
    ):
        day = datetime.fromtimestamp(ts).toordinal()
        agg = baseline._daily_aggregates.setdefault(
            day,
            {
                "observations": 0.0,
                "rate_sum": 0.0,
                "size_sum": 0.0,
            },
        )
        agg["observations"] += 1.0
        agg["rate_sum"] += current_rate
        agg["size_sum"] += packet_size

        # Keep recent window only (+buffer day).
        min_day = day - (self.DRIFT_WINDOW_DAYS + 1)
        stale_days: List[int] = [d for d in baseline._daily_aggregates if d < min_day]
        for stale in stale_days:
            baseline._daily_aggregates.pop(stale, None)

    def _compute_7d_drift(self, baseline: BaselineStats, ts: float) -> tuple[bool, float, str]:
        today = datetime.fromtimestamp(ts).toordinal()
        current = baseline._daily_aggregates.get(today)
        if not current or current.get("observations", 0.0) < 10:
            return False, 0.0, "insufficient_recent_data"

        reference_days = [d for d in baseline._daily_aggregates if today - self.DRIFT_WINDOW_DAYS <= d < today]
        if not reference_days:
            return False, 0.0, "insufficient_history"

        ref_obs = sum(baseline._daily_aggregates[d]["observations"] for d in reference_days)
        if ref_obs < 25:
            return False, 0.0, "insufficient_history"

        cur_rate = current["rate_sum"] / max(current["observations"], 1.0)
        cur_size = current["size_sum"] / max(current["observations"], 1.0)
        ref_rate = sum(baseline._daily_aggregates[d]["rate_sum"] for d in reference_days) / max(ref_obs, 1.0)
        ref_size = sum(baseline._daily_aggregates[d]["size_sum"] for d in reference_days) / max(ref_obs, 1.0)

        rate_delta = abs(cur_rate - ref_rate) / max(ref_rate, 1e-6)
        size_delta = abs(cur_size - ref_size) / max(ref_size, 1e-6)
        score = max(rate_delta, size_delta)
        changed = score >= self.DRIFT_CHANGE_THRESHOLD
        reason = "rate_shift" if rate_delta >= size_delta else "packet_size_shift"
        return changed, score, reason

    def get_profile_count(self) -> int:
        return len(self._baselines)

    def get_drifted_profiles_count(self) -> int:
        now = time.time()
        count = 0
        for baseline in self._baselines.values():
            changed, _, _ = self._compute_7d_drift(baseline, now)
            if changed:
                count += 1
        return count

    def update_and_compare(
        self,
        endpoint_key: str,
        app_name: str,
        hour: int,
        packet_size: float,
        bytes_in_flow: float,
        dst_ip: str,
        dst_port: int,
        timestamp: float = None,
    ) -> BehaviorContext:
        """
        Update baseline for this source and return deviation scores.

        Args:
            endpoint_key: Endpoint identifier (typically src_ip)
            app_name: Application identifier
            hour: Local hour of day for time-bucketed baselines
            packet_size: Average packet size in this flow
            bytes_in_flow: Total bytes in this flow
            dst_ip: Destination IP
            dst_port: Destination port
            timestamp: Current time
        """
        ts = timestamp or time.time()
        profile_key = self._profile_key(endpoint_key, app_name, hour)
        bucket = self._time_bucket(hour)

        if profile_key not in self._baselines:
            self._baselines[profile_key] = BaselineStats(
                profile_key=profile_key,
                endpoint_key=endpoint_key,
                app_name=app_name,
                time_bucket=bucket,
                last_updated=ts,
            )

        baseline = self._baselines[profile_key]

        # Calculate current request rate
        time_diff = ts - baseline.last_updated if baseline.last_updated > 0 else 60.0
        time_diff = max(time_diff, 0.001)
        current_rate = 60.0 / time_diff  # requests per minute

        # Compute deviations BEFORE updating baseline
        if baseline.total_observations < 5:
            # Not enough data for meaningful comparison
            rate_dev = 0.0
            size_dev = 0.0
        else:
            rate_dev = self._z_score(current_rate, baseline._rate_ema, baseline._rate_var)
            size_dev = self._z_score(packet_size, baseline._size_ema, baseline._size_var)

        # Destination novelty
        dest_count = baseline.common_destinations.get(dst_ip, 0)
        total_dest = sum(baseline.common_destinations.values()) or 1
        destination_novelty = 1.0 - (dest_count / total_dest) if dest_count > 0 else 1.0

        # Port novelty
        port_count = baseline.common_ports.get(dst_port, 0)
        total_ports = sum(baseline.common_ports.values()) or 1
        port_novelty = 1.0 - (port_count / total_ports) if port_count > 0 else 1.0

        # Update baseline with EMA
        alpha = self.ALPHA
        baseline._rate_ema = alpha * current_rate + (1 - alpha) * baseline._rate_ema
        baseline._size_ema = alpha * packet_size + (1 - alpha) * baseline._size_ema
        baseline._bytes_ema = alpha * bytes_in_flow + (1 - alpha) * baseline._bytes_ema
        baseline._rate_var = alpha * (current_rate - baseline._rate_ema) ** 2 + (1 - alpha) * baseline._rate_var
        baseline._size_var = alpha * (packet_size - baseline._size_ema) ** 2 + (1 - alpha) * baseline._size_var

        baseline.request_rate = baseline._rate_ema
        baseline.avg_packet_size = baseline._size_ema
        baseline.avg_bytes_per_flow = baseline._bytes_ema

        # Update destination/port counts
        baseline.common_destinations[dst_ip] = baseline.common_destinations.get(dst_ip, 0) + 1
        baseline.common_ports[dst_port] = baseline.common_ports.get(dst_port, 0) + 1

        # Keep only top 100 destinations/ports to prevent memory growth
        if len(baseline.common_destinations) > 100:
            sorted_dests = sorted(baseline.common_destinations.items(), key=lambda x: x[1], reverse=True)
            baseline.common_destinations = dict(sorted_dests[:100])
        if len(baseline.common_ports) > 50:
            sorted_ports = sorted(baseline.common_ports.items(), key=lambda x: x[1], reverse=True)
            baseline.common_ports = dict(sorted_ports[:50])

        baseline.total_observations += 1
        baseline.last_updated = ts

        self._update_daily_aggregate(baseline, ts, current_rate, packet_size)
        changed_7d, change_score, change_reason = self._compute_7d_drift(baseline, ts)

        return BehaviorContext(
            rate_deviation=rate_dev,
            size_deviation=size_dev,
            destination_novelty=destination_novelty,
            port_novelty=port_novelty,
            baseline_profile_key=profile_key,
            baseline_time_bucket=bucket,
            baseline_changed_7d=changed_7d,
            baseline_change_score=change_score,
            baseline_change_reason=change_reason,
        )

    def _z_score(self, value: float, mean: float, variance: float) -> float:
        """Compute z-score (number of standard deviations from mean)."""
        std = math.sqrt(variance) if variance > 0 else 1.0
        return abs(value - mean) / std

    def get_baseline(self, key: str) -> BaselineStats:
        """Get baseline stats for a source."""
        return self._baselines.get(key, BaselineStats())
