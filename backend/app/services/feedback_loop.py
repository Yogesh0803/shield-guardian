import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


_LOCK = threading.Lock()
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_DATA_DIR = _BACKEND_ROOT / "data"
_FEEDBACK_LOG_PATH = _DATA_DIR / "ml_feedback_labels.jsonl"
_TUNING_PATH = _DATA_DIR / "threshold_tuning.json"


def _ensure_data_dir() -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)


def _default_tuning() -> Dict[str, Any]:
    return {
        "reviewed_count": 0,
        "false_positive_count": 0,
        "whitelist_count": 0,
        "silence_rule_count": 0,
        "recommended_thresholds": {
            "anomaly_threshold_medium": 0.5,
            "anomaly_threshold_high": 0.8,
        },
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _load_tuning() -> Dict[str, Any]:
    if not _TUNING_PATH.exists():
        return _default_tuning()
    try:
        return json.loads(_TUNING_PATH.read_text(encoding="utf-8"))
    except Exception:
        return _default_tuning()


def _save_tuning(payload: Dict[str, Any]) -> None:
    payload["updated_at"] = datetime.now(timezone.utc).isoformat()
    _TUNING_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _recompute_thresholds(tuning: Dict[str, Any]) -> None:
    reviewed = max(int(tuning.get("reviewed_count", 0)), 1)
    fp_count = int(tuning.get("false_positive_count", 0))
    fp_rate = fp_count / reviewed

    # Conservative adaptation: raise thresholds as FP rate increases.
    medium = max(0.5, min(0.85, 0.5 + (fp_rate * 0.2)))
    high = max(0.75, min(0.97, 0.8 + (fp_rate * 0.15)))

    tuning["recommended_thresholds"] = {
        "anomaly_threshold_medium": round(medium, 3),
        "anomaly_threshold_high": round(high, 3),
        "false_positive_rate": round(fp_rate, 4),
    }


def record_feedback(feedback_record: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_data_dir()

    with _LOCK:
        feedback_record = dict(feedback_record)
        feedback_record["logged_at"] = datetime.now(timezone.utc).isoformat()

        with _FEEDBACK_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(feedback_record) + "\n")

        tuning = _load_tuning()
        tuning["reviewed_count"] = int(tuning.get("reviewed_count", 0)) + 1

        action_type = str(feedback_record.get("action_type", "")).lower()
        if action_type == "false_positive":
            tuning["false_positive_count"] = int(tuning.get("false_positive_count", 0)) + 1
        elif action_type == "whitelist":
            tuning["whitelist_count"] = int(tuning.get("whitelist_count", 0)) + 1
        elif action_type == "silence_rule":
            tuning["silence_rule_count"] = int(tuning.get("silence_rule_count", 0)) + 1

        _recompute_thresholds(tuning)
        _save_tuning(tuning)

        return tuning


def get_tuning_summary() -> Dict[str, Any]:
    _ensure_data_dir()
    with _LOCK:
        tuning = _load_tuning()
        _recompute_thresholds(tuning)
        return tuning
