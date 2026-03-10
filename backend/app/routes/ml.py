from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.schemas.ml import (
    MLStatusResponse,
    MLAccuracy,
    MLPredictionBatch,
    MLPredictionIngestResponse,
)
from app.middleware.auth import get_current_user, require_admin
from app.models.user import User
from app.models.ml_prediction import MLPrediction
from app.models.alert import Alert
from app.models.endpoint import Endpoint
from app.database import get_db
from app.config import settings
from app.services.ml_loader import get_loaded_models

import uuid as _uuid

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])

# Cache for ML engine status piggybacked on prediction batches.
# Updated every time ingest_predictions receives an engine_status payload.
_cached_engine_status: dict = {
    "models_loaded": [],
    "updated_at": None,
}


def _verify_ml_api_key(x_ml_api_key: Optional[str] = Header(None)) -> None:
    """Validate the shared secret sent by the ML engine.

    The ML engine must include an ``X-ML-API-Key`` header whose value
    matches the ``ML_API_KEY`` setting.  This prevents unauthenticated
    actors from injecting bogus predictions.
    """
    if not x_ml_api_key or x_ml_api_key != settings.ML_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing ML API key",
        )


def _tz_naive_utcnow() -> datetime:
    """Return current UTC time as a timezone-naive datetime.

    SQLite may return naive datetimes even when timezone-aware values
    were stored.  All comparisons in this module use naive UTC to
    avoid TypeError from mixing aware and naive datetimes.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


@router.get("/status", response_model=MLStatusResponse)
def get_ml_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return ML model status from actual prediction data in the database."""
    total_predictions = db.query(func.count(MLPrediction.id)).scalar() or 0
    total_blocked = (
        db.query(func.count(MLPrediction.id))
        .filter(MLPrediction.action == "block")
        .scalar()
        or 0
    )
    total_alerts = (
        db.query(func.count(MLPrediction.id))
        .filter(MLPrediction.action == "alert")
        .scalar()
        or 0
    )

    # Calculate predictions per minute over the last 10 minutes
    now = _tz_naive_utcnow()
    ten_min_ago = now - timedelta(minutes=10)
    recent_count = (
        db.query(func.count(MLPrediction.id))
        .filter(MLPrediction.timestamp >= ten_min_ago)
        .scalar()
        or 0
    )
    predictions_per_minute = round(recent_count / 10.0, 1)

    import logging as _log
    _ml_logger = _log.getLogger("guardian-shield.ml-status")
    _ml_logger.debug(
        f"predictions_per_minute calc: now(utc)={now.isoformat()}, "
        f"window_start={ten_min_ago.isoformat()}, "
        f"recent_count={recent_count}, ppm={predictions_per_minute}, "
        f"total={total_predictions}"
    )

    # Find most recent prediction timestamp as a proxy for "last active"
    last_prediction = db.query(func.max(MLPrediction.timestamp)).scalar()

    # Determine if the ML engine is running.
    # Option A: the external engine has sent predictions in the last 2 min.
    # Option B: model artefacts exist on disk (models are loadable).
    two_min_ago = now - timedelta(minutes=2)
    if last_prediction is not None:
        # Normalise to naive UTC for safe comparison
        lp = (
            last_prediction.replace(tzinfo=None)
            if last_prediction.tzinfo
            else last_prediction
        )
        is_running = lp >= two_min_ago
    else:
        is_running = False

    # If models are available on disk, consider the engine "ready"
    # even when no live predictions have been received yet.
    if not is_running and get_loaded_models():
        is_running = True

    # ── Model confidence from real prediction data ──────────────────
    # anomaly_detector: avg decisiveness — how far anomaly_score is
    #   from the 0.5 boundary (always >= 0.5; higher = more confident).
    anomaly_confidence = (
        db.query(
            func.avg(
                case(
                    (MLPrediction.anomaly_score > 0.5, MLPrediction.anomaly_score),
                    else_=(1.0 - MLPrediction.anomaly_score),
                )
            )
        ).scalar()
        if total_predictions > 0
        else None
    )
    # attack_classifier: avg confidence on classified attacks only.
    attack_confidence = (
        db.query(func.avg(MLPrediction.confidence))
        .filter(
            MLPrediction.attack_type.notin_(["Benign", "Unknown"]),
            MLPrediction.attack_type.isnot(None),
        )
        .scalar()
        if total_predictions > 0
        else None
    )

    # Models loaded — merge engine cache with locally probed files so the
    # dashboard shows models even when the external ML engine isn't running.
    engine_models = _cached_engine_status.get("models_loaded") or []
    local_models = get_loaded_models()  # populated at startup by probe_models()
    # Deduplicate while preserving order
    seen = set()
    models_loaded = []
    for m in engine_models + local_models:
        if m not in seen:
            seen.add(m)
            models_loaded.append(m)

    return MLStatusResponse(
        is_running=is_running,
        models_loaded=models_loaded,
        predictions_per_minute=predictions_per_minute,
        last_retrain=None,
        accuracy=MLAccuracy(
            anomaly_detector=round(anomaly_confidence, 4) if anomaly_confidence else 0.0,
            attack_classifier=round(attack_confidence, 4) if attack_confidence else 0.0,
        ),
        total_predictions=total_predictions,
        total_blocked=total_blocked,
        total_alerts=total_alerts,
    )


@router.post("/predictions")
def ingest_predictions(
    batch: MLPredictionBatch,
    db: Session = Depends(get_db),
    _key: None = Depends(_verify_ml_api_key),
):
    """
    Receive a batch of ML predictions from the ML engine and persist them.

    This endpoint is called periodically by the ML engine's _report_loop.
    No authentication is required (internal service-to-service call).
    """
    import logging
    logger = logging.getLogger(__name__)

    # Update cached engine status if the engine supplied one
    if batch.engine_status:
        _cached_engine_status["models_loaded"] = (
            batch.engine_status.models_loaded or []
        )
        _cached_engine_status["updated_at"] = _tz_naive_utcnow()

    created = 0
    errors = 0
    records = []
    for pred in batch.predictions:
        try:
            # Store as naive UTC to avoid mixed-tz comparisons on read-back
            if pred.timestamp:
                ts = datetime.fromtimestamp(
                    pred.timestamp, tz=timezone.utc
                ).replace(tzinfo=None)
            else:
                ts = _tz_naive_utcnow()

            record = MLPrediction(
                anomaly_score=pred.anomaly_score,
                attack_type=pred.attack_type,
                confidence=pred.confidence,
                action=pred.action,
                app_name=pred.app_name,
                src_ip=pred.src_ip,
                dst_ip=pred.dst_ip,
                src_port=pred.src_port,
                dst_port=pred.dst_port,
                protocol=pred.protocol,
                context_json=pred.context if pred.context else None,
                timestamp=ts,
            )
            records.append(record)
            created += 1
        except Exception as e:
            errors += 1
            logger.warning(f"Skipping malformed prediction: {e}")

    # Bulk-add all valid records and commit once.  This avoids the
    # previous bug where db.rollback() on one bad record would silently
    # discard all previously-added valid records in the same session.
    if records:
        try:
            db.add_all(records)
            # Create alerts and discover endpoints within the same transaction
            _create_alerts_from_predictions(batch.predictions, db, logger)
            _discover_endpoints_from_predictions(batch.predictions, db, logger)
            db.commit()
            logger.info(
                f"[INGEST] Stored {created} prediction(s) OK "
                f"(errors={errors}, ts_range="
                f"{records[0].timestamp.isoformat() if records else 'n/a'}"
                f"..{records[-1].timestamp.isoformat() if records else 'n/a'})"
            )
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to commit prediction batch: {e}")
            return MLPredictionIngestResponse(
                status="error",
                predictions_stored=0,
                errors=len(batch.predictions),
            )
    else:
        logger.warning(
            "[INGEST] Received batch but 0 valid records created "
            f"({errors} errors)"
        )

    return MLPredictionIngestResponse(
        status="ok",
        predictions_stored=created,
        errors=errors,
    )


_ATTACK_TYPE_TO_CATEGORY = {
    "DDoS": "intrusion",
    "DoS": "intrusion",
    "BruteForce": "authentication",
    "PortScan": "intrusion",
    "SQL Injection": "intrusion",
    "XSS": "intrusion",
    "WebAttack": "intrusion",
    "Infiltration": "malware",
    "Bot": "malware",
    "Heartbleed": "intrusion",
    "DNS Tunneling": "anomaly",
    "Data Exfiltration": "data_leak",
    "Unknown": "anomaly",
}


def _action_to_severity(action: str, anomaly_score: float) -> str:
    """Map prediction action + score to an alert severity."""
    if action == "block":
        return "critical" if anomaly_score > 0.85 else "high"
    if action == "alert":
        return "high" if anomaly_score > 0.7 else "medium"
    return "low"


def _create_alerts_from_predictions(predictions, db: Session, logger):
    """Create Alert records for block/alert predictions."""
    alerts_to_add = []
    # Find existing endpoint IPs for linking alerts to endpoints (columns only, avoid relationship loading)
    endpoint_map = {ip: eid for ip, eid in db.query(Endpoint.ip_address, Endpoint.id).all()}

    for pred in predictions:
        if pred.action not in ("block", "alert"):
            continue

        attack_type = pred.attack_type or "Unknown"
        category = _ATTACK_TYPE_TO_CATEGORY.get(attack_type, "anomaly")
        severity = _action_to_severity(pred.action, pred.anomaly_score)

        # Link to the endpoint that matches the dst_ip (defended host)
        endpoint_id = endpoint_map.get(pred.dst_ip) or endpoint_map.get(pred.src_ip)
        if not endpoint_id:
            # Fall back to first endpoint if no IP match
            first_ep_id = db.query(Endpoint.id).first()
            endpoint_id = first_ep_id[0] if first_ep_id else None
        if not endpoint_id:
            continue  # no endpoints exist at all

        src = pred.src_ip or "?"
        dst = pred.dst_ip or "?"
        port = pred.dst_port or "?"
        msg = (
            f"{attack_type} detected: {src} → {dst}:{port} "
            f"(score: {pred.anomaly_score:.2f}, app: {pred.app_name or 'unknown'})"
        )

        if pred.timestamp:
            ts = datetime.fromtimestamp(
                pred.timestamp, tz=timezone.utc
            ).replace(tzinfo=None)
        else:
            ts = _tz_naive_utcnow()

        alert = Alert(
            id=str(_uuid.uuid4()),
            severity=severity,
            category=category,
            attack_type=attack_type,
            message=msg,
            confidence=pred.confidence,
            endpoint_id=endpoint_id,
            timestamp=ts,
        )
        alerts_to_add.append(alert)

    if alerts_to_add:
        db.add_all(alerts_to_add)
        logger.info(f"[INGEST] Queued {len(alerts_to_add)} alert(s) from predictions")


def _discover_endpoints_from_predictions(predictions, db: Session, logger):
    """Auto-register new endpoints discovered from prediction traffic."""
    existing_ips = {ip for (ip,) in db.query(Endpoint.ip_address).all()}
    seen_ips = set()
    new_endpoints = []

    for pred in predictions:
        for ip in (pred.dst_ip, pred.src_ip):
            if not ip or ip in existing_ips or ip in seen_ips:
                continue
            # Skip loopback and link-local addresses
            if ip.startswith("127.") or ip.startswith("0.") or ip == "0.0.0.0":
                continue
            seen_ips.add(ip)
            # Only auto-register private / monitored IPs as endpoints
            if _is_private_ip(ip):
                ep = Endpoint(
                    id=str(_uuid.uuid4()),
                    name=f"Auto-discovered ({ip})",
                    ip_address=ip,
                    status="active",
                )
                new_endpoints.append(ep)

    if new_endpoints:
        db.add_all(new_endpoints)
        logger.info(
            f"[INGEST] Queued {len(new_endpoints)} new endpoint(s): "
            f"{[ep.ip_address for ep in new_endpoints]}"
        )


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    return (
        ip.startswith("10.")
        or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.")
        or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("192.168.")
    )


@router.post("/retrain")
def retrain_model(admin_user: User = Depends(require_admin)):
    """Trigger model retraining (placeholder). Requires admin role."""
    return {
        "status": "training_initiated",
        "message": "Model retraining has been queued. Estimated time: 15 minutes.",
        "initiated_by": admin_user.email,
        "estimated_completion": (
            datetime.now(timezone.utc) + timedelta(minutes=15)
        ).isoformat(),
    }
