from pydantic import BaseModel, field_validator
from typing import Optional, Dict, Any, List
from datetime import datetime


class MLAccuracy(BaseModel):
    """Model confidence metrics computed from prediction data.

    anomaly_detector — avg decisiveness: how far anomaly scores are from
                       the 0.5 decision boundary (higher = more confident).
    attack_classifier — avg confidence of the classifier on identified
                        attack flows (excludes Benign / Unknown).
    """
    anomaly_detector: float
    attack_classifier: float


class MLStatusResponse(BaseModel):
    is_running: bool
    models_loaded: list[str]
    predictions_per_minute: float
    last_retrain: Optional[str] = None
    accuracy: MLAccuracy
    total_predictions: int
    total_blocked: int
    total_alerts: int = 0


class MLPredictionCreate(BaseModel):
    """Schema for a single prediction submitted by the ML engine."""
    anomaly_score: float
    attack_type: Optional[str] = "Benign"
    confidence: float
    action: str
    app_name: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    timestamp: Optional[float] = None
    # Explainability data — attached by the ML engine when available
    explanation: Optional[Dict[str, Any]] = None

    @field_validator("anomaly_score", "confidence")
    @classmethod
    def clamp_zero_one(cls, v: float) -> float:
        return max(0.0, min(float(v), 1.0))

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed = {"allow", "alert", "block"}
        if v not in allowed:
            raise ValueError(f"action must be one of {allowed}")
        return v


class MLEngineStatus(BaseModel):
    """Lightweight status piggybacked on prediction batches."""
    models_loaded: Optional[List[str]] = None


class MLPredictionBatch(BaseModel):
    """Batch of predictions sent by the ML engine.

    Capped at 200 predictions per request to bound memory and DB
    write time.  The ML engine sends at most 50 per cycle, so 200
    provides ample headroom.
    """
    predictions: List[MLPredictionCreate]
    engine_status: Optional[MLEngineStatus] = None

    @field_validator("predictions")
    @classmethod
    def cap_batch_size(cls, v: List[MLPredictionCreate]) -> List[MLPredictionCreate]:
        max_batch = 200
        if len(v) > max_batch:
            raise ValueError(
                f"batch size {len(v)} exceeds maximum of {max_batch}"
            )
        return v


class MLPredictionIngestResponse(BaseModel):
    """Response for POST /api/ml/predictions."""
    status: str
    predictions_stored: int
    errors: int = 0


class MLPredictionResponse(BaseModel):
    id: str
    anomaly_score: float
    attack_type: Optional[str] = None
    confidence: float
    action: str
    app_name: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    context_json: Optional[Dict[str, Any]] = None
    timestamp: datetime

    class Config:
        from_attributes = True
