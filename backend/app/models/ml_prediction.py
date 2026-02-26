import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, Index, Integer, String, DateTime, Float
from sqlalchemy.dialects.sqlite import JSON

from app.database import Base


class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    anomaly_score = Column(Float, nullable=False)
    attack_type = Column(String(100), nullable=True)
    confidence = Column(Float, nullable=False)
    action = Column(String(50), nullable=False, index=True)
    app_name = Column(String(255), nullable=True)
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    context_json = Column(JSON, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        # Composite index for the attack_type filter used by accuracy queries
        Index("ix_ml_predictions_attack_type", "attack_type"),
    )
