import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String

from app.database import Base


class AlertSilenceRule(Base):
    __tablename__ = "alert_silence_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    endpoint_id = Column(String(36), ForeignKey("endpoints.id"), nullable=True, index=True)
    attack_type = Column(String(100), nullable=True, index=True)
    app_name = Column(String(255), nullable=True, index=True)
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
