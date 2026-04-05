import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class AlertFeedback(Base):
    __tablename__ = "alert_feedback"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False, index=True)
    target_type = Column(String(50), nullable=True)
    target_value = Column(String(255), nullable=True)
    policy_id = Column(String(36), ForeignKey("policies.id"), nullable=True)
    silence_rule_id = Column(String(36), ForeignKey("alert_silence_rules.id"), nullable=True)
    note = Column(Text, nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    alert = relationship("Alert", lazy="selectin")
    policy = relationship("Policy", lazy="selectin")
    rule = relationship("AlertSilenceRule", lazy="selectin")
    user = relationship("User", lazy="selectin")
