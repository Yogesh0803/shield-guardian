from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Literal
from datetime import datetime


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    severity: str
    category: str
    attack_type: Optional[str] = None
    message: str
    confidence: Optional[float] = None
    app_id: Optional[str] = None
    endpoint_id: str
    timestamp: datetime
    feedback_action: Optional[str] = None
    is_false_positive: bool = False
    whitelisted_target: Optional[str] = None
    silenced_rule_id: Optional[str] = None
    feedback_note: Optional[str] = None


class AlertQuery(BaseModel):
    endpoint_id: Optional[str] = None
    app_id: Optional[str] = None
    severity: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=500)


class FalsePositiveAction(BaseModel):
    note: Optional[str] = None


class WhitelistAction(BaseModel):
    target_type: Literal["ip", "domain", "app"]
    target_value: Optional[str] = None
    note: Optional[str] = None


class SilenceRuleAction(BaseModel):
    policy_id: Optional[str] = None
    note: Optional[str] = None
