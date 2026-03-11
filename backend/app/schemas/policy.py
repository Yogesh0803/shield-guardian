from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class PolicyCreate(BaseModel):
    name: str = Field(..., description="Policy name")
    description: Optional[str] = None
    purpose: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    endpoint_id: Optional[str] = None
    is_active: bool = Field(default=True)
    natural_language: Optional[str] = Field(
        default=None,
        description="Natural language description to parse into conditions",
    )


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    purpose: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    endpoint_id: Optional[str] = None
    is_active: bool
    created_at: datetime


class NLPPolicyParse(BaseModel):
    natural_language: Optional[str] = None
    input: Optional[str] = None  # frontend sends "input" field


class NLPPolicyParseResponse(BaseModel):
    name: str
    description: str
    purpose: str
    parsed: Dict[str, Any]
    confidence: float
    explanation: str
    # Extended fields for intelligent firewall actions
    rule_type: str = Field(
        default="basic",
        description="Rule category: basic, anomaly, attack, rate_limit, isolation, monitor, time_access",
    )
    capabilities_used: List[str] = Field(
        default_factory=list,
        description="List of intelligent capabilities detected in the policy",
    )
