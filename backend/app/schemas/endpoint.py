from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing import Optional, List
from datetime import datetime


class AppCreate(BaseModel):
    name: str = Field(..., description="Application name")
    process_name: Optional[str] = Field(default=None, description="Process name (auto-generated from app name if omitted)")
    status: str = Field(default="running", description="Application status")

    @model_validator(mode="after")
    def set_process_name(self):
        if not self.process_name:
            self.process_name = self.name.lower().replace(" ", "_")
        return self


class AppResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    process_name: str
    status: str
    endpoint_id: str
    created_at: datetime


class EndpointCreate(BaseModel):
    name: str = Field(..., description="Endpoint name")
    ip_address: str = Field(..., description="IP address")
    status: str = Field(default="active", description="Endpoint status")


class PolicyBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    purpose: Optional[str] = None
    is_active: bool


class AlertBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    severity: str
    category: Optional[str] = None
    attack_type: Optional[str] = None
    message: str
    confidence: Optional[float] = None
    app_name: Optional[str] = None
    timestamp: datetime


class EndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    ip_address: str
    status: str
    created_at: datetime
    applications: List[AppResponse] = []
    policies: List[PolicyBrief] = []
    recent_alerts: List[AlertBrief] = []
    traffic_logs: int = 0


class EndpointListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    ip_address: str
    status: str
    created_at: datetime
    applications: List[AppResponse] = []
    traffic_logs: int = 0

