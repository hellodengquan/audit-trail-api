from pydantic import BaseModel, Field, ConfigDict, model_serializer, model_validator
from typing import Optional, Any, List, Dict
from datetime import datetime
import uuid

from app.models import EventAction, EventStatus, SeverityLevel


def generate_event_id() -> str:
    return f"evt_{uuid.uuid4().hex[:24]}"


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime


class AuditEventCreate(BaseModel):
    event_id: Optional[str] = Field(default_factory=generate_event_id)
    timestamp: Optional[datetime] = None

    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    actor_type: str = "user"
    actor_ip: Optional[str] = None
    actor_user_agent: Optional[str] = None

    action: EventAction
    action_detail: Optional[str] = None

    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None

    status: EventStatus = EventStatus.SUCCESS
    error_message: Optional[str] = None

    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    event_metadata: Optional[Dict[str, Any]] = Field(default=None, exclude=True)
    metadata: Optional[Dict[str, Any]] = None

    service_name: Optional[str] = None
    request_id: Optional[str] = None

    @model_validator(mode="after")
    def _sync_metadata(self):
        if self.metadata is not None:
            self.event_metadata = self.metadata
        elif self.event_metadata is not None:
            self.metadata = self.event_metadata
        return self


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: str
    timestamp: datetime

    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    actor_type: str
    actor_ip: Optional[str] = None
    actor_user_agent: Optional[str] = None

    action: EventAction
    action_detail: Optional[str] = None

    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None

    status: EventStatus
    error_message: Optional[str] = None

    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    event_metadata: Optional[Dict[str, Any]] = Field(default=None, exclude=True)

    is_sensitive: bool
    severity: SeverityLevel
    matched_rule_id: Optional[int] = None

    service_name: Optional[str] = None
    request_id: Optional[str] = None

    created_at: datetime

    @model_serializer
    def _serialize(self) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "actor_id": self.actor_id,
            "actor_name": self.actor_name,
            "actor_type": self.actor_type,
            "actor_ip": self.actor_ip,
            "actor_user_agent": self.actor_user_agent,
            "action": self.action,
            "action_detail": self.action_detail,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "status": self.status,
            "error_message": self.error_message,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "metadata": self.event_metadata,
            "is_sensitive": self.is_sensitive,
            "severity": self.severity,
            "matched_rule_id": self.matched_rule_id,
            "service_name": self.service_name,
            "request_id": self.request_id,
            "created_at": self.created_at,
        }
        return data


class AuditEventListResponse(BaseModel):
    items: List[AuditEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AuditEventQueryParams(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    actor_ip: Optional[str] = None

    action: Optional[EventAction] = None
    status: Optional[EventStatus] = None

    resource_type: Optional[str] = None
    resource_id: Optional[str] = None

    is_sensitive: Optional[bool] = None
    severity: Optional[SeverityLevel] = None

    service_name: Optional[str] = None
    request_id: Optional[str] = None

    keyword: Optional[str] = None

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class SensitiveRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_active: bool = True

    action_pattern: Optional[str] = None
    resource_type_pattern: Optional[str] = None
    resource_id_pattern: Optional[str] = None
    actor_pattern: Optional[str] = None

    min_severity: SeverityLevel = SeverityLevel.HIGH

    alert_enabled: bool = False
    alert_channels: Optional[List[str]] = None


class SensitiveRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None

    action_pattern: Optional[str] = None
    resource_type_pattern: Optional[str] = None
    resource_id_pattern: Optional[str] = None
    actor_pattern: Optional[str] = None

    min_severity: Optional[SeverityLevel] = None

    alert_enabled: Optional[bool] = None
    alert_channels: Optional[List[str]] = None


class SensitiveRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: Optional[str] = None
    is_active: bool

    action_pattern: Optional[str] = None
    resource_type_pattern: Optional[str] = None
    resource_id_pattern: Optional[str] = None
    actor_pattern: Optional[str] = None

    min_severity: SeverityLevel

    alert_enabled: bool
    alert_channels: Optional[List[str]] = None

    created_at: datetime
    updated_at: datetime


class StatisticsResponse(BaseModel):
    total_events: int = 0
    today_events: int = 0
    sensitive_events: int = 0
    failed_events: int = 0

    by_action: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_resource_type: Dict[str, int] = {}

    trend_data: List[Dict[str, Any]] = []


class AggregationQueryParams(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    group_by: str = Field(default="action", pattern="^(action|severity|status|resource_type|actor|day|hour)$")
