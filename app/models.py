from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    JSON, ForeignKey, Index, Enum as SQLAlchemyEnum
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum

from app.database import Base


class EventAction(str, enum.Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"
    IMPORT = "import"
    APPROVE = "approve"
    REJECT = "reject"
    OTHER = "other"


class EventStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"
    BLOCKED = "blocked"


class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(200))
    email = Column(String(200))
    role = Column(String(50), default="viewer")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)

    timestamp = Column(DateTime, server_default=func.now(), index=True, nullable=False)

    actor_id = Column(String(100), index=True)
    actor_name = Column(String(200), index=True)
    actor_type = Column(String(50), default="user")
    actor_ip = Column(String(45))
    actor_user_agent = Column(String(500))

    action = Column(SQLAlchemyEnum(EventAction), index=True, nullable=False)
    action_detail = Column(String(500))

    resource_type = Column(String(100), index=True)
    resource_id = Column(String(100), index=True)
    resource_name = Column(String(300))

    status = Column(SQLAlchemyEnum(EventStatus), default=EventStatus.SUCCESS, index=True)
    error_message = Column(Text)

    old_value = Column(JSON)
    new_value = Column(JSON)
    event_metadata = Column(JSON)

    is_sensitive = Column(Boolean, default=False, index=True)
    severity = Column(SQLAlchemyEnum(SeverityLevel), default=SeverityLevel.LOW, index=True)
    matched_rule_id = Column(Integer, ForeignKey("sensitive_rules.id"), nullable=True)

    service_name = Column(String(100), index=True)
    request_id = Column(String(100), index=True)

    created_at = Column(DateTime, server_default=func.now())

    matched_rule = relationship("SensitiveRule", back_populates="events")

    __table_args__ = (
        Index("idx_actor_timestamp", "actor_id", "timestamp"),
        Index("idx_resource_timestamp", "resource_type", "resource_id", "timestamp"),
        Index("idx_sensitive_severity", "is_sensitive", "severity"),
        Index("idx_action_timestamp", "action", "timestamp"),
    )


class SensitiveRule(Base):
    __tablename__ = "sensitive_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True, index=True)

    action_pattern = Column(String(200))
    resource_type_pattern = Column(String(200))
    resource_id_pattern = Column(String(200))
    actor_pattern = Column(String(200))

    min_severity = Column(SQLAlchemyEnum(SeverityLevel), default=SeverityLevel.HIGH)

    alert_enabled = Column(Boolean, default=False)
    alert_channels = Column(JSON)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    events = relationship("AuditEvent", back_populates="matched_rule")
