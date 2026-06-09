from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
import json
import csv
import io

from app.database import get_db
from app.auth import get_current_user, require_role
from app.models import User, EventAction, EventStatus, SeverityLevel
from app import crud

router = APIRouter(prefix="/export", tags=["Export"])


@router.get("/csv", summary="导出为CSV")
def export_csv(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    actor_id: Optional[str] = None,
    actor_name: Optional[str] = None,
    action: Optional[EventAction] = None,
    status_enum: Optional[EventStatus] = Query(None, alias="status"),
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    is_sensitive: Optional[bool] = None,
    severity: Optional[SeverityLevel] = None,
    keyword: Optional[str] = None,
    limit: int = Query(10000, ge=1, le=100000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "manager", "auditor")),
):
    events, total = crud.export_audit_events(
        db, start_time=start_time, end_time=end_time,
        actor_id=actor_id, actor_name=actor_name,
        action=action, status=status_enum,
        resource_type=resource_type, resource_id=resource_id,
        is_sensitive=is_sensitive, severity=severity,
        keyword=keyword, limit=limit
    )

    output = io.StringIO()
    writer = csv.writer(output)

    headers = [
        "ID", "Event ID", "Timestamp", "Actor ID", "Actor Name", "Actor IP",
        "Action", "Action Detail", "Resource Type", "Resource ID", "Resource Name",
        "Status", "Sensitive", "Severity", "Service", "Error Message"
    ]
    writer.writerow(headers)

    for e in events:
        writer.writerow([
            e.id, e.event_id, e.timestamp.isoformat(),
            e.actor_id or "", e.actor_name or "", e.actor_ip or "",
            e.action.value, e.action_detail or "",
            e.resource_type or "", e.resource_id or "", e.resource_name or "",
            e.status.value, e.is_sensitive, e.severity.value,
            e.service_name or "", e.error_message or ""
        ])

    output.seek(0)
    filename = f"audit_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/json", summary="导出为JSON")
def export_json(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    actor_id: Optional[str] = None,
    actor_name: Optional[str] = None,
    action: Optional[EventAction] = None,
    status_enum: Optional[EventStatus] = Query(None, alias="status"),
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    is_sensitive: Optional[bool] = None,
    severity: Optional[SeverityLevel] = None,
    keyword: Optional[str] = None,
    limit: int = Query(10000, ge=1, le=100000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "manager", "auditor")),
):
    events, total = crud.export_audit_events(
        db, start_time=start_time, end_time=end_time,
        actor_id=actor_id, actor_name=actor_name,
        action=action, status=status_enum,
        resource_type=resource_type, resource_id=resource_id,
        is_sensitive=is_sensitive, severity=severity,
        keyword=keyword, limit=limit
    )

    def serialize_event(e):
        return {
            "id": e.id,
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "actor_id": e.actor_id,
            "actor_name": e.actor_name,
            "actor_ip": e.actor_ip,
            "actor_user_agent": e.actor_user_agent,
            "action": e.action.value,
            "action_detail": e.action_detail,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "resource_name": e.resource_name,
            "status": e.status.value,
            "error_message": e.error_message,
            "old_value": e.old_value,
            "new_value": e.new_value,
            "metadata": e.event_metadata,
            "is_sensitive": e.is_sensitive,
            "severity": e.severity.value,
            "service_name": e.service_name,
            "request_id": e.request_id
        }

    data = json.dumps(
        {"total": total, "count": len(events), "events": [serialize_event(e) for e in events]},
        ensure_ascii=False, indent=2
    )
    filename = f"audit_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    return StreamingResponse(
        iter([data]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
