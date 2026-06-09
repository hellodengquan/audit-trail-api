from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime

from app.database import get_db
from app.auth import get_current_user, get_client_ip
from app.models import SeverityLevel, EventAction, EventStatus, User
from app.schemas import (
    AuditEventCreate, AuditEventResponse, AuditEventListResponse,
    AuditEventQueryParams
)
from app import crud
from app.rate_limiter import enforce_events_rate_limit

router = APIRouter(prefix="/events", tags=["Audit Events"])


@router.post("", response_model=AuditEventResponse, status_code=status.HTTP_201_CREATED)
async def create_event(
    event_data: AuditEventCreate,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_events_rate_limit),
):
    if event_data.actor_ip is None:
        event_data.actor_ip = get_client_ip(request)
    if event_data.actor_user_agent is None:
        event_data.actor_user_agent = request.headers.get("User-Agent")

    event = crud.create_audit_event(db, event_data)
    return event


@router.post("/bulk", status_code=status.HTTP_201_CREATED)
async def create_events_bulk(
    events_data: List[AuditEventCreate],
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_events_rate_limit),
):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    for event in events_data:
        if event.actor_ip is None:
            event.actor_ip = client_ip
        if event.actor_user_agent is None:
            event.actor_user_agent = user_agent

    events = crud.create_audit_events_bulk(db, events_data)
    return {"created": len(events), "ids": [e.event_id for e in events]}


@router.get("", response_model=AuditEventListResponse)
def list_events(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    actor_id: Optional[str] = None,
    actor_name: Optional[str] = None,
    actor_ip: Optional[str] = None,
    action: Optional[EventAction] = None,
    status_enum: Optional[EventStatus] = Query(None, alias="status"),
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    is_sensitive: Optional[bool] = None,
    severity: Optional[SeverityLevel] = None,
    service_name: Optional[str] = None,
    request_id: Optional[str] = None,
    keyword: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    params = AuditEventQueryParams(
        start_time=start_time, end_time=end_time,
        actor_id=actor_id, actor_name=actor_name, actor_ip=actor_ip,
        action=action, status=status_enum,
        resource_type=resource_type, resource_id=resource_id,
        is_sensitive=is_sensitive, severity=severity,
        service_name=service_name, request_id=request_id,
        keyword=keyword, page=page, page_size=page_size
    )
    events, total, current_page, total_pages = crud.query_audit_events(db, params)
    return AuditEventListResponse(
        items=events, total=total, page=current_page,
        page_size=page_size, total_pages=total_pages
    )


@router.get("/id/{event_id}", response_model=AuditEventResponse)
def get_event_by_id(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = crud.get_audit_event_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/event-id/{event_uuid}", response_model=AuditEventResponse)
def get_event_by_uuid(
    event_uuid: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = crud.get_audit_event_by_event_id(db, event_uuid)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/actor", response_model=AuditEventListResponse, summary="按操作者查询")
def query_by_actor(
    actor_id: Optional[str] = None,
    actor_name: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not actor_id and not actor_name:
        raise HTTPException(
            status_code=400,
            detail="Either actor_id or actor_name must be provided"
        )
    events, total, current_page, total_pages = crud.query_by_actor(
        db, actor_id, actor_name, start_time, end_time, page, page_size
    )
    return AuditEventListResponse(
        items=events, total=total, page=current_page,
        page_size=page_size, total_pages=total_pages
    )


@router.get("/resource", response_model=AuditEventListResponse, summary="按资源查询")
def query_by_resource(
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not resource_type and not resource_id:
        raise HTTPException(
            status_code=400,
            detail="Either resource_type or resource_id must be provided"
        )
    events, total, current_page, total_pages = crud.query_by_resource(
        db, resource_type, resource_id, start_time, end_time, page, page_size
    )
    return AuditEventListResponse(
        items=events, total=total, page=current_page,
        page_size=page_size, total_pages=total_pages
    )


@router.get("/sensitive", response_model=AuditEventListResponse, summary="敏感操作追踪")
def query_sensitive_events(
    min_severity: Optional[SeverityLevel] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    events, total, current_page, total_pages = crud.query_sensitive_events(
        db, min_severity, start_time, end_time, page, page_size
    )
    return AuditEventListResponse(
        items=events, total=total, page=current_page,
        page_size=page_size, total_pages=total_pages
    )


@router.get("/actors", summary="获取所有操作者列表")
def list_actors(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return crud.get_distinct_actors(db, limit)


@router.get("/resources", summary="获取所有资源列表")
def list_resources(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return crud.get_distinct_resources(db, limit)
