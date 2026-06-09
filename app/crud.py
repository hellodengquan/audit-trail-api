from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, timedelta
import re
import fnmatch

from app.models import AuditEvent, SensitiveRule, EventAction, EventStatus, SeverityLevel
from app.schemas import (
    AuditEventCreate, AuditEventQueryParams,
    SensitiveRuleCreate, SensitiveRuleUpdate, AggregationQueryParams
)


def _match_pattern(text: Optional[str], pattern: Optional[str]) -> bool:
    if not pattern:
        return True
    if not text:
        return False

    if fnmatch.fnmatch(text, pattern):
        return True

    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except re.error:
        pass

    if "|" in pattern:
        parts = pattern.split("|")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            try:
                regex_part = fnmatch.translate(part).replace(r"\Z(?ms)", "").replace(r"\Z", "")
                if re.search(regex_part, text, re.IGNORECASE):
                    return True
            except re.error:
                pass

    return False


def _evaluate_sensitive_rules(
    db: Session, event_data: AuditEventCreate
) -> Tuple[bool, SeverityLevel, Optional[int]]:
    is_sensitive = False
    max_severity = SeverityLevel.LOW
    matched_rule_id: Optional[int] = None

    rules = db.query(SensitiveRule).filter(SensitiveRule.is_active == True).all()

    for rule in rules:
        action_match = _match_pattern(event_data.action.value, rule.action_pattern)
        resource_type_match = _match_pattern(event_data.resource_type, rule.resource_type_pattern)
        resource_id_match = _match_pattern(event_data.resource_id, rule.resource_id_pattern)
        actor_match = _match_pattern(event_data.actor_id, rule.actor_pattern) or _match_pattern(event_data.actor_name, rule.actor_pattern)

        if action_match and resource_type_match and resource_id_match and actor_match:
            is_sensitive = True
            severity_order = list(SeverityLevel)
            rule_severity_idx = severity_order.index(rule.min_severity)
            current_max_idx = severity_order.index(max_severity)
            if rule_severity_idx > current_max_idx:
                max_severity = rule.min_severity
            if matched_rule_id is None:
                matched_rule_id = rule.id

    return is_sensitive, max_severity, matched_rule_id


def create_audit_event(db: Session, event_data: AuditEventCreate) -> AuditEvent:
    is_sensitive, severity, matched_rule_id = _evaluate_sensitive_rules(db, event_data)

    db_event = AuditEvent(
        event_id=event_data.event_id,
        timestamp=event_data.timestamp or datetime.utcnow(),
        actor_id=event_data.actor_id,
        actor_name=event_data.actor_name,
        actor_type=event_data.actor_type,
        actor_ip=event_data.actor_ip,
        actor_user_agent=event_data.actor_user_agent,
        action=event_data.action,
        action_detail=event_data.action_detail,
        resource_type=event_data.resource_type,
        resource_id=event_data.resource_id,
        resource_name=event_data.resource_name,
        status=event_data.status,
        error_message=event_data.error_message,
        old_value=event_data.old_value,
        new_value=event_data.new_value,
        event_metadata=event_data.event_metadata,
        is_sensitive=is_sensitive,
        severity=severity,
        matched_rule_id=matched_rule_id,
        service_name=event_data.service_name,
        request_id=event_data.request_id,
    )

    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


def create_audit_events_bulk(db: Session, events_data: List[AuditEventCreate]) -> List[AuditEvent]:
    db_events = []
    for event_data in events_data:
        is_sensitive, severity, matched_rule_id = _evaluate_sensitive_rules(db, event_data)
        db_event = AuditEvent(
            event_id=event_data.event_id,
            timestamp=event_data.timestamp or datetime.utcnow(),
            actor_id=event_data.actor_id,
            actor_name=event_data.actor_name,
            actor_type=event_data.actor_type,
            actor_ip=event_data.actor_ip,
            actor_user_agent=event_data.actor_user_agent,
            action=event_data.action,
            action_detail=event_data.action_detail,
            resource_type=event_data.resource_type,
            resource_id=event_data.resource_id,
            resource_name=event_data.resource_name,
            status=event_data.status,
            error_message=event_data.error_message,
            old_value=event_data.old_value,
            new_value=event_data.new_value,
            event_metadata=event_data.event_metadata,
            is_sensitive=is_sensitive,
            severity=severity,
            matched_rule_id=matched_rule_id,
            service_name=event_data.service_name,
            request_id=event_data.request_id,
        )
        db_events.append(db_event)

    db.bulk_save_objects(db_events)
    db.commit()
    return db_events


def get_audit_event_by_id(db: Session, event_id: int) -> Optional[AuditEvent]:
    return db.query(AuditEvent).filter(AuditEvent.id == event_id).first()


def get_audit_event_by_event_id(db: Session, event_id: str) -> Optional[AuditEvent]:
    return db.query(AuditEvent).filter(AuditEvent.event_id == event_id).first()


def query_audit_events(
    db: Session, params: AuditEventQueryParams
) -> Tuple[List[AuditEvent], int, int, int]:
    query = db.query(AuditEvent)
    conditions = []

    if params.start_time:
        conditions.append(AuditEvent.timestamp >= params.start_time)
    if params.end_time:
        conditions.append(AuditEvent.timestamp <= params.end_time)
    if params.actor_id:
        conditions.append(AuditEvent.actor_id == params.actor_id)
    if params.actor_name:
        conditions.append(AuditEvent.actor_name.ilike(f"%{params.actor_name}%"))
    if params.actor_ip:
        conditions.append(AuditEvent.actor_ip == params.actor_ip)
    if params.action:
        conditions.append(AuditEvent.action == params.action)
    if params.status:
        conditions.append(AuditEvent.status == params.status)
    if params.resource_type:
        conditions.append(AuditEvent.resource_type == params.resource_type)
    if params.resource_id:
        conditions.append(AuditEvent.resource_id == params.resource_id)
    if params.is_sensitive is not None:
        conditions.append(AuditEvent.is_sensitive == params.is_sensitive)
    if params.severity:
        conditions.append(AuditEvent.severity == params.severity)
    if params.service_name:
        conditions.append(AuditEvent.service_name == params.service_name)
    if params.request_id:
        conditions.append(AuditEvent.request_id == params.request_id)

    if params.keyword:
        keyword = f"%{params.keyword}%"
        conditions.append(or_(
            AuditEvent.actor_name.ilike(keyword),
            AuditEvent.action_detail.ilike(keyword),
            AuditEvent.resource_name.ilike(keyword),
            AuditEvent.error_message.ilike(keyword),
        ))

    if conditions:
        query = query.filter(and_(*conditions))

    total = query.count()

    total_pages = (total + params.page_size - 1) // params.page_size

    events = (
        query.order_by(AuditEvent.timestamp.desc())
        .offset((params.page - 1) * params.page_size)
        .limit(params.page_size)
        .all()
    )

    return events, total, params.page, total_pages


def query_by_actor(
    db: Session, actor_id: Optional[str] = None, actor_name: Optional[str] = None,
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
    page: int = 1, page_size: int = 20
) -> Tuple[List[AuditEvent], int, int, int]:
    query = db.query(AuditEvent)
    conditions = []

    if actor_id:
        conditions.append(AuditEvent.actor_id == actor_id)
    if actor_name:
        conditions.append(AuditEvent.actor_name.ilike(f"%{actor_name}%"))
    if start_time:
        conditions.append(AuditEvent.timestamp >= start_time)
    if end_time:
        conditions.append(AuditEvent.timestamp <= end_time)

    if conditions:
        query = query.filter(and_(*conditions))

    total = query.count()
    total_pages = (total + page_size - 1) // page_size

    events = (
        query.order_by(AuditEvent.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return events, total, page, total_pages


def query_by_resource(
    db: Session, resource_type: Optional[str] = None, resource_id: Optional[str] = None,
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
    page: int = 1, page_size: int = 20
) -> Tuple[List[AuditEvent], int, int, int]:
    query = db.query(AuditEvent)
    conditions = []

    if resource_type:
        conditions.append(AuditEvent.resource_type == resource_type)
    if resource_id:
        conditions.append(AuditEvent.resource_id == resource_id)
    if start_time:
        conditions.append(AuditEvent.timestamp >= start_time)
    if end_time:
        conditions.append(AuditEvent.timestamp <= end_time)

    if conditions:
        query = query.filter(and_(*conditions))

    total = query.count()
    total_pages = (total + page_size - 1) // page_size

    events = (
        query.order_by(AuditEvent.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return events, total, page, total_pages


def query_sensitive_events(
    db: Session, min_severity: Optional[SeverityLevel] = None,
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
    page: int = 1, page_size: int = 20
) -> Tuple[List[AuditEvent], int, int, int]:
    query = db.query(AuditEvent).filter(AuditEvent.is_sensitive == True)

    if min_severity:
        severity_order = list(SeverityLevel)
        min_idx = severity_order.index(min_severity)
        query = query.filter(AuditEvent.severity.in_(severity_order[min_idx:]))

    if start_time:
        query = query.filter(AuditEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(AuditEvent.timestamp <= end_time)

    total = query.count()
    total_pages = (total + page_size - 1) // page_size

    events = (
        query.order_by(AuditEvent.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return events, total, page, total_pages


def get_statistics(
    db: Session, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
) -> Dict[str, Any]:
    query = db.query(AuditEvent)
    conditions = []

    if start_time:
        conditions.append(AuditEvent.timestamp >= start_time)
    if end_time:
        conditions.append(AuditEvent.timestamp <= end_time)

    if conditions:
        query = query.filter(and_(*conditions))

    total_events = query.count()

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_events = query.filter(AuditEvent.timestamp >= today_start).count()

    sensitive_events = query.filter(AuditEvent.is_sensitive == True).count()
    failed_events = query.filter(AuditEvent.status == EventStatus.FAILURE).count()

    by_action = dict(
        query.with_entities(AuditEvent.action, func.count(AuditEvent.id))
        .group_by(AuditEvent.action).all()
    )
    by_action = {k.value: v for k, v in by_action.items()}

    by_severity = dict(
        query.with_entities(AuditEvent.severity, func.count(AuditEvent.id))
        .group_by(AuditEvent.severity).all()
    )
    by_severity = {k.value: v for k, v in by_severity.items()}

    by_status = dict(
        query.with_entities(AuditEvent.status, func.count(AuditEvent.id))
        .group_by(AuditEvent.status).all()
    )
    by_status = {k.value: v for k, v in by_status.items()}

    by_resource_type = dict(
        query.with_entities(AuditEvent.resource_type, func.count(AuditEvent.id))
        .filter(AuditEvent.resource_type.isnot(None))
        .group_by(AuditEvent.resource_type).limit(20).all()
    )

    trend_start = start_time or (datetime.utcnow() - timedelta(days=7))
    trend_data_raw = (
        db.query(
            func.date(AuditEvent.timestamp).label("day"),
            func.count(AuditEvent.id).label("count")
        )
        .filter(AuditEvent.timestamp >= trend_start)
        .group_by("day")
        .order_by("day")
        .all()
    )
    trend_data = [{"date": str(day), "count": count} for day, count in trend_data_raw]

    return {
        "total_events": total_events,
        "today_events": today_events,
        "sensitive_events": sensitive_events,
        "failed_events": failed_events,
        "by_action": by_action,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_resource_type": by_resource_type,
        "trend_data": trend_data,
    }


def get_aggregation(db: Session, params: AggregationQueryParams) -> List[Dict[str, Any]]:
    query = db.query(AuditEvent)

    if params.start_time:
        query = query.filter(AuditEvent.timestamp >= params.start_time)
    if params.end_time:
        query = query.filter(AuditEvent.timestamp <= params.end_time)

    group_map = {
        "action": AuditEvent.action,
        "severity": AuditEvent.severity,
        "status": AuditEvent.status,
        "resource_type": AuditEvent.resource_type,
        "actor": AuditEvent.actor_id,
    }

    if params.group_by in group_map:
        column = group_map[params.group_by]
        results = (
            query.with_entities(column, func.count(AuditEvent.id).label("count"))
            .filter(column.isnot(None))
            .group_by(column)
            .order_by(func.count(AuditEvent.id).desc())
            .limit(50)
            .all()
        )
        return [{"key": str(k.value if hasattr(k, 'value') else k), "count": count} for k, count in results]

    elif params.group_by == "day":
        results = (
            query.with_entities(
                func.date(AuditEvent.timestamp).label("day"),
                func.count(AuditEvent.id).label("count")
            )
            .group_by("day")
            .order_by("day")
            .limit(90)
            .all()
        )
        return [{"key": str(day), "count": count} for day, count in results]

    elif params.group_by == "hour":
        results = (
            query.with_entities(
                func.strftime("%Y-%m-%d %H:00", AuditEvent.timestamp).label("hour"),
                func.count(AuditEvent.id).label("count")
            )
            .group_by("hour")
            .order_by("hour")
            .limit(72)
            .all()
        )
        return [{"key": hour, "count": count} for hour, count in results]

    return []


def create_sensitive_rule(db: Session, rule_data: SensitiveRuleCreate) -> SensitiveRule:
    db_rule = SensitiveRule(**rule_data.model_dump())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


def get_sensitive_rule(db: Session, rule_id: int) -> Optional[SensitiveRule]:
    return db.query(SensitiveRule).filter(SensitiveRule.id == rule_id).first()


def get_sensitive_rules(
    db: Session, skip: int = 0, limit: int = 100, is_active: Optional[bool] = None
) -> Tuple[List[SensitiveRule], int]:
    query = db.query(SensitiveRule)
    if is_active is not None:
        query = query.filter(SensitiveRule.is_active == is_active)
    total = query.count()
    rules = query.order_by(SensitiveRule.created_at.desc()).offset(skip).limit(limit).all()
    return rules, total


def update_sensitive_rule(
    db: Session, rule_id: int, rule_data: SensitiveRuleUpdate
) -> Optional[SensitiveRule]:
    db_rule = get_sensitive_rule(db, rule_id)
    if not db_rule:
        return None

    update_data = rule_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_rule, key, value)

    db.commit()
    db.refresh(db_rule)
    return db_rule


def delete_sensitive_rule(db: Session, rule_id: int) -> bool:
    db_rule = get_sensitive_rule(db, rule_id)
    if not db_rule:
        return False
    db.delete(db_rule)
    db.commit()
    return True


def get_distinct_actors(db: Session, limit: int = 100) -> List[Dict[str, Any]]:
    results = (
        db.query(AuditEvent.actor_id, AuditEvent.actor_name, func.count(AuditEvent.id).label("count"))
        .filter(AuditEvent.actor_id.isnot(None))
        .group_by(AuditEvent.actor_id, AuditEvent.actor_name)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(limit)
        .all()
    )
    return [
        {"actor_id": aid, "actor_name": aname, "event_count": count}
        for aid, aname, count in results
    ]


def get_distinct_resources(db: Session, limit: int = 100) -> List[Dict[str, Any]]:
    results = (
        db.query(AuditEvent.resource_type, AuditEvent.resource_id, AuditEvent.resource_name, func.count(AuditEvent.id).label("count"))
        .filter(AuditEvent.resource_type.isnot(None))
        .group_by(AuditEvent.resource_type, AuditEvent.resource_id, AuditEvent.resource_name)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(limit)
        .all()
    )
    return [
        {"resource_type": rt, "resource_id": rid, "resource_name": rname, "event_count": count}
        for rt, rid, rname, count in results
    ]
