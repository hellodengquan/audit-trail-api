from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime

from app.database import get_db
from app.auth import get_current_user, require_role
from app.models import User, SeverityLevel
from app.schemas import (
    SensitiveRuleCreate, SensitiveRuleUpdate, SensitiveRuleResponse,
    StatisticsResponse, AggregationQueryParams
)
from app import crud

router = APIRouter(tags=["Management"])


@router.get("/statistics", response_model=StatisticsResponse, summary="统计概览")
def get_statistics(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return crud.get_statistics(db, start_time, end_time)


@router.get("/aggregation", summary="聚合分析")
def get_aggregation(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    group_by: str = Query("action", pattern="^(action|severity|status|resource_type|actor|day|hour)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    params = AggregationQueryParams(
        start_time=start_time, end_time=end_time, group_by=group_by
    )
    return crud.get_aggregation(db, params)


@router.post("/sensitive-rules", response_model=SensitiveRuleResponse, status_code=201, summary="创建敏感规则")
def create_sensitive_rule(
    rule_data: SensitiveRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "manager")),
):
    return crud.create_sensitive_rule(db, rule_data)


@router.get("/sensitive-rules", summary="列出敏感规则")
def list_sensitive_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rules, total = crud.get_sensitive_rules(db, skip, limit, is_active)
    return {
        "items": [SensitiveRuleResponse.model_validate(r) for r in rules],
        "total": total,
        "skip": skip,
        "limit": limit
    }


@router.get("/sensitive-rules/{rule_id}", response_model=SensitiveRuleResponse, summary="获取单个敏感规则")
def get_sensitive_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = crud.get_sensitive_rule(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/sensitive-rules/{rule_id}", response_model=SensitiveRuleResponse, summary="更新敏感规则")
def update_sensitive_rule(
    rule_id: int,
    rule_data: SensitiveRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "manager")),
):
    rule = crud.update_sensitive_rule(db, rule_id, rule_data)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.delete("/sensitive-rules/{rule_id}", status_code=204, summary="删除敏感规则")
def delete_sensitive_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    success = crud.delete_sensitive_rule(db, rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return None
