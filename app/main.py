from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from contextlib import asynccontextmanager
from prometheus_fastapi_instrumentator import Instrumentator, metrics

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import AuditEvent, User, SensitiveRule  # noqa: F401
from app.auth import create_default_admin_user
from app.middleware import RequestLoggingMiddleware
from app.exceptions import register_exception_handlers
from app.routers import auth, audit, admin, export
from app import crud
from app.schemas import SensitiveRuleCreate
from app.models import SeverityLevel
from app import metrics as audit_metrics


def init_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        create_default_admin_user(db)
        _init_default_sensitive_rules(db)
        try:
            audit_metrics.bootstrap_actor_count_from_db(db)
        except Exception:
            pass
    finally:
        db.close()


def _init_default_sensitive_rules(db):
    rules_count = db.query(SensitiveRule).count()
    if rules_count > 0:
        return

    default_rules = [
        SensitiveRuleCreate(
            name="用户数据删除操作",
            description="追踪所有用户数据的删除操作",
            action_pattern="delete",
            resource_type_pattern="user*",
            min_severity=SeverityLevel.HIGH,
            alert_enabled=True,
            alert_channels=["email", "webhook"],
        ),
        SensitiveRuleCreate(
            name="权限变更操作",
            description="追踪所有权限和角色相关的变更",
            action_pattern="update",
            resource_type_pattern="*role*|*permission*|*privilege*",
            min_severity=SeverityLevel.CRITICAL,
            alert_enabled=True,
            alert_channels=["email"],
        ),
        SensitiveRuleCreate(
            name="登录失败追踪",
            description="追踪所有失败的登录尝试",
            action_pattern="login",
            min_severity=SeverityLevel.MEDIUM,
            alert_enabled=False,
        ),
        SensitiveRuleCreate(
            name="批量导出操作",
            description="追踪数据批量导出操作",
            action_pattern="export",
            min_severity=SeverityLevel.HIGH,
            alert_enabled=False,
        ),
        SensitiveRuleCreate(
            name="财务数据操作",
            description="追踪所有财务相关数据的操作",
            resource_type_pattern="*finance*|*payment*|*order*|*transaction*",
            min_severity=SeverityLevel.HIGH,
            alert_enabled=True,
            alert_channels=["webhook"],
        ),
    ]

    for rule in default_rules:
        crud.create_sensitive_rule(db, rule)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "审计日志服务 API\n\n"
            "核心功能：\n"
            "- 事件记录（POST /api/v1/events）\n"
            "- 操作者查询（GET /api/v1/events/actor）\n"
            "- 资源查询（GET /api/v1/events/resource）\n"
            "- 敏感操作追踪（GET /api/v1/events/sensitive）\n\n"
            "默认管理员账号：admin / admin123"
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Process-Time", "X-Request-ID"],
    )

    register_exception_handlers(app)

    api_prefix = settings.API_V1_PREFIX
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(audit.router, prefix=api_prefix)
    app.include_router(admin.router, prefix=api_prefix)
    app.include_router(export.router, prefix=api_prefix)

    @app.get("/health", tags=["Health"])
    async def health_check():
        return {
            "status": "healthy",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
        }

    @app.get("/metrics", tags=["Observability"])
    async def prometheus_metrics():
        return PlainTextResponse(
            audit_metrics.generate_metrics(),
            media_type=audit_metrics.get_metrics_content_type(),
        )

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            "metrics": "/metrics",
            "api_prefix": settings.API_V1_PREFIX,
        }

    Instrumentator(
        should_group_status_codes=False,
        excluded_handlers=["/metrics", "/health", "/openapi.json", "/docs", "/redoc"],
        body_handlers=[],
    ).add(
        metrics.request_size(),
        metrics.response_size(),
        metrics.latency(),
        metrics.requests(),
    ).instrument(app)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info",
    )
