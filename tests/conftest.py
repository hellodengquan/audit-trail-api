import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, get_db
from app.config import settings
from app.main import create_app
from app.auth import get_password_hash
from app.models import User
from app import crud
from app.schemas import SensitiveRuleCreate
from app.models import SeverityLevel

TEST_DATABASE_URL = "sqlite://"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session")
def db_engine():
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    try:
        _seed_initial_data(session)
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


def _seed_initial_data(db):
    admin = User(
        username="admin",
        password_hash=get_password_hash("admin123"),
        full_name="Test Admin",
        email="admin@test.com",
        role="admin",
        is_active=True,
    )
    manager = User(
        username="manager",
        password_hash=get_password_hash("manager123"),
        full_name="Test Manager",
        email="manager@test.com",
        role="manager",
        is_active=True,
    )
    auditor = User(
        username="auditor",
        password_hash=get_password_hash("auditor123"),
        full_name="Test Auditor",
        email="auditor@test.com",
        role="auditor",
        is_active=True,
    )
    viewer = User(
        username="viewer",
        password_hash=get_password_hash("viewer123"),
        full_name="Test Viewer",
        email="viewer@test.com",
        role="viewer",
        is_active=True,
    )
    inactive = User(
        username="inactive",
        password_hash=get_password_hash("inactive123"),
        full_name="Inactive User",
        email="inactive@test.com",
        role="viewer",
        is_active=False,
    )
    db.add_all([admin, manager, auditor, viewer, inactive])

    default_rules = [
        SensitiveRuleCreate(
            name="测试-用户删除",
            description="所有用户删除操作",
            action_pattern="delete",
            resource_type_pattern="user*",
            min_severity=SeverityLevel.HIGH,
            alert_enabled=True,
            alert_channels=["email"],
        ),
        SensitiveRuleCreate(
            name="测试-权限变更",
            description="权限角色相关操作",
            action_pattern="update",
            resource_type_pattern="*role*|*permission*",
            min_severity=SeverityLevel.CRITICAL,
        ),
        SensitiveRuleCreate(
            name="测试-登录失败",
            description="登录失败",
            action_pattern="login",
            min_severity=SeverityLevel.MEDIUM,
        ),
        SensitiveRuleCreate(
            name="测试-导出",
            description="数据导出",
            action_pattern="export",
            min_severity=SeverityLevel.HIGH,
        ),
        SensitiveRuleCreate(
            name="测试-财务",
            description="财务相关操作",
            resource_type_pattern="*finance*|*payment*|*order*|*transaction*",
            min_severity=SeverityLevel.HIGH,
        ),
    ]
    for r in default_rules:
        crud.create_sensitive_rule(db, r)

    db.commit()


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="function")
def auth_headers(client):
    def _login(username: str = "admin", password: str = "admin123"):
        resp = client.post(
            f"{settings.API_V1_PREFIX}/login",
            json={"username": username, "password": password},
        )
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _login


@pytest.fixture(scope="function")
def admin_headers(auth_headers):
    return auth_headers("admin", "admin123")


@pytest.fixture(scope="function")
def manager_headers(auth_headers):
    return auth_headers("manager", "manager123")


@pytest.fixture(scope="function")
def auditor_headers(auth_headers):
    return auth_headers("auditor", "auditor123")


@pytest.fixture(scope="function")
def viewer_headers(auth_headers):
    return auth_headers("viewer", "viewer123")
