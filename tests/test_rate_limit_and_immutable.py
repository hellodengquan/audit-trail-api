import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
import tempfile
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import get_db, Base
from app.auth import create_default_admin_user
from app.config import settings as app_settings
from app.main import create_app
from app import crud
from app.schemas import AuditEventCreate
from app.rate_limiter import reset_rate_limiter_storage
from app.auth import get_password_hash
from app.models import User, SeverityLevel
from app import crud as _crud
from app.schemas import SensitiveRuleCreate


API = app_settings.API_V1_PREFIX


# ---------------------------------------------------------------------------
# Fixtures: rate-limit tests share the in-memory DB with all other tests
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    reset_rate_limiter_storage()
    yield
    reset_rate_limiter_storage()


def _make_memory_engine():
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _seed_memory(db):
    users = [
        User(username="admin", password_hash=get_password_hash("admin123"),
             full_name="Test Admin", role="admin", is_active=True),
        User(username="viewer", password_hash=get_password_hash("viewer123"),
             full_name="Test Viewer", role="viewer", is_active=True),
    ]
    db.add_all(users)
    for rule in [
        SensitiveRuleCreate(name="R1", action_pattern="delete", min_severity=SeverityLevel.HIGH),
        SensitiveRuleCreate(name="R2", action_pattern="login", min_severity=SeverityLevel.MEDIUM),
    ]:
        _crud.create_sensitive_rule(db, rule)
    db.commit()


@pytest.fixture(scope="function")
def rl_client():
    engine = _make_memory_engine()
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()
    try:
        _seed_memory(session)
    finally:
        session.close()

    def override_get_db():
        sess = Session()
        try:
            yield sess
        finally:
            sess.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    Session.close_all()
    engine.dispose()


@pytest.fixture
def rl_admin_token(rl_client):
    resp = rl_client.post(f"{API}/login", json={"username": "admin", "password": "admin123"})
    return resp.json()["access_token"]


@pytest.fixture
def rl_headers(rl_admin_token):
    return {"Authorization": f"Bearer {rl_admin_token}"}


# ---------------------------------------------------------------------------
# Rate limit tests
# ---------------------------------------------------------------------------
class TestRateLimitByIP:
    """基于 IP 维度的速率限制"""

    def test_ip_default_60_per_minute_under_limit(self, rl_client, rl_headers):
        """未达到阈值时所有请求正常"""
        for _ in range(5):
            resp = rl_client.post(
                f"{API}/events",
                json={"actor_id": "u_x", "action": "read"},
                headers=rl_headers,
            )
            assert resp.status_code == 201, resp.text

    def test_ip_exceeds_60_per_minute_returns_429(self, rl_client, rl_headers, monkeypatch):
        """超过阈值触发 429"""
        monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", True)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_IP", 3)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR", 999999)
        reset_rate_limiter_storage()

        for i in range(3):
            resp = rl_client.post(
                f"{API}/events",
                json={"actor_id": f"u_{i}", "action": "read"},
                headers=rl_headers,
            )
            assert resp.status_code == 201, f"request {i}: {resp.text}"

        # 第 4 条 -> 429
        resp = rl_client.post(
            f"{API}/events",
            json={"actor_id": "u_last", "action": "read"},
            headers=rl_headers,
        )
        assert resp.status_code == 429
        body = resp.json()
        assert body["error"]["type"] == "http_error"
        assert body["error"]["code"] == 429
        detail = body["error"]["message"]
        assert "rate_limit" in detail["type"]
        assert detail["scope"] == "ip"

    def test_disabled_rate_limit_bypasses(self, rl_client, rl_headers, monkeypatch):
        """关闭限速时不触发 429"""
        monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", False)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_IP", 1)
        reset_rate_limiter_storage()

        for _ in range(10):
            resp = rl_client.post(
                f"{API}/events",
                json={"actor_id": "u", "action": "read"},
                headers=rl_headers,
            )
            assert resp.status_code == 201, resp.text


class TestRateLimitByActor:
    """基于 actor_id 维度的速率限制"""

    def test_actor_exceeds_limit_returns_429(self, rl_client, rl_headers, monkeypatch):
        """actor_id 维度达到阈值返回 429"""
        monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", True)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_IP", 999999)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR", 2)
        reset_rate_limiter_storage()

        for i in range(2):
            resp = rl_client.post(
                f"{API}/events",
                json={"actor_id": "same_actor", "action": "read"},
                headers=rl_headers,
            )
            assert resp.status_code == 201

        resp = rl_client.post(
            f"{API}/events",
            json={"actor_id": "same_actor", "action": "read"},
            headers=rl_headers,
        )
        assert resp.status_code == 429
        detail = resp.json()["error"]["message"]
        assert detail["scope"] == "actor_id"
        assert "same_actor" in detail["message"]

    def test_different_actors_not_affected(self, rl_client, rl_headers, monkeypatch):
        """不同 actor 之间互不影响"""
        monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", True)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_IP", 999999)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR", 1)
        reset_rate_limiter_storage()

        # 每个 actor 发 1 条都应该成功
        for aid in ["a1", "a2", "a3", "a4", "a5"]:
            resp = rl_client.post(
                f"{API}/events",
                json={"actor_id": aid, "action": "read"},
                headers=rl_headers,
            )
            assert resp.status_code == 201, f"actor={aid} failed: {resp.text}"


class TestRateLimitBulk:
    """批量写入接口的限速"""

    def test_bulk_consumes_list_length_cost(self, rl_client, rl_headers, monkeypatch):
        monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", True)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_IP", 5)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR", 999999)
        reset_rate_limiter_storage()

        # 一条 bulk 含 3 条事件 => 消耗 3 额度
        resp = rl_client.post(
            f"{API}/events/bulk",
            json=[{"actor_id": f"b{i}", "action": "read"} for i in range(3)],
            headers=rl_headers,
        )
        assert resp.status_code == 201, resp.text

        # 再发 3 条单独事件 => 3 + 3 = 6 > 5 => 429
        for i in range(2):
            resp = rl_client.post(
                f"{API}/events",
                json={"actor_id": f"a{i}", "action": "read"},
                headers=rl_headers,
            )
            assert resp.status_code == 201

        resp = rl_client.post(
            f"{API}/events",
            json={"actor_id": "a_last", "action": "read"},
            headers=rl_headers,
        )
        assert resp.status_code == 429

    def test_bulk_missing_actor_uses_ip_only(self, rl_client, rl_headers, monkeypatch):
        """bulk 事件列表为空也应成功，不走 actor 检查"""
        monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", True)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_IP", 9999)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR", 9999)
        reset_rate_limiter_storage()

        resp = rl_client.post(f"{API}/events/bulk", json=[], headers=rl_headers)
        assert resp.status_code == 201, resp.text


class TestRateLimitQuery:
    """查询接口不受限制"""

    def test_query_no_rate_limit(self, rl_client, rl_headers, monkeypatch):
        """查询接口不受限速影响"""
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_IP", 1)
        monkeypatch.setattr(app_settings, "RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR", 1)
        reset_rate_limiter_storage()

        for _ in range(10):
            resp = rl_client.get(f"{API}/events", headers=rl_headers)
            assert resp.status_code == 200

        for _ in range(10):
            resp = rl_client.get(f"{API}/statistics", headers=rl_headers)
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Immutable trigger tests
#   SQLite 触发器只对同一 DB 连接生效。这里使用持久化文件 SQLite
#   并通过 alembic 执行完整 upgrade 头。
# ---------------------------------------------------------------------------
@pytest.fixture(scope="function")
def immutable_client_and_db():
    import alembic.config
    import alembic.command

    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test_immutable.db")
        db_url = f"sqlite:///{db_path}"
        os.environ["DATABASE_URL"] = db_url

        alembic_cfg = alembic.config.Config(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "alembic.ini",
            )
        )
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)
        alembic.command.upgrade(alembic_cfg, "head")

        engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        session = Session()
        try:
            _seed_memory(session)
            session.commit()
        finally:
            session.close()

        def override_get_db():
            sess = Session()
            try:
                yield sess
            finally:
                sess.close()

        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as client:
            yield client, engine, Session
        try:
            del os.environ["DATABASE_URL"]
        except KeyError:
            pass
        Session.close_all()
        engine.dispose()


@pytest.fixture
def imm_token(immutable_client_and_db):
    client, _, _ = immutable_client_and_db
    resp = client.post(f"{API}/login", json={"username": "admin", "password": "admin123"})
    return resp.json()["access_token"]


@pytest.fixture
def imm_headers(imm_token):
    return {"Authorization": f"Bearer {imm_token}"}


class TestImmutableAuditTable:
    """DB 触发器拦截 UPDATE/DELETE"""

    def test_insert_still_works(self, immutable_client_and_db, imm_headers):
        """触发器不应影响正常 INSERT"""
        client, _, _ = immutable_client_and_db
        resp = client.post(
            f"{API}/events",
            json={"actor_id": "u_trig", "action": "read",
                  "resource_type": "doc", "resource_id": "d1"},
            headers=imm_headers,
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["id"] is not None

    def test_direct_sql_update_blocked(self, immutable_client_and_db):
        """直接执行 SQL UPDATE 被触发器拦截"""
        _, engine, Session = immutable_client_and_db
        # 先手动插入 1 条
        with engine.connect() as conn:
            conn.execute(text(
                """INSERT INTO audit_events
                (event_id, timestamp, actor_id, actor_name, actor_type,
                 action, resource_type, resource_id, resource_name,
                 status, is_sensitive, severity)
                VALUES ('evt_test_imm', CURRENT_TIMESTAMP,
                        'u_sql', 'SQL', 'user', 'read', 'doc', 'd1', 'D1',
                        'success', 0, 'low')"""
            ))
            conn.commit()

        with engine.connect() as conn:
            with pytest.raises(Exception) as exc_info:
                conn.execute(text(
                    "UPDATE audit_events SET resource_name = 'HACKED' WHERE event_id = 'evt_test_imm'"
                ))
                conn.commit()
        msg = str(exc_info.value).lower()
        assert "immutable" in msg or "forbidden" in msg or "abort" in msg

    def test_direct_sql_delete_blocked(self, immutable_client_and_db):
        """直接执行 SQL DELETE 被触发器拦截"""
        _, engine, Session = immutable_client_and_db
        with engine.connect() as conn:
            conn.execute(text(
                """INSERT INTO audit_events
                (event_id, timestamp, actor_id, actor_name, actor_type,
                 action, resource_type, resource_id, resource_name,
                 status, is_sensitive, severity)
                VALUES ('evt_test_imm2', CURRENT_TIMESTAMP,
                        'u_sql2', 'SQL2', 'user', 'read', 'doc', 'd2', 'D2',
                        'success', 0, 'low')"""
            ))
            conn.commit()

        with engine.connect() as conn:
            with pytest.raises(Exception) as exc_info:
                conn.execute(text(
                    "DELETE FROM audit_events WHERE event_id = 'evt_test_imm2'"
                ))
                conn.commit()
        msg = str(exc_info.value).lower()
        assert "immutable" in msg or "forbidden" in msg or "abort" in msg

    def test_triggers_registered_in_sqlite_master(self, immutable_client_and_db):
        """检查触发器确实存在于 sqlite_master"""
        _, engine, _ = immutable_client_and_db
        with engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT name, type FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'"
            )).fetchall()
        names = {r[0] for r in rows}
        assert "trg_audit_events_no_update" in names
        assert "trg_audit_events_no_delete" in names
        assert len(names) == 2

    def test_bulk_insert_still_works(self, immutable_client_and_db, imm_headers):
        """批量接口依然可以 INSERT"""
        client, _, _ = immutable_client_and_db
        resp = client.post(
            f"{API}/events/bulk",
            json=[
                {"actor_id": f"bulk_{i}", "action": "create"}
                for i in range(5)
            ],
            headers=imm_headers,
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["created"] == 5

    def test_query_after_insert_works(self, immutable_client_and_db, imm_headers):
        """插入后可以正常查询"""
        client, _, _ = immutable_client_and_db
        client.post(
            f"{API}/events",
            json={"actor_id": "query_after", "action": "login", "status": "failure"},
            headers=imm_headers,
        )
        resp = client.get(
            f"{API}/events/actor",
            params={"actor_id": "query_after"},
            headers=imm_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(x["actor_id"] == "query_after" for x in data["items"])
