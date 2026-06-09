import pytest
from app.config import settings

API = settings.API_V1_PREFIX


class TestCreateAuditEvent:
    """测试审计事件创建核心路径"""

    def test_create_event_basic_success(self, client, admin_headers):
        payload = {
            "actor_id": "user_001",
            "actor_name": "张三",
            "action": "create",
            "resource_type": "document",
            "resource_id": "doc_001",
            "resource_name": "技术方案文档",
            "status": "success",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["event_id"].startswith("evt_")
        assert data["actor_id"] == "user_001"
        assert data["action"] == "create"
        assert data["status"] == "success"
        assert data["is_sensitive"] is False
        assert data["severity"] == "low"

    def test_create_event_with_metadata(self, client, admin_headers):
        payload = {
            "actor_id": "user_002",
            "actor_name": "李四",
            "action": "update",
            "resource_type": "profile",
            "resource_id": "profile_007",
            "status": "success",
            "old_value": {"nickname": "old_name", "age": 28},
            "new_value": {"nickname": "new_name", "age": 29},
            "metadata": {"channel": "mobile_app", "version": "2.3.1"},
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["old_value"]["age"] == 28
        assert data["new_value"]["age"] == 29
        assert data["metadata"]["channel"] == "mobile_app"

    def test_create_event_auto_capture_ip_ua(self, client, admin_headers):
        payload = {
            "actor_id": "user_099",
            "actor_name": "自动捕获测试",
            "action": "read",
        }
        resp = client.post(
            f"{API}/events",
            json=payload,
            headers={
                **admin_headers,
                "User-Agent": "TestAgent/1.0",
                "X-Forwarded-For": "203.0.113.42",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["actor_ip"] == "203.0.113.42"
        assert data["actor_user_agent"] == "TestAgent/1.0"

    def test_create_event_validation_missing_action(self, client, admin_headers):
        payload = {
            "actor_id": "user_x",
            "actor_name": "缺少action",
            "resource_type": "x",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 422

    def test_create_event_invalid_enum(self, client, admin_headers):
        payload = {
            "actor_id": "user_x",
            "action": "INVALID_ACTION",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 422

    def test_create_event_bulk(self, client, admin_headers):
        events = [
            {"actor_id": f"user_{i:03d}", "actor_name": f"批量用户{i}", "action": "read"}
            for i in range(50)
        ]
        resp = client.post(f"{API}/events/bulk", json=events, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["created"] == 50
        assert len(data["ids"]) == 50


class TestSensitiveOperationGrading:
    """测试敏感操作自动分级断言"""

    def test_user_delete_triggers_high(self, client, admin_headers):
        payload = {
            "actor_id": "admin_01",
            "actor_name": "管理员",
            "action": "delete",
            "resource_type": "user_account",
            "resource_id": "user_999",
            "resource_name": "要删除的用户",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["is_sensitive"] is True
        assert data["severity"] == "high"

    def test_role_update_triggers_critical(self, client, admin_headers):
        payload = {
            "actor_id": "super_admin",
            "actor_name": "超级管理员",
            "action": "update",
            "resource_type": "user_role",
            "resource_id": "role_admin",
            "resource_name": "管理员角色权限",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["is_sensitive"] is True
        assert data["severity"] == "critical"

    def test_finance_resource_triggers_high(self, client, admin_headers):
        payload = {
            "actor_id": "finance_user",
            "actor_name": "财务人员",
            "action": "create",
            "resource_type": "finance_payment",
            "resource_id": "pay_8888",
            "resource_name": "大额支付单",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["is_sensitive"] is True
        assert data["severity"] == "high"

    def test_export_triggers_high(self, client, admin_headers):
        payload = {
            "actor_id": "analyst_01",
            "actor_name": "分析师",
            "action": "export",
            "resource_type": "report",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["is_sensitive"] is True
        assert data["severity"] == "high"

    def test_normal_read_not_sensitive(self, client, admin_headers):
        payload = {
            "actor_id": "viewer_01",
            "actor_name": "只读用户",
            "action": "read",
            "resource_type": "article",
            "resource_id": "art_123",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["is_sensitive"] is False
        assert data["severity"] == "low"

    def test_multiple_rules_pick_highest_severity(self, client, admin_headers):
        payload = {
            "actor_id": "admin",
            "actor_name": "管理员",
            "action": "delete",
            "resource_type": "finance_transaction",
        }
        resp = client.post(f"{API}/events", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["is_sensitive"] is True
        severity_order = ["low", "medium", "high", "critical"]
        assert severity_order.index(data["severity"]) >= severity_order.index("high")


class TestQueryAuditEvents:
    """测试事件查询路径"""

    @pytest.fixture(autouse=True)
    def _setup_events(self, client, admin_headers):
        self._create_sample_events(client, admin_headers)

    def _create_sample_events(self, client, headers):
        events = [
            {"actor_id": "actor_A", "actor_name": "演员A", "action": "create",
             "resource_type": "order", "resource_id": "o_1", "resource_name": "订单1"},
            {"actor_id": "actor_A", "actor_name": "演员A", "action": "update",
             "resource_type": "order", "resource_id": "o_1", "resource_name": "订单1"},
            {"actor_id": "actor_A", "actor_name": "演员A", "action": "delete",
             "resource_type": "user_account", "resource_id": "u_1", "resource_name": "用户1"},
            {"actor_id": "actor_B", "actor_name": "演员B", "action": "read",
             "resource_type": "document", "resource_id": "d_1", "resource_name": "文档1"},
            {"actor_id": "actor_B", "actor_name": "演员B", "action": "export",
             "resource_type": "report", "resource_id": "r_1", "resource_name": "报表1",
             "status": "failure", "error_message": "网络超时"},
            {"actor_id": "actor_C", "actor_name": "演员C", "action": "update",
             "resource_type": "permission_role", "resource_id": "p_1", "resource_name": "权限1"},
            {"actor_id": "actor_D", "actor_name": "演员D", "action": "login",
             "status": "failure", "error_message": "密码错误"},
        ]
        for e in events:
            client.post(f"{API}/events", json=e, headers=headers)

    def test_query_by_actor_id(self, client, admin_headers):
        resp = client.get(f"{API}/events/actor", params={"actor_id": "actor_A"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert all(e["actor_id"] == "actor_A" for e in data["items"])

    def test_query_by_actor_name_fuzzy(self, client, admin_headers):
        resp = client.get(f"{API}/events/actor", params={"actor_name": "演员"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4

    def test_query_actor_missing_params_fails(self, client, admin_headers):
        resp = client.get(f"{API}/events/actor", headers=admin_headers)
        assert resp.status_code == 400

    def test_query_by_resource_type(self, client, admin_headers):
        resp = client.get(f"{API}/events/resource", params={"resource_type": "order"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert all(e["resource_type"] == "order" for e in data["items"])

    def test_query_sensitive_only(self, client, admin_headers):
        resp = client.get(f"{API}/events/sensitive", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        for e in data["items"]:
            assert e["is_sensitive"] is True
        ids = [e["resource_id"] for e in data["items"]]
        assert "u_1" in ids or "p_1" in ids or "r_1" in ids

    def test_query_sensitive_min_severity_critical(self, client, admin_headers):
        resp = client.get(
            f"{API}/events/sensitive",
            params={"min_severity": "critical"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        for e in data["items"]:
            assert e["severity"] == "critical"

    def test_query_generic_with_filters(self, client, admin_headers):
        resp = client.get(
            f"{API}/events",
            params={"status": "failure", "page_size": 10},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        for e in data["items"]:
            assert e["status"] == "failure"

    def test_query_with_keyword(self, client, admin_headers):
        resp = client.get(
            f"{API}/events",
            params={"keyword": "密码错误"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any("密码错误" in (e["error_message"] or "") for e in data["items"])

    def test_query_pagination(self, client, admin_headers):
        resp = client.get(
            f"{API}/events",
            params={"page": 1, "page_size": 2},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["page"] == 1
        assert data["page_size"] == 2
        assert data["total_pages"] >= 4

    def test_get_event_by_numeric_id(self, client, admin_headers):
        list_resp = client.get(f"{API}/events", params={"page_size": 1}, headers=admin_headers)
        target_id = list_resp.json()["items"][0]["id"]
        resp = client.get(f"{API}/events/id/{target_id}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == target_id

    def test_get_event_by_uuid(self, client, admin_headers):
        list_resp = client.get(f"{API}/events", params={"page_size": 1}, headers=admin_headers)
        target_uuid = list_resp.json()["items"][0]["event_id"]
        resp = client.get(f"{API}/events/event-id/{target_uuid}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["event_id"] == target_uuid

    def test_get_event_not_found(self, client, admin_headers):
        resp = client.get(f"{API}/events/id/9999999", headers=admin_headers)
        assert resp.status_code == 404

    def test_list_actors_and_resources(self, client, admin_headers):
        actors = client.get(f"{API}/events/actors", headers=admin_headers).json()
        assert len(actors) >= 4
        assert any(a["actor_id"] == "actor_A" for a in actors)

        resources = client.get(f"{API}/events/resources", headers=admin_headers).json()
        assert len(resources) >= 4
        assert any(r["resource_type"] == "order" for r in resources)


class TestStatisticsAndAggregation:
    """测试统计聚合路径"""

    @pytest.fixture(autouse=True)
    def _setup(self, client, admin_headers):
        for i in range(5):
            client.post(f"{API}/events", json={
                "actor_id": f"u{i}", "action": "create",
                "resource_type": f"type_{i % 3}", "status": "success",
            }, headers=admin_headers)
        for i in range(3):
            client.post(f"{API}/events", json={
                "actor_id": f"u{i}", "action": "delete",
                "resource_type": "user_account", "status": "failure",
            }, headers=admin_headers)

    def test_statistics_basic(self, client, admin_headers):
        resp = client.get(f"{API}/statistics", headers=admin_headers)
        assert resp.status_code == 200
        s = resp.json()
        assert s["total_events"] >= 8
        assert s["failed_events"] >= 3
        assert s["sensitive_events"] >= 3
        assert s["by_action"]["delete"] >= 3
        assert "high" in s["by_severity"] or "critical" in s["by_severity"]

    def test_aggregation_by_action(self, client, admin_headers):
        resp = client.get(f"{API}/aggregation", params={"group_by": "action"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        actions = {x["key"] for x in data}
        assert "create" in actions and "delete" in actions

    def test_aggregation_by_status(self, client, admin_headers):
        resp = client.get(f"{API}/aggregation", params={"group_by": "status"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        statuses = {x["key"] for x in data}
        assert "success" in statuses and "failure" in statuses

    def test_aggregation_invalid_group_by_fails(self, client, admin_headers):
        resp = client.get(f"{API}/aggregation", params={"group_by": "invalid_key"}, headers=admin_headers)
        assert resp.status_code == 422
