import pytest
from jose import jwt
from datetime import datetime, timedelta
from app.config import settings

API = settings.API_V1_PREFIX


class TestAuthentication:
    """测试 JWT 认证核心路径"""

    def test_login_admin_success(self, client):
        resp = client.post(f"{API}/login", json={
            "username": "admin", "password": "admin123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["token_type"] == "bearer"
        assert "access_token" in data
        token = data["access_token"]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == "admin"
        assert payload["role"] == "admin"
        assert "exp" in payload

    def test_login_all_roles_success(self, client):
        accounts = [
            ("admin", "admin123", "admin"),
            ("manager", "manager123", "manager"),
            ("auditor", "auditor123", "auditor"),
            ("viewer", "viewer123", "viewer"),
        ]
        for username, password, expected_role in accounts:
            resp = client.post(f"{API}/login", json={
                "username": username, "password": password,
            })
            assert resp.status_code == 200, f"Login failed for {username}"
            token = resp.json()["access_token"]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            assert payload["role"] == expected_role

    def test_login_wrong_password_fails(self, client):
        resp = client.post(f"{API}/login", json={
            "username": "admin", "password": "WRONG_PASSWORD",
        })
        assert resp.status_code == 401
        assert "access_token" not in resp.json()

    def test_login_nonexistent_user_fails(self, client):
        resp = client.post(f"{API}/login", json={
            "username": "ghost_user", "password": "whatever123",
        })
        assert resp.status_code == 401

    def test_login_inactive_user_fails(self, client):
        resp = client.post(f"{API}/login", json={
            "username": "inactive", "password": "inactive123",
        })
        assert resp.status_code == 401

    def test_login_validation_errors(self, client):
        resp_no_body = client.post(f"{API}/login", json={})
        assert resp_no_body.status_code == 422

        resp_bad_type = client.post(f"{API}/login", json={
            "username": 12345, "password": True,
        })
        assert resp_bad_type.status_code == 422

    def test_me_endpoint_returns_user_info(self, client, admin_headers):
        resp = client.get(f"{API}/me", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"
        assert "password_hash" not in data
        assert data["is_active"] is True


class TestJWTAuthorization:
    """测试 JWT 鉴权边界路径"""

    def test_missing_token_401(self, client):
        resp = client.get(f"{API}/events")
        assert resp.status_code == 401
        assert resp.json()["error"]["message"] == "Not authenticated"

    def test_invalid_token_format_401(self, client):
        resp = client.get(f"{API}/events", headers={"Authorization": "Bearer not-a-valid-jwt"})
        assert resp.status_code == 401
        assert resp.json()["error"]["message"] == "Invalid token"

    def test_expired_token_401(self, client):
        expired_payload = {
            "sub": "admin",
            "role": "admin",
            "exp": datetime.utcnow() - timedelta(hours=1),
        }
        expired_token = jwt.encode(expired_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        resp = client.get(f"{API}/events", headers={"Authorization": f"Bearer {expired_token}"})
        assert resp.status_code == 401

    def test_token_with_nonexistent_user_401(self, client):
        fake_payload = {
            "sub": "deleted_user_xyz",
            "role": "admin",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        fake_token = jwt.encode(fake_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        resp = client.get(f"{API}/me", headers={"Authorization": f"Bearer {fake_token}"})
        assert resp.status_code == 401

    def test_token_with_wrong_secret_401(self, client):
        payload = {
            "sub": "admin",
            "role": "admin",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        wrong_token = jwt.encode(payload, "WRONG_SECRET_123", algorithm=settings.ALGORITHM)
        resp = client.get(f"{API}/me", headers={"Authorization": f"Bearer {wrong_token}"})
        assert resp.status_code == 401

    def test_authorization_prefix_required(self, client):
        resp = client.post(f"{API}/login", json={
            "username": "admin", "password": "admin123",
        })
        token = resp.json()["access_token"]
        resp2 = client.get(f"{API}/events", headers={"Authorization": token})
        assert resp2.status_code == 401


class TestRoleBasedAccessControl:
    """测试基于角色的权限分支（RBAC）"""

    def _post_rule_payload(self):
        return {
            "name": "测试规则",
            "action_pattern": "create",
            "min_severity": "medium",
        }

    def test_event_create_no_auth_needed(self, client):
        resp = client.post(f"{API}/events", json={
            "actor_id": "anonymous", "action": "read",
        })
        assert resp.status_code == 201

    def test_event_query_requires_auth(self, client):
        resp = client.get(f"{API}/events")
        assert resp.status_code == 401

    def test_viewer_can_query(self, client, viewer_headers):
        resp = client.get(f"{API}/events", headers=viewer_headers)
        assert resp.status_code == 200
        resp2 = client.get(f"{API}/events/actor", params={"actor_id": "x"}, headers=viewer_headers)
        assert resp2.status_code == 200
        resp3 = client.get(f"{API}/events/sensitive", headers=viewer_headers)
        assert resp3.status_code == 200

    def test_viewer_can_access_statistics(self, client, viewer_headers):
        resp = client.get(f"{API}/statistics", headers=viewer_headers)
        assert resp.status_code == 200

    def test_viewer_can_list_rules(self, client, viewer_headers):
        resp = client.get(f"{API}/sensitive-rules", headers=viewer_headers)
        assert resp.status_code == 200

    def test_viewer_cannot_create_rule_403(self, client, viewer_headers):
        resp = client.post(f"{API}/sensitive-rules", json=self._post_rule_payload(), headers=viewer_headers)
        assert resp.status_code == 403
        assert resp.json()["error"]["message"] == "Insufficient permissions"

    def test_viewer_cannot_update_rule_403(self, client, viewer_headers):
        resp = client.put(f"{API}/sensitive-rules/1", json={"name": "x"}, headers=viewer_headers)
        assert resp.status_code == 403

    def test_viewer_cannot_delete_rule_403(self, client, viewer_headers):
        resp = client.delete(f"{API}/sensitive-rules/1", headers=viewer_headers)
        assert resp.status_code == 403

    def test_viewer_cannot_export_403(self, client, viewer_headers):
        resp = client.get(f"{API}/export/csv", headers=viewer_headers)
        assert resp.status_code == 403
        resp2 = client.get(f"{API}/export/json", headers=viewer_headers)
        assert resp2.status_code == 403

    def test_auditor_can_export(self, client, auditor_headers):
        resp_csv = client.get(f"{API}/export/csv", headers=auditor_headers)
        assert resp_csv.status_code == 200
        resp_json = client.get(f"{API}/export/json", headers=auditor_headers)
        assert resp_json.status_code == 200

    def test_auditor_cannot_create_rule_403(self, client, auditor_headers):
        resp = client.post(f"{API}/sensitive-rules", json=self._post_rule_payload(), headers=auditor_headers)
        assert resp.status_code == 403

    def test_manager_can_create_rule(self, client, manager_headers):
        resp = client.post(f"{API}/sensitive-rules", json=self._post_rule_payload(), headers=manager_headers)
        assert resp.status_code == 201

    def test_manager_can_update_rule(self, client, manager_headers):
        resp = client.put(
            f"{API}/sensitive-rules/1",
            json={"name": "更新后的名称", "is_active": False},
            headers=manager_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "更新后的名称"
        assert data["is_active"] is False

    def test_manager_cannot_delete_rule_403(self, client, manager_headers):
        resp = client.delete(f"{API}/sensitive-rules/5", headers=manager_headers)
        assert resp.status_code == 403

    def test_admin_full_access(self, client, admin_headers):
        create_resp = client.post(
            f"{API}/sensitive-rules",
            json={"name": "ADMIN-创建", "min_severity": "low"},
            headers=admin_headers,
        )
        assert create_resp.status_code == 201
        rule_id = create_resp.json()["id"]

        update_resp = client.put(
            f"{API}/sensitive-rules/{rule_id}",
            json={"description": "ADMIN更新"},
            headers=admin_headers,
        )
        assert update_resp.status_code == 200

        delete_resp = client.delete(f"{API}/sensitive-rules/{rule_id}", headers=admin_headers)
        assert delete_resp.status_code == 204

    def test_role_permission_matrix_summary(self, client):
        accounts = [
            ("admin", "admin123"),
            ("manager", "manager123"),
            ("auditor", "auditor123"),
            ("viewer", "viewer123"),
        ]
        login_tokens = {}
        for u, p in accounts:
            r = client.post(f"{API}/login", json={"username": u, "password": p})
            login_tokens[u] = r.json()["access_token"]

        matrix = {
            "create_rule": {"admin": 201, "manager": 201, "auditor": 403, "viewer": 403},
            "update_rule": {"admin": 200, "manager": 200, "auditor": 403, "viewer": 403},
            "delete_rule": {"admin": 204, "manager": 403, "auditor": 403, "viewer": 403},
            "export_csv": {"admin": 200, "manager": 200, "auditor": 200, "viewer": 403},
            "query_events": {"admin": 200, "manager": 200, "auditor": 200, "viewer": 200},
        }

        for action, expected in matrix.items():
            if action == "create_rule":
                for role in ["admin", "manager", "auditor", "viewer"]:
                    token = login_tokens[role]
                    resp = client.post(
                        f"{API}/sensitive-rules",
                        json={"name": f"test-{action}-{role}", "min_severity": "low"},
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    assert resp.status_code == expected[role], \
                        f"{action}: role={role} expected {expected[role]} got {resp.status_code}"
            elif action == "update_rule":
                for role in ["admin", "manager", "auditor", "viewer"]:
                    token = login_tokens[role]
                    resp = client.put(
                        f"{API}/sensitive-rules/1",
                        json={"name": f"update-{role}"},
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    assert resp.status_code == expected[role], \
                        f"{action}: role={role} expected {expected[role]} got {resp.status_code}"
            elif action == "delete_rule":
                for role in ["admin", "manager", "auditor", "viewer"]:
                    token = login_tokens[role]
                    if role == "admin":
                        create_resp = client.post(
                            f"{API}/sensitive-rules",
                            json={"name": "to-delete", "min_severity": "low"},
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        rule_id = create_resp.json()["id"]
                    else:
                        rule_id = 2
                    resp = client.delete(
                        f"{API}/sensitive-rules/{rule_id}",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    assert resp.status_code == expected[role], \
                        f"{action}: role={role} expected {expected[role]} got {resp.status_code}"
            elif action == "export_csv":
                for role in ["admin", "manager", "auditor", "viewer"]:
                    token = login_tokens[role]
                    resp = client.get(
                        f"{API}/export/csv",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    assert resp.status_code == expected[role], \
                        f"{action}: role={role} expected {expected[role]} got {resp.status_code}"
            elif action == "query_events":
                for role in ["admin", "manager", "auditor", "viewer"]:
                    token = login_tokens[role]
                    resp = client.get(
                        f"{API}/events",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    assert resp.status_code == expected[role], \
                        f"{action}: role={role} expected {expected[role]} got {resp.status_code}"


class TestSensitiveRuleManagement:
    """测试敏感规则管理 CRUD 分支"""

    def test_create_rule_success(self, client, admin_headers):
        payload = {
            "name": "完整规则测试",
            "description": "完整描述",
            "is_active": True,
            "action_pattern": "update|delete",
            "resource_type_pattern": "user*",
            "resource_id_pattern": "vip_*",
            "actor_pattern": "external_*",
            "min_severity": "critical",
            "alert_enabled": True,
            "alert_channels": ["email", "webhook", "sms"],
        }
        resp = client.post(f"{API}/sensitive-rules", json=payload, headers=admin_headers)
        assert resp.status_code == 201
        d = resp.json()
        assert d["name"] == "完整规则测试"
        assert d["action_pattern"] == "update|delete"
        assert d["alert_enabled"] is True
        assert len(d["alert_channels"]) == 3

    def test_list_rules_with_filters(self, client, admin_headers):
        resp = client.get(f"{API}/sensitive-rules", params={
            "is_active": True, "limit": 3,
        }, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 5
        assert len(data["items"]) == 3
        assert all(r["is_active"] for r in data["items"])

    def test_get_rule_detail(self, client, admin_headers):
        resp = client.get(f"{API}/sensitive-rules/1", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert "name" in data

    def test_get_rule_not_found(self, client, admin_headers):
        resp = client.get(f"{API}/sensitive-rules/99999", headers=admin_headers)
        assert resp.status_code == 404

    def test_update_rule_partial(self, client, admin_headers):
        resp = client.put(
            f"{API}/sensitive-rules/1",
            json={"description": "只有描述被更新"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["description"] == "只有描述被更新"
        assert data["name"] is not None
        assert data["action_pattern"] is not None

    def test_update_rule_not_found(self, client, admin_headers):
        resp = client.put(
            f"{API}/sensitive-rules/99999",
            json={"name": "no"},
            headers=admin_headers,
        )
        assert resp.status_code == 404

    def test_delete_rule_success(self, client, admin_headers):
        resp = client.delete(f"{API}/sensitive-rules/5", headers=admin_headers)
        assert resp.status_code == 204
        resp2 = client.get(f"{API}/sensitive-rules/5", headers=admin_headers)
        assert resp2.status_code == 404

    def test_delete_rule_not_found(self, client, admin_headers):
        resp = client.delete(f"{API}/sensitive-rules/99999", headers=admin_headers)
        assert resp.status_code == 404
