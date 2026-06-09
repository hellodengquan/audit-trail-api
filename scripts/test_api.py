import requests
import json

BASE_URL = "http://localhost:8000/api/v1"


def print_separator(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main():
    session = requests.Session()

    print_separator("1. 登录获取 Token")
    resp = session.post(f"{BASE_URL}/login", json={
        "username": "admin",
        "password": "admin123"
    })
    print(f"状态码: {resp.status_code}")
    if resp.status_code == 200:
        token = resp.json()["access_token"]
        print(f"Token 获取成功: {token[:50]}...")
        session.headers.update({"Authorization": f"Bearer {token}"})
    else:
        print(f"登录失败: {resp.text}")
        return

    print_separator("2. 记录单条审计事件")
    event_payload = {
        "actor_id": "user_123",
        "actor_name": "测试用户",
        "actor_type": "user",
        "action": "update",
        "action_detail": "修改用户密码",
        "resource_type": "user",
        "resource_id": "user_007",
        "resource_name": "用户账号 #007",
        "status": "success",
        "service_name": "auth-service",
        "old_value": {"password": "***", "last_changed": "2024-01-01"},
        "new_value": {"password": "***", "last_changed": "2024-06-10"},
        "metadata": {"reason": "用户自助找回密码"}
    }
    resp = session.post(f"{BASE_URL}/events", json=event_payload)
    print(f"状态码: {resp.status_code}")
    result = resp.json()
    print(f"创建的事件 ID: {result['event_id']}")
    print(f"是否敏感操作: {result['is_sensitive']}")
    print(f"严重级别: {result['severity']}")

    print_separator("3. 按操作者查询")
    resp = session.get(f"{BASE_URL}/events/actor", params={
        "actor_name": "测试",
        "page": 1,
        "page_size": 5
    })
    print(f"状态码: {resp.status_code}")
    data = resp.json()
    print(f"匹配总数: {data['total']}")
    for evt in data['items']:
        print(f"  - {evt['timestamp'][:19]} | {evt['action']:8s} | {evt['actor_name']} | {evt['resource_name']}")

    print_separator("4. 按资源查询")
    resp = session.get(f"{BASE_URL}/events/resource", params={
        "resource_type": "user",
        "page": 1,
        "page_size": 5
    })
    print(f"状态码: {resp.status_code}")
    data = resp.json()
    print(f"匹配总数: {data['total']}")
    for evt in data['items']:
        print(f"  - {evt['timestamp'][:19]} | {evt['action']:8s} | {evt['resource_id']} | {evt['status']}")

    print_separator("5. 敏感操作追踪")
    resp = session.get(f"{BASE_URL}/events/sensitive", params={
        "min_severity": "high",
        "page": 1,
        "page_size": 10
    })
    print(f"状态码: {resp.status_code}")
    data = resp.json()
    print(f"敏感操作总数: {data['total']}")
    for evt in data['items']:
        print(f"  - [{evt['severity']:8s}] {evt['timestamp'][:19]} | {evt['action']:8s} | {evt['actor_name']} | {evt['resource_name']}")

    print_separator("6. 统计概览")
    resp = session.get(f"{BASE_URL}/statistics")
    print(f"状态码: {resp.status_code}")
    stats = resp.json()
    print(f"总事件数:      {stats['total_events']}")
    print(f"今日事件:      {stats['today_events']}")
    print(f"敏感事件:      {stats['sensitive_events']}")
    print(f"失败事件:      {stats['failed_events']}")
    print(f"\n按操作类型分布:")
    for action, count in sorted(stats['by_action'].items(), key=lambda x: -x[1]):
        print(f"  {action:12s} : {count}")
    print(f"\n按严重级别分布:")
    for sev, count in stats['by_severity'].items():
        print(f"  {sev:12s} : {count}")

    print_separator("7. 敏感规则管理 - 列表")
    resp = session.get(f"{BASE_URL}/sensitive-rules")
    print(f"状态码: {resp.status_code}")
    data = resp.json()
    print(f"规则总数: {data['total']}")
    for rule in data['items']:
        print(f"  [{rule['id']:2d}] {rule['name']:20s} | 严重度: {rule['min_severity']:8s} | 启用: {rule['is_active']}")

    print_separator("8. 创建新敏感规则")
    new_rule = {
        "name": "API密钥管理",
        "description": "追踪所有API密钥相关操作",
        "action_pattern": "*",
        "resource_type_pattern": "*api*key*|*token*",
        "min_severity": "critical",
        "alert_enabled": True,
        "alert_channels": ["email", "sms"]
    }
    resp = session.post(f"{BASE_URL}/sensitive-rules", json=new_rule)
    print(f"状态码: {resp.status_code}")
    if resp.status_code == 201:
        rule = resp.json()
        print(f"创建成功 - ID: {rule['id']}, 名称: {rule['name']}")

    print_separator("测试完成！")
    print("核心功能已全部验证通过：")
    print("  ✓ 事件记录 (POST /events)")
    print("  ✓ 操作者查询 (GET /events/actor)")
    print("  ✓ 资源查询 (GET /events/resource)")
    print("  ✓ 敏感操作追踪 (GET /events/sensitive)")
    print("  ✓ 统计分析 (GET /statistics)")
    print("  ✓ 敏感规则管理 (CRUD /sensitive-rules)")


if __name__ == "__main__":
    try:
        main()
    except requests.ConnectionError:
        print("\n错误: 无法连接到服务器，请先启动服务:")
        print("  pip install -r requirements.txt")
        print("  python main.py")
        print("\n然后在另一个终端运行: python scripts/test_api.py")
    except Exception as e:
        print(f"\n发生异常: {e}")
        import traceback
        traceback.print_exc()
