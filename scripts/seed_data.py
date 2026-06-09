import asyncio
import httpx
import random
from datetime import datetime, timedelta

BASE_URL = "http://localhost:8000/api/v1"

ACTIONS = [
    {"action": "create", "detail": "创建新记录"},
    {"action": "read", "detail": "查看记录详情"},
    {"action": "update", "detail": "更新记录信息"},
    {"action": "delete", "detail": "删除记录"},
    {"action": "login", "detail": "用户登录"},
    {"action": "logout", "detail": "用户登出"},
    {"action": "export", "detail": "导出数据"},
    {"action": "import", "detail": "导入数据"},
    {"action": "approve", "detail": "审批通过"},
    {"action": "reject", "detail": "审批拒绝"},
]

RESOURCES = [
    {"type": "user", "name_prefix": "用户"},
    {"type": "order", "name_prefix": "订单"},
    {"type": "product", "name_prefix": "商品"},
    {"type": "role", "name_prefix": "角色"},
    {"type": "permission", "name_prefix": "权限"},
    {"type": "finance_payment", "name_prefix": "支付记录"},
    {"type": "finance_transaction", "name_prefix": "交易记录"},
    {"type": "setting", "name_prefix": "系统设置"},
    {"type": "report", "name_prefix": "报表"},
]

ACTORS = [
    {"id": "user_001", "name": "张三"},
    {"id": "user_002", "name": "李四"},
    {"id": "user_003", "name": "王五"},
    {"id": "user_004", "name": "赵六"},
    {"id": "user_005", "name": "孙七"},
    {"id": "user_006", "name": "周八"},
    {"id": "admin_001", "name": "超级管理员"},
    {"id": "system", "name": "系统自动"},
]

STATUSES = ["success", "success", "success", "success", "failure"]


def random_timestamp(days_back: int = 30) -> str:
    now = datetime.utcnow()
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return (now - delta).isoformat()


def generate_event():
    action = random.choice(ACTIONS)
    resource = random.choice(RESOURCES)
    actor = random.choice(ACTORS)
    status = random.choice(STATUSES)

    resource_id = f"{resource['type']}_{random.randint(1000, 9999)}"
    resource_name = f"{resource['name_prefix']}#{random.randint(1000, 9999)}"

    event = {
        "timestamp": random_timestamp(),
        "actor_id": actor["id"],
        "actor_name": actor["name"],
        "actor_type": "admin" if actor["id"].startswith("admin") else "user",
        "actor_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "actor_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "action": action["action"],
        "action_detail": action["detail"],
        "resource_type": resource["type"],
        "resource_id": resource_id,
        "resource_name": resource_name,
        "status": status,
        "error_message": None if status == "success" else f"操作失败：{random.choice(['权限不足', '数据不存在', '参数错误', '网络超时'])}",
        "service_name": random.choice(["user-service", "order-service", "auth-service", "finance-service", "admin-portal"]),
        "request_id": f"req_{random.randint(100000, 999999)}",
        "metadata": {
            "browser": random.choice(["Chrome", "Safari", "Firefox"]),
            "os": random.choice(["macOS", "Windows", "Linux"]),
            "locale": random.choice(["zh-CN", "en-US", "ja-JP"]),
        }
    }

    if action["action"] in ["update", "delete"]:
        event["old_value"] = {
            "id": resource_id,
            "name": resource_name,
            "status": "active",
            "updated_at": datetime.utcnow().isoformat()
        }

    if action["action"] in ["create", "update"]:
        event["new_value"] = {
            "id": resource_id,
            "name": resource_name,
            "status": random.choice(["active", "pending", "archived"]),
            "created_at": datetime.utcnow().isoformat()
        }

    return event


async def seed_events(count: int = 500):
    print(f"开始生成 {count} 条审计事件...")

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=60.0) as client:
        resp = await client.post("/login", json={"username": "admin", "password": "admin123"})
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        events = [generate_event() for _ in range(count)]

        batch_size = 100
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            try:
                resp = await client.post("/events/bulk", json=batch, headers=headers)
                if resp.status_code == 201:
                    result = resp.json()
                    print(f"批次 {i // batch_size + 1}: 成功创建 {result['created']} 条事件")
                else:
                    print(f"批次 {i // batch_size + 1}: 失败 - {resp.status_code} - {resp.text}")
            except Exception as e:
                print(f"批次 {i // batch_size + 1}: 异常 - {e}")

        print("\n生成统计数据...")
        resp = await client.get("/statistics", headers=headers)
        if resp.status_code == 200:
            stats = resp.json()
            print(f"\n统计概览:")
            print(f"  总事件数: {stats['total_events']}")
            print(f"  今日事件: {stats['today_events']}")
            print(f"  敏感事件: {stats['sensitive_events']}")
            print(f"  失败事件: {stats['failed_events']}")

    print("\n数据填充完成！")


if __name__ == "__main__":
    asyncio.run(seed_events(500))
