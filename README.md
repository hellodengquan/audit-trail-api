# 审计日志服务 (Audit Trail Service)

基于 **FastAPI + SQLAlchemy + JWT** 构建的企业级审计日志服务，提供事件记录、操作者/资源查询、敏感操作追踪、统计分析、数据导出等能力。

---

## 目录

- [功能特性](#功能特性)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [快速启动](#快速启动)
- [ER 关系图](#er-关系图)
- [API 概览](#api-概览)
- [敏感规则配置](#敏感规则配置)
- [权限体系](#权限体系)
- [测试](#测试)
- [部署与运维](#部署与运维)
- [常见问题](#常见问题)

---

## 功能特性

| 模块 | 能力 |
|------|------|
| **事件记录** | 单条/批量写入、自动捕获 IP/UA、字段变更对比 (old/new value) |
| **操作者查询** | 按 actor_id / actor_name / actor_ip 过滤、时间范围、分页 |
| **资源查询** | 按 resource_type / resource_id 过滤、全量资源列表 |
| **敏感追踪** | 规则引擎自动分级 (low/medium/high/critical)、最小严重度筛选 |
| **统计分析** | 概览面板、按 action/severity/status/资源类型/天/小时聚合 |
| **数据导出** | CSV / JSON 格式、支持全部过滤参数 |
| **规则管理** | 敏感规则 CRUD、通配符+正则双模式匹配、告警通道配置 |
| **认证权限** | JWT Bearer Token、4级 RBAC (admin/manager/auditor/viewer) |
| **可观测** | 请求日志中间件、X-Request-ID、统一异常响应 |

---

## 技术栈

- **Python 3.10+**
- **FastAPI 0.115** — 高性能异步 Web 框架
- **SQLAlchemy 2.0** — ORM (SQLite / PostgreSQL)
- **Pydantic v2** — 数据校验与序列化
- **python-jose** — JWT Token 签发/验证
- **bcrypt** — 密码哈希 (SHA-256 prehash 解决 72字节限制)
- **httpx / requests** — HTTP Client
- **openpyxl** — Excel 支持
- **pytest** — 单元测试框架

---

## 项目结构

```
19-audit-trail-api/
├── app/
│   ├── config.py           # pydantic-settings 环境变量配置
│   ├── database.py         # 引擎、Session、Base
│   ├── models.py           # SQLAlchemy ORM 模型 (User/AuditEvent/SensitiveRule)
│   ├── schemas.py          # Pydantic 请求/响应模型
│   ├── crud.py             # 业务逻辑 & DB 操作、敏感规则评估
│   ├── auth.py             # JWT、密码哈希、RBAC 依赖
│   ├── middleware.py       # 请求日志、CORS、X-Request-ID
│   ├── exceptions.py       # 统一异常处理器
│   ├── main.py             # FastAPI 应用工厂
│   └── routers/
│       ├── auth.py         # /login  /me
│       ├── audit.py        # /events*  (核心审计)
│       ├── admin.py        # /statistics  /aggregation  /sensitive-rules*
│       └── export.py       # /export/csv  /export/json
├── tests/
│   ├── conftest.py         # 测试客户端、内存 SQLite、fixture
│   ├── test_audit_crud.py  # 事件创建/查询/分级/聚合 (约 30 用例)
│   └── test_auth_permissions.py  # 认证/JWT/RBAC/规则管理 (约 30 用例)
├── scripts/
│   ├── seed_data.py        # 填充 N 条示例审计事件
│   └── test_api.py         # 端到端功能验证脚本
├── requirements.txt
├── .env.example
├── main.py                 # uvicorn 启动入口
└── audit_trail.db          # SQLite (自动生成)
```

---

## 快速启动

### 1. 环境准备

```bash
# 推荐 Python 3.10+
python3 --version

# 克隆后进入目录
cd 19-audit-trail-api
```

### 2. 创建虚拟环境并安装依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. 配置环境变量 (可选)

```bash
cp .env.example .env
# 编辑 .env，修改 SECRET_KEY / DATABASE_URL 等
```

### 4. 启动服务

```bash
python main.py
# 或
uvicorn main:app --host 0.0.0.0 --port 8000 --reload --workers 4
```

启动后：

| 资源 | 地址 |
|------|------|
| 健康检查 | http://localhost:8000/health |
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| JSON Schema | http://localhost:8000/openapi.json |

### 5. 默认管理员账号

```
用户名: admin
密码:   admin123
```

### 6. 获取 Token 并调用接口

```bash
# 登录获取 JWT
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token")')

# 记录审计事件
curl -X POST http://localhost:8000/api/v1/events \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "actor_id": "user_007",
    "actor_name": "张三",
    "action": "update",
    "resource_type": "user_account",
    "resource_id": "acc_12345",
    "resource_name": "VIP用户账号",
    "old_value": {"role": "viewer"},
    "new_value": {"role": "admin"},
    "metadata": {"operator": "自助修改"},
    "service_name": "user-portal"
  }'

# 查询敏感操作 (严重度 >= high)
curl "http://localhost:8000/api/v1/events/sensitive?min_severity=high" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### 7. 填充示例数据

```bash
# 生成 500 条随机事件 (动作/资源/操作者/时间均匀分布)
python scripts/seed_data.py 500
```

### 8. 运行单元测试

```bash
pip install pytest
pytest tests/ -v --tb=short
```

---

## ER 关系图

```
┌─────────────────────┐        ┌──────────────────────────┐        ┌─────────────────────┐
│       users         │        │       audit_events       │        │   sensitive_rules   │
├─────────────────────┤        ├──────────────────────────┤        ├─────────────────────┤
│ id          PK int  │        │ id             PK int    │        │ id         PK int   │
│ username    UQ str  │        │ event_id       UQ str    │        │ name              str│
│ password_hash  str  │◄───┐   │ timestamp  IDX datetime  │        │ description      txt│
│ full_name     str   │    │   │ actor_id     IDX str     │        │ is_active   IDX bool│
│ email         str   │    │   │ actor_name   IDX str     │        │ action_pattern   str│
│ role          str   │    │   │ actor_type       str     │        │ resource_type_p. str│
│ is_active     bool  │    │   │ actor_ip         str     │        │ resource_id_pat. str│
│ created_at   datetime│    │   │ actor_user_agent str     │        │ actor_pattern    str│
│ updated_at   datetime│    │   │ action       IDX enum    │        │ min_severity     enum│
└─────────────────────┘    │   │ action_detail    str     │        │ alert_enabled    bool│
                           │   │ resource_type  IDX str   │        │ alert_channels   json│
                           │   │ resource_id    IDX str   │        │ created_at     datetime│
                           │   │ resource_name    str     │        │ updated_at     datetime│
                           │   │ status       IDX enum    │        └─────────────────────┘
                           │   │ error_message    txt     │                  ▲
                           │   │ old_value        json    │                  │
                           │   │ new_value        json    │                  │
                           │   │ event_metadata   json    │                  │
                           │   │ is_sensitive IDX bool    │                  │
                           │   │ severity     IDX enum    │                  │
                           │   │ matched_rule_id FK int ──┼──────────────────┘
                           │   │ service_name IDX str     │
                           │   │ request_id     IDX str   │
                           │   │ created_at     datetime  │
                           │   └──────────────────────────┘
                           │
                           │            INDEXES:
                           │     • idx_actor_timestamp (actor_id, timestamp)
                           │     • idx_resource_timestamp (resource_type, resource_id, timestamp)
                           │     • idx_sensitive_severity (is_sensitive, severity)
                           │     • idx_action_timestamp (action, timestamp)
                           │
                           └── (逻辑关联，审计 actor_id 可为 users.id 或外部系统 ID)
```

### 核心字段说明

| 字段 | 含义 |
|------|------|
| `event_id` | 全局唯一事件 UUID，跨系统追踪用 |
| `actor_id / actor_name` | 操作者 ID 与显示名，支持外部系统 ID |
| `old_value / new_value` | JSON 格式字段变更快照，用于变更对比 |
| `event_metadata` | 业务扩展字段，如渠道、版本、上下文 |
| `is_sensitive` | 是否敏感（由 `sensitive_rules` 自动评估） |
| `severity` | 严重级别：low / medium / high / critical |
| `matched_rule_id` | 命中的第一条敏感规则 ID |
| `request_id` | 与上游业务链路追踪 ID 对齐 |

---

## API 概览

所有接口前缀：`/api/v1`

### 🔐 认证

| Method | 路径 | 说明 | 权限 |
|--------|------|------|------|
| POST | `/login` | 获取 JWT Token | 匿名 |
| GET | `/me` | 当前用户信息 | 已认证 |

### 📋 审计事件（核心）

| Method | 路径 | 说明 | 权限 |
|--------|------|------|------|
| POST | `/events` | 记录单条事件 | 匿名 (业务系统写入) |
| POST | `/events/bulk` | 批量记录 | 匿名 |
| GET | `/events` | 综合查询（12 种过滤参数 + 关键字） | viewer+ |
| GET | `/events/id/{id}` | 按自增 ID 查单条 | viewer+ |
| GET | `/events/event-id/{uuid}` | 按 event_id 查单条 | viewer+ |
| GET | `/events/actor` | 按操作者查询 | viewer+ |
| GET | `/events/resource` | 按资源查询 | viewer+ |
| GET | `/events/sensitive` | 敏感操作追踪 | viewer+ |
| GET | `/events/actors` | 所有操作者列表 + 事件数 | viewer+ |
| GET | `/events/resources` | 所有资源列表 + 事件数 | viewer+ |

### 📊 统计与管理

| Method | 路径 | 说明 | 权限 |
|--------|------|------|------|
| GET | `/statistics` | 概览统计（总数/分布/趋势） | viewer+ |
| GET | `/aggregation` | 聚合分析 (action/severity/status/resource_type/actor/day/hour) | viewer+ |
| GET | `/sensitive-rules` | 敏感规则列表 | viewer+ |
| GET | `/sensitive-rules/{id}` | 规则详情 | viewer+ |
| POST | `/sensitive-rules` | 创建规则 | manager+ |
| PUT | `/sensitive-rules/{id}` | 更新规则 | manager+ |
| DELETE | `/sensitive-rules/{id}` | 删除规则 | admin |

### 📥 导出

| Method | 路径 | 说明 | 权限 |
|--------|------|------|------|
| GET | `/export/csv` | 导出 CSV | auditor+ |
| GET | `/export/json` | 导出 JSON | auditor+ |

---

## 敏感规则配置

服务启动时自动创建 **5 条默认规则**，可在 `/sensitive-rules` 管理。

### 规则匹配模式

一个事件要命中规则，**4 个 pattern 必须同时匹配**（为空的 pattern 视为匹配）：

| 字段 | 匹配模式 | 支持语法 |
|------|----------|----------|
| `action_pattern` | 事件动作 | fnmatch 通配符 + 正则 + `\|` 或分隔 |
| `resource_type_pattern` | 资源类型 | 同上 |
| `resource_id_pattern` | 资源 ID | 同上 |
| `actor_pattern` | 操作者 ID / 名称 | 同上 |

### 匹配优先级

- 事件可同时命中多条规则
- `is_sensitive` 置为 `True`
- `severity` 取所有命中规则中 `min_severity` 最高的
- `matched_rule_id` 取第一条命中的规则

### 规则配置示例

#### 示例 1：追踪所有删除操作

```json
POST /api/v1/sensitive-rules
Authorization: Bearer <token>
{
  "name": "删除操作全局追踪",
  "description": "任何资源的删除行为都视为高风险",
  "is_active": true,
  "action_pattern": "delete",
  "min_severity": "high",
  "alert_enabled": true,
  "alert_channels": ["webhook"]
}
```

#### 示例 2：追踪财务资源上的所有写操作

```json
{
  "name": "财务数据写操作",
  "resource_type_pattern": "*finance*|*payment*|*order*|*refund*",
  "action_pattern": "create|update|delete|import|export",
  "min_severity": "critical",
  "alert_enabled": true,
  "alert_channels": ["email", "webhook", "sms"]
}
```

#### 示例 3：追踪外部人员访问内部系统

```json
{
  "name": "外部人员访问",
  "actor_pattern": "ext_*|vendor_*|guest_*",
  "action_pattern": "*",
  "min_severity": "medium"
}
```

#### 示例 4：追踪某批 VIP 用户的操作

```json
{
  "name": "VIP 用户操作追踪",
  "resource_id_pattern": "vip_[A-Z0-9]{5,}|user_9{3,}",
  "action_pattern": "*",
  "min_severity": "medium"
}
```

### 严重级别定义

| Level | 含义 | 典型场景 |
|-------|------|----------|
| `low` | 低风险 | 常规读取、页面浏览、搜索 |
| `medium` | 中风险 | 登录失败、外部访问、配置查询 |
| `high` | 高风险 | 删除、导出、财务数据修改、权限查询 |
| `critical` | 极高风险 | 权限/角色变更、批量删除、管理员操作、支付相关 |

---

## 权限体系

### 角色定义

```
┌──────────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│  能力     │  admin    │ manager  │ auditor  │ viewer   │ 匿名     │
├──────────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 登录认证  │     ✓     │    ✓     │    ✓     │    ✓     │    —     │
│ 写入事件  │     ✓     │    ✓     │    ✓     │    ✓     │    ✓     │
│ 查询事件  │     ✓     │    ✓     │    ✓     │    ✓     │    ✗     │
│ 统计分析  │     ✓     │    ✓     │    ✓     │    ✓     │    ✗     │
│ 查看规则  │     ✓     │    ✓     │    ✓     │    ✓     │    ✗     │
│ 创建规则  │     ✓     │    ✓     │    ✗     │    ✗     │    ✗     │
│ 更新规则  │     ✓     │    ✓     │    ✗     │    ✗     │    ✗     │
│ 删除规则  │     ✓     │    ✗     │    ✗     │    ✗     │    ✗     │
│ 导出数据  │     ✓     │    ✓     │    ✓     │    ✗     │    ✗     │
└──────────┴───────────┴──────────┴──────────┴──────────┴──────────┘
```

### 创建新用户（通过代码）

```python
from app.database import SessionLocal
from app.auth import get_password_hash
from app.models import User

db = SessionLocal()
user = User(
    username="new_auditor",
    password_hash=get_password_hash("StrongPassword1!"),
    full_name="新任审计员",
    email="auditor2@company.com",
    role="auditor",
    is_active=True,
)
db.add(user)
db.commit()
```

---

## 测试

### 测试覆盖

| 文件 | 用例数 | 覆盖范围 |
|------|--------|----------|
| `tests/test_audit_crud.py` | ~30 | 事件创建、校验、批量、IP/UA 捕获、敏感分级（5条规则）、按操作者/资源/敏感/关键字/分页查询、统计聚合 |
| `tests/test_auth_permissions.py` | ~30 | 登录、JWT 验证边界（过期/错密/错误 secret/无效格式）、4级 RBAC 矩阵、规则管理 CRUD、不存在资源 404 |

### 运行测试

```bash
# 运行全部
pytest tests/ -v

# 按模块
pytest tests/test_audit_crud.py -v
pytest tests/test_auth_permissions.py -v

# 覆盖率报告
pip install pytest-cov
pytest tests/ --cov=app --cov-report=term-missing --cov-report=html
```

### 测试架构

- 内存 SQLite（`sqlite://` + `StaticPool`），无需数据库服务
- 每个测试函数独立事务，执行后回滚，测试间不污染
- `conftest.py` 预置 5 个角色用户 + 5 条敏感规则
- 提供 `admin_headers / manager_headers / auditor_headers / viewer_headers` fixture

---

## 部署与运维

### Docker 部署示例

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

```bash
docker build -t audit-trail .
docker run -d \
  -p 8000:8000 \
  -e DATABASE_URL="postgresql://user:pass@db:5432/audit" \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e ADMIN_PASSWORD="change_me_123" \
  --name audit-service \
  audit-trail
```

### 切换到 PostgreSQL（生产环境推荐）

```bash
# 1. 安装驱动
pip install psycopg2-binary asyncpg

# 2. 修改 .env
DATABASE_URL=postgresql://audit_user:StrongPass@localhost:5432/audit_trail

# 3. 创建数据库
createdb audit_trail
psql audit_trail -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"

# 4. 重启服务即可，SQLAlchemy 会自动建表
```

### 常用运维操作

#### 1. 查看事件总量

```sql
SELECT COUNT(*) FROM audit_events;
```

#### 2. 清理 90 天前的日志

```sql
DELETE FROM audit_events
 WHERE timestamp < NOW() - INTERVAL '90 days';

-- PostgreSQL
VACUUM ANALYZE audit_events;

-- SQLite
VACUUM;
```

#### 3. 重置管理员密码

```python
from app.database import SessionLocal
from app.auth import get_password_hash
from app.models import User
from app.config import settings

db = SessionLocal()
admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
admin.password_hash = get_password_hash("NewSecurePassword!")
db.commit()
```

#### 4. 导出上一个月的审计记录

```bash
# 使用服务自带的导出接口
curl -G "http://localhost:8000/api/v1/export/csv" \
  --data-urlencode "start_time=2026-05-01T00:00:00" \
  --data-urlencode "end_time=2026-05-31T23:59:59" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o may_2026_audit.csv
```

#### 5. 高敏感操作定时告警（cron 示例）

```bash
# 每小时检查上一小时 critical 级事件数
0 * * * * /opt/audit/check_critical.sh >> /var/log/audit_alert.log 2>&1
```

```bash
#!/bin/bash
# check_critical.sh
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"xxx"}' | jq -r .access_token)

COUNT=$(curl -s "http://localhost:8000/api/v1/events/sensitive?min_severity=critical" \
  -H "Authorization: Bearer $TOKEN" | jq .total)

if [ "$COUNT" -gt 5 ]; then
  curl -X POST "$WEBHOOK_URL" -d "{\"text\":\"[审计告警] 过去7天 $COUNT 条 critical 级事件\"}"
fi
```

### 性能建议

| 场景 | 建议 |
|------|------|
| 写入量大 | 使用 `/events/bulk` 批量接口，每批 500-1000 条；或接入 Kafka 异步消费 |
| 查询量大 | PostgreSQL 上建立 `timestamp` 单独 BRIN 索引；按月分表 |
| 超 1 亿条 | 引入 Elasticsearch / ClickHouse 做归档查询，热数据保留在 PostgreSQL |
| 敏感规则多 | 规则数超过 100 条时建议增加规则优先级字段并做预分类 |

---

## 常见问题

### Q: 业务系统如何接入？

A: 在每个需要审计的操作后，向 `POST /api/v1/events` 发送请求（**不需要 token**，适合内部服务）。可配合 SDK 或中间件自动发送。

### Q: 为什么查询接口要认证、写入接口不要？

A: 审计服务通常部署在内网，业务系统写入是高频行为；查询者是后台管理员/审计员，必须留痕。如需保护写入，可在 `app/routers/audit.py` 的 `create_event` 上加 `Depends(get_current_user)`。

### Q: 支持按组织/租户隔离吗？

A: 当前版本未内置多租户。扩展方式：在 `AuditEvent` 加 `tenant_id` 字段，所有查询接口强制过滤 `tenant_id`，用户表加 `tenant_id` 关联。

### Q: 告警通道如何扩展（企业微信/钉钉/Slack）？

A: 在 `crud.py` 的 `_evaluate_sensitive_rules` 返回后，根据 `alert_channels` 调用对应 Webhook；或独立消费者异步处理，避免同步阻塞写入。

### Q: 如何保障审计日志不可篡改？

A: 推荐：
1. 数据库对 `audit_events` 只有 INSERT 权限，无 UPDATE/DELETE
2. 每条事件写入后异步计算哈希（SHA-256(prev_hash + self)），形成区块链结构
3. 定时将日志文件归档至 WORM 存储或对象存储版本桶

---

## Production Hardening

本章节面向生产部署场景，涵盖 **Schema 迁移流程** 和 **可观测性指标体系** 两部分核心治理能力。

### 10.1 数据库 Schema 迁移（Alembic）

本项目已接入 **Alembic** 作为官方迁移工具，**取代此前 `drop+create` 的破坏性方式**，确保历史数据在字段演进中完整保留。

#### 10.1.1 迁移相关文件

```
19-audit-trail-api/
├── alembic.ini              # Alembic 主配置
└── migrations/
    ├── env.py               # 迁移环境（已绑定 SQLAlchemy Base.metadata）
    ├── script.py.mako       # 迁移脚本模板
    └── versions/
        └── d73d9e05e6c7_initial_tables_users_audit_events_.py   # 初始 revision
```

#### 10.1.2 完整迁移工作流

```bash
# =========================================================
# Step 0: 第一次部署（从空库初始化）
# =========================================================
# 直接迁移到最新版本
alembic upgrade head

# 验证迁移版本
alembic current
# 预期输出: d73d9e05e6c7 (head)

# =========================================================
# Step 1: 修改模型（例如给 AuditEvent 加 tenant_id 字段）
# =========================================================
# 编辑 app/models.py，在 AuditEvent 中新增：
#   tenant_id = Column(String(50), index=True)

# =========================================================
# Step 2: 自动生成迁移脚本（推荐 review 后再提交）
# =========================================================
alembic revision --autogenerate -m "add_tenant_id_to_audit_events"
# → 生成 migrations/versions/<hash>_add_tenant_id_to_audit_events.py
# ⚠️ 务必打开文件 review：
#    - 字段顺序、类型、nullable 是否正确
#    - 索引/约束是否遗漏
#    - 枚举变更是否需要数据迁移脚本

# =========================================================
# Step 3: 预演升级（SQL 预览）
# =========================================================
alembic upgrade head --sql > migration.sql
# 对 SQL 文件做代码评审，特别注意：
#   - 大表 ALTER TABLE 是否需要先加索引再改字段
#   - 枚举类型变更（PostgreSQL 需先 CREATE TYPE ... AS ENUM）

# =========================================================
# Step 4: 生产升级
# =========================================================
# 推荐在低峰期执行；PostgreSQL 上 DDL 会短暂锁表
alembic upgrade head

# 验证
alembic current
psql audit_trail -c "SELECT * FROM alembic_version;"

# =========================================================
# 常用其他命令
# =========================================================
alembic history -v            # 查看迁移历史
alembic downgrade -1         # 回滚 1 个版本
alembic stamp head           # 标记为最新版本（跳过执行，仅用于人工同步后的修复）
alembic merge heads          # 多分支合并
```

#### 10.1.3 环境变量配置

```bash
# 默认使用 alembic.ini 的 sqlalchemy.url；生产建议覆盖：
export DATABASE_URL="postgresql://audit_user:StrongPass@db.example.com:5432/audit_trail"

# 或用 Docker 传参：
docker run -e DATABASE_URL=... audit-trail alembic upgrade head
```

#### 10.1.4 迁移检查清单（生产执行前必须确认）

- [ ] `--sql` 预览文件已评审
- [ ] 已在 staging 环境 1:1 还原生产数据演练过
- [ ] 大表 DDL 已评估执行时长与锁表影响
- [ ] 回滚脚本 `downgrade -1` 也已在 staging 演练
- [ ] 迁移执行时间选在业务低峰期

---

### 10.2 可观测性指标（Prometheus）

项目接入了 **prometheus-fastapi-instrumentator**，并内置 3 类指标共 **8+ 条时间序列**，运维可通过 `/metrics` 抓取。

#### 10.2.1 快速验证

```bash
# 启动服务后
curl -s http://localhost:8000/metrics | grep -E "^audit_|^http_"

# 产出示例：
# audit_events_ingested_total{action="create",service_name="user-service",status="success"} 127
# audit_sensitive_hits_total{matched_rule_id="1",severity="high"} 23
# audit_distinct_actor_count 58
# http_request_duration_seconds_sum{endpoint="/api/v1/events",method="POST",status_code="201"} 0.412
# http_requests_total{endpoint="/api/v1/events",method="POST",status_code="201"} 127
```

#### 10.2.2 指标总览

| 指标名 | 类型 | labels | 含义 | 典型用途 |
|--------|------|--------|------|----------|
| `audit_events_ingested_total` | **Counter** | `action` / `status` / `service_name` | 累计写入事件数 | 写入速率（rate）、按服务/动作拆分、错误率 |
| `audit_sensitive_hits_total` | **Counter** | `severity` / `matched_rule_id` | 敏感操作命中数 | 敏感事件增长趋势、单条规则命中排行 |
| `audit_distinct_actor_count` | **Gauge** | （无） | 观察到的独立操作者数量 | 账号活跃度监控、异常突增告警 |
| `http_request_duration_seconds` | **Histogram** | `method` / `endpoint` / `status_code` | 请求耗时分布 | p50/p95/p99 延迟、写入瓶颈定位 |
| `http_requests_total` | **Counter** | `method` / `endpoint` / `status_code` | HTTP 请求总数 | QPS、错误率（5xx/总）、端点热度排行 |
| `http_request_size_bytes` | **Summary** | 同上 | 请求体大小 | 大请求识别、带宽规划 |
| `http_response_size_bytes` | **Summary** | 同上 | 响应体大小 | 大响应（导出接口）优化 |

#### 10.2.3 三大业务指标详解

##### 🔹 `audit_events_ingested_total`

```promql
# 近 5 分钟事件写入速率（TPS）
rate(audit_events_ingested_total[5m])

# 按动作类型拆分（create/read/update/delete/login...）
sum by (action) (rate(audit_events_ingested_total[5m]))

# 失败率（status=failure 的占比）
  sum(rate(audit_events_ingested_total{status="failure"}[5m]))
/ sum(rate(audit_events_ingested_total[5m]))
```

> 💡 **告警建议**：当失败率 > 5% 持续 2 分钟触发 P2 告警。

##### 🔹 `audit_sensitive_hits_total`

```promql
# 近 1 小时敏感事件总数
increase(audit_sensitive_hits_total[1h])

# 按严重级别拆分（critical/high/medium/low）
sum by (severity) (increase(audit_sensitive_hits_total[1h]))

# 命中最多的 Top 5 敏感规则（用于规则优化）
topk(5, sum by (matched_rule_id) (rate(audit_sensitive_hits_total[1d])))
```

> 💡 **告警建议**：`severity="critical"` 事件在 5 分钟内出现 ≥ 3 条 → P1 电话告警。

##### 🔹 `audit_distinct_actor_count`

```promql
# 独立操作者数 24 小时变化曲线
audit_distinct_actor_count

# 异常突增检测（1 小时内涨超 2 倍）
  audit_distinct_actor_count
/ audit_distinct_actor_count offset 1h
> 2
```

> 💡 **启动自动同步**：服务启动时 `bootstrap_actor_count_from_db()` 会扫描已有数据填充初始值，重启后不会归零。

#### 10.2.4 HTTP 基础监控

```promql
# 核心端点 95 分位延迟（秒）
histogram_quantile(0.95,
  sum by (le, endpoint) (rate(http_request_duration_seconds_bucket[5m]))
)

# 5xx 错误率
  sum(rate(http_requests_total{status_code=~"5.."}[5m]))
/ sum(rate(http_requests_total[5m]))

# 事件写入接口 QPS
sum(rate(http_requests_total{endpoint="/api/v1/events",method="POST"}[1m]))
```

#### 10.2.5 Prometheus 抓取配置示例

```yaml
# prometheus.yml
scrape_configs:
  - job_name: audit-trail-api
    scrape_interval: 15s
    metrics_path: /metrics
    static_configs:
      - targets: ["audit-trail-api:8000"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance

  - job_name: audit-trail-api-slow
    scrape_interval: 1m
    metrics_path: /metrics
    static_configs:
      - targets: ["audit-trail-api:8000"]
```

#### 10.2.6 Grafana 推荐面板（可直接 import）

| 面板 | 查询 | 图表类型 |
|------|------|----------|
| 写入 TPS | `sum(rate(audit_events_ingested_total[1m]))` | 时间线 |
| 失败率 | 见上文公式 | 仪表盘（Gauge） |
| 敏感事件排行 | `topk(10, sum by (matched_rule_id) (rate(audit_sensitive_hits_total[6h])))` | 饼图 / 柱状图 |
| 延迟分布 | `histogram_quantile(0.99, sum by (le) (rate(...)))` | 热力图 |
| 操作者增长 | `audit_distinct_actor_count` | 单值 Stat + 趋势 |

---

## 生产加固：速率限制 + 审计不可篡改

### 11.1 写入速率限制（Rate Limiting）

为防止恶意 / 异常客户端快速填充磁盘，`POST /events` 与 `POST /events/bulk` 已接入基于 **IP + actor_id 双维度** 的速率限制，默认阈值为 **每分钟 60 条**。

#### 11.1.1 机制说明

| 维度 | 触发条件 | 超额响应 |
|------|----------|----------|
| IP (`X-Forwarded-For` / `X-Real-IP` / 远端 IP) | 同一 IP 在 60s 窗口中写入事件数（批量按长度计）超过阈值 | `429 Too Many Requests` + 详细 JSON 错误体 |
| actor_id (请求体 JSON) | 同一 `actor_id` 在 60s 窗口中写入事件数超过阈值 | `429 Too Many Requests`，`detail.scope == "actor_id"` |

- 两条检查**分别独立**，任一超额立即 429
- `POST /events/bulk` 一次写入 N 条，消耗额度 = `min(N, 1000)`（取批量长度）
- 存储使用**内存固定窗口**（FastAPI 多 worker 场景建议切到 Redis 实现，见下文）
- 不影响查询接口（`GET /events*`, `/statistics`, `/export*`）

#### 11.1.2 配置项（环境变量）

```bash
# 是否启用速率限制（默认 true）
RATE_LIMIT_ENABLED=true

# 单 IP 每分钟可写入的事件数（默认 60）
RATE_LIMIT_EVENTS_PER_MINUTE_IP=60

# 单 actor_id 每分钟可写入的事件数（默认 60）
RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR=60

# bulk 写入放大系数（预留，当前默认按 list 长度计）
RATE_LIMIT_BULK_FACTOR=10
```

#### 11.1.3 429 响应示例

```json
// HTTP 429
{
  "error": {
    "code": 429,
    "message": {
      "message": "Too many requests for this IP",
      "type": "rate_limit",
      "scope": "ip",
      "limit": 60,
      "window_seconds": 60
    },
    "type": "http_error"
  }
}
```

#### 11.1.4 多 worker / Kubernetes 部署

当前默认实现是 `MemoryStorage`，仅在同一进程内有效。若使用 `uvicorn --workers N` 或多副本部署，需切到 Redis：

```bash
pip install limits[redis]
```

```python
# app/rate_limiter.py 替换 _storage & _window
from limits.storage import RedisStorage
from limits.strategies import MovingWindowRateLimiter

REDIS_URL = os.environ.get("RATE_LIMIT_REDIS_URL", "redis://localhost:6379/1")
_storage = RedisStorage(REDIS_URL)
_window = MovingWindowRateLimiter(storage=_storage)
```

---

### 11.2 审计日志不可篡改（Immutable via Triggers）

在文档承诺「不可篡改」的基础上，新增数据库层触发器硬约束：**audit_events 表的 UPDATE / DELETE 直接由数据库抛出错误**，即便 admin token 被盗或管理员误操作也无法修改历史数据。

#### 11.2.1 迁移脚本

已在 `migrations/versions/ad13ecb4406d_*.py` 中实现 3 种方言：

| 数据库 | 实现方式 | 版本支持 |
|--------|----------|----------|
| **SQLite** | `CREATE TRIGGER … BEFORE UPDATE/DELETE … RAISE(ABORT, '… immutable')` | SQLite 3.x |
| **PostgreSQL** | `plpgsql` 函数 `audit_events_immutable()` + 2 个触发器 | PG 11+ |
| **MySQL / MariaDB** | `BEFORE UPDATE/DELETE … SIGNAL SQLSTATE '45000'` | MySQL 5.7+ / MariaDB 10.2+ |

升级命令：

```bash
# 生产环境执行：从旧版本升级
alembic upgrade head
# 或只执行本次触发器迁移
alembic upgrade ad13ecb4406d
```

降级（仅用于运维操作，不建议长期关闭）：

```bash
# 回滚触发器，允许临时清理
alembic downgrade -1
```

#### 11.2.2 行为验证

```sql
-- 1. 尝试 UPDATE（管理员直连数据库）
UPDATE audit_events SET is_sensitive = 0 WHERE id = 1;
-- SQLite  报错: [SQLITE_CONSTRAINT_TRIGGER] abort at 22 in ... UPDATE on audit_events is forbidden - table is immutable
-- PG      报错: ERROR:  UPDATE on audit_events is forbidden - table is immutable
-- MySQL   报错: Error Code: 1644. UPDATE on audit_events is forbidden ...

-- 2. 尝试 DELETE
DELETE FROM audit_events WHERE id = 1;
-- 同上，被 BEFORE DELETE 触发器拦截
```

#### 11.2.3 运维场景处理

| 场景 | 推荐做法 |
|------|----------|
| 合规数据清理（保留 N 天） | 先 `alembic downgrade -1` 关触发器，按时间段 DELETE，然后 `alembic upgrade head` 重新建触发器；全程记录操作日志 |
| 数据订正（极个别事件修正） | 不修改旧行，**追加**一条互补事件 `action="correct"`，`old_value`/`new_value` 写明原因 |
| 全量重建 / 迁移 | 走 `pg_dump`/`mysqldump` 逻辑导出，触发器在新库自动通过 alembic 重建 |
| 需要对 audit_events 建分区 | 通过新迁移 DDL 完成，**不要直接 DROP/TRUNCATE**，若需要请先关触发器 |

#### 11.2.4 纵深防御建议

触发器属于硬兜底，建议同时配置以下多重防线：

1. **数据库账号最小化**：生产环境专用 DB 用户仅授予 `INSERT, SELECT`，不要 `UPDATE/DELETE/ALTER/DROP`
2. **WAL / Binlog 归档**：PostgreSQL `archive_mode=on`，MySQL binlog 过期 ≥ 180 天
3. **事件哈希链**：可选扩展 `audit_events` 加 `prev_hash` 字段，形成 SHA-256 链，破坏者无法重算后续所有哈希
4. **旁路写入对象存储**：每 5 分钟以 append-only 方式把 JSON 行写入 S3 / OSS，设置 WORM 策略
5. **定时校验**：通过每日离线任务比对 DB 条数、敏感事件总数与哈希链完整性，发现差异立即告警

---

### 11.3 触发告警推荐

结合 Prometheus 指标 + 429 响应做 SLO 告警：

```yaml
# 1. 写入被频繁限流（可能是攻击或 bug）
- alert: AuditWriteRateLimitExceeded
  expr: sum by (scope) (rate(http_requests_total{endpoint!~"/health|/metrics",status_code="429"}[5m])) > 1
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "Audit API 限流了 {{ $value | printf \"%.2f\" }} req/s"
    scope: "{{ $labels.scope }}"

# 2. 检测到尝试 UPDATE/DELETE（DB error 会在应用层返回 500）
- alert: AuditImmutableViolationAttempt
  expr: increase(http_requests_total{status_code="500",endpoint=~".*events.*"}[1h]) > 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "审计表疑似存在篡改尝试，请立即核查 application log"
```

---

## License

内部项目，按需使用。
