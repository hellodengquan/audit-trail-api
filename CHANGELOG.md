# Changelog

审计日志服务版本变更记录，遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)
与 [语义化版本（SemVer 2.0.0）](https://semver.org/lang/zh-CN/) 规范。

类型标签：
- `Added`      新增功能 / 新 API / 新依赖
- `Changed`    行为变更 / 接口调整 / 依赖升级
- `Deprecated` 即将移除的功能
- `Removed`    已移除的功能
- `Fixed`      Bug 修复
- `Security`   安全修复 / 加固措施
- `Tests`      新增 / 修改测试
- `Ops`        运维相关（迁移、可观测、部署）

---

## [0.4.0] — 2026-06-10

**主题：生产加固 II — 写入速率限制 + 审计不可篡改**

### Added
- 基于 IP + `actor_id` 双维度的写入速率限制，默认每分钟 60 条，可通过环境变量配置（`app/rate_limiter.py` + `app/config.py`）
  - 新增依赖：`slowapi==0.1.9`、`limits==5.8.0`
  - 超额响应：HTTP 429 `rate_limit`，`detail.scope ∈ {ip, actor_id}`
  - `POST /events/bulk` 按列表长度消耗额度（上限 1000/次）
  - 仅限制写入接口，不影响查询/统计/导出
  - 提供 Redis 存储切换指南（README §11.1.4），适配多 worker / K8s
- 数据库层 **审计不可篡改**：`audit_events` 表新增 `BEFORE UPDATE` / `BEFORE DELETE` 触发器（迁移 `ad13ecb4406d`）
  - 支持 SQLite / PostgreSQL 11+ / MySQL 5.7+ 三方言
  - 直接修改/删除数据将由数据库抛出 `…table is immutable` 异常
  - 可通过 `alembic downgrade -1` 临时关闭（合规清理场景）
- 生产环境运维纵深防御指南（README §11.2.4）：最小化 DB 权限、WAL/Binlog 归档、哈希链、WORM 对象存储、定时校验
- 告警规则：`AuditWriteRateLimitExceeded`（429 激增）、`AuditImmutableViolationAttempt`（篡改尝试 500）
- 生产部署镜像与编排：
  - **Dockerfile**（`python:3.12-slim` 多阶段构建，非 root 运行，tini 1 号进程，HEALTHCHECK）
  - **docker-compose.yml**（audit-trail-api + prometheus v2.53.2，双 named volume 持久化）
  - 内置 `docker/prometheus.yml` scrape 配置

### Tests
- 新增 `tests/test_rate_limit_and_immutable.py`（**14 用例**）
  - `TestRateLimitByIP`：默认阈值 201、超额 429、关闭限速 bypass
  - `TestRateLimitByActor`：同 actor 超限、不同 actor 互不影响
  - `TestRateLimitBulk`：bulk 按 list 长度计 cost、空 bulk 正常
  - `TestRateLimitQuery`：查询接口不受限速约束
  - `TestImmutableAuditTable`：INSERT 正常、直连 UPDATE 被拦截、直连 DELETE 被拦截、触发器注册校验、bulk INSERT 正常、插入后查询 OK
- 覆盖率新增约 220 LOC（rate_limiter.py + migration + triggers）

### Ops
- **迁移**：`alembic upgrade head` 将执行 `add_audit_events_immutable_triggers`（幂等，先 drop 再 create）
- **升级影响**：升级后所有对 `audit_events` 的 UPDATE / DELETE 立即被拦截；如出现运维脚本依赖写旧记录需先执行 `alembic downgrade -1`

---

## [0.3.0] — 2026-06-09

**主题：生产加固 I — Prometheus 可观测 + 统计分析**

### Added
- **Prometheus /metrics 端点**，基于 `prometheus-fastapi-instrumentator==7.0.0`
  - 自动采集：请求量、延迟直方图、状态码分布、`http_requests_total`
  - 业务指标（`app/metrics.py`）：
    - `audit_events_ingested_total{actor,action,resource,severity,is_sensitive}` 写入量
    - `audit_events_write_errors_total{reason}` 写入失败
    - `audit_sensitive_hits_total{rule_id,rule_name,severity}` 敏感事件命中
    - `audit_api_latency_seconds{endpoint,method}` 接口延迟直方图
    - `audit_distinct_actor_count` 独立操作者计数（Gauge，启动时从 DB 初始化）
- **统计 / 聚合 API**：
  - `GET /api/v1/statistics` 总览（总量、敏感量、近 N 天趋势、TOP actor/action/resource）
  - `GET /api/v1/statistics/aggregate?group_by=action|status|severity|actor_id|resource_type` 维度分组
- **导出功能**：`GET /api/v1/export/json` 与 `GET /api/v1/export/csv`，支持同查询接口一致的过滤条件

### Tests
- 新增 `test_statistics_basic`、`test_aggregation_by_action/status`、`test_aggregation_invalid_group_by_fails`
- `test_audit_crud.py` 共 29 测试用例，其中统计/聚合类 18 条

### Changed
- `requirements.txt` 新增 `prometheus-fastapi-instrumentator==7.0.0`、`prometheus-client==0.25.0`
- `app/main.py` 启动钩子中 bootstrap 指标，避免冷启动 actor_count = 0

### Ops
- README 新增 **Prometheus 可观测性**章节，推荐 7 个监控面板的 PromQL + 图表类型
- 推荐 3 条告警：`AuditIngestHighErrorRate`、`AuditSensitiveSpike`、`AuditAPIHighLatency`

---

## [0.2.0] — 2026-06-08

**主题：权限治理 + 敏感事件分级**

### Added
- **基于角色的访问控制（RBAC）**，4 种角色：
  - `admin`    所有权限 + 用户管理
  - `manager`  写入 + 查询 + 导出 + 敏感规则管理
  - `auditor`  只读 + 导出
  - `viewer`   只读（无敏感字段细节）
  - 无角色 / 未登录：仅 `POST /api/v1/events`（匿名上报允许）
- **认证**：HS256 JWT（`python-jose[cryptography]` + `passlib[bcrypt]`）
  - `POST /api/v1/login` JSON 登录，返回 `access_token`
  - `GET /api/v1/me` 查看当前登录用户
  - 默认管理员 `admin:admin123`（首次启动自动创建，生产请覆盖环境变量）
- **敏感事件分级引擎**（`app/schemas.SensitiveRuleCreate` + `app/crud._match_rules`）
  - 规则由 `name / action_pattern / resource_pattern / actor_pattern / is_sensitive / min_severity` 组成
  - 写入时自动匹配，覆盖 `is_sensitive` 与 `severity`
  - `GET|POST|PUT|DELETE /api/v1/sensitive-rules` 规则 CRUD（`admin` / `manager`）
- **管理 API**：用户 CRUD + 角色变更（`admin` 专属）

### Tests
- 新增 `tests/test_auth_permissions.py`（**20+ 用例**）：
  - 每种角色对每类端点的 `401 / 403 / 200/201` 矩阵
  - 匿名写入权限、admin-only 端点保护
  - JWT 过期、错误 token 等边界
- `tests/test_audit_crud.py` 新增敏感规则匹配用例

### Security
- 密码 bcrypt 哈希 + JWT token 过期（默认 1440 分钟）
- pydantic BaseSettings 仅从环境变量 / `.env` 读取密钥，不硬编码

### Changed
- 所有写操作（除匿名上报）和敏感操作必须通过 `role_required(...)` 依赖
- `audit_events` 模型加 `is_sensitive`（bool）与 `severity`（enum: low/medium/high/critical）字段

---

## [0.1.0] — 2026-06-07

**主题：MVP 发布 — 审计事件 CRUD + 多维度查询**

> 首个可运行版本，提供事件落库与基础查询能力。

### Added
- **数据模型**：
  - `users`（用户表）、`audit_events`（审计事件表）、`sensitive_rules`（敏感规则表）
  - `audit_events.id`（自增主键）+ `event_id`（业务 UUID）双 ID，支持两套查询风格
  - 字段：actor_id/name/type、action、resource_type/id/name、status、changes(JSON)、metadata(JSON)、severity、is_sensitive
- **写入 API**：
  - `POST /api/v1/events`      单条创建（201 返回完整事件）
  - `POST /api/v1/events/bulk` 批量创建（`{created, failed, items}`）
- **查询 API**：
  - `GET /api/v1/events`              分页 + 多条件过滤（时间、actor、action、resource、severity、status、keyword 全文）
  - `GET /api/v1/events/{numeric_id}` 按自增主键
  - `GET /api/v1/events/uuid/{uuid}`  按业务 UUID
  - `GET /api/v1/events/actor`        按 actor 精确查询（审计常用）
  - `GET /api/v1/events/resource`     按资源过滤
- **技术栈**：FastAPI 0.115 + SQLAlchemy 2.0 + Alembic 1.18 + Pydantic v2 + Uvicorn
- **结构化异常**（`app/exceptions.py`）：所有 4xx/5xx 统一包裹 `{success=false, error:{code,type,message,details}}`

### Tests
- 新增 `tests/test_audit_crud.py`：
  - `TestEventCreation`：字段校验、空必填、非法 JSON、批量空、部分失败
  - `TestSensitiveOperationGrading`：规则匹配、多规则取最高 severity
  - `TestQueryAuditEvents`：9 类查询 + 分页 + not found + 聚合参数

### Ops
- 初始 Alembic 迁移 `d73d9e05e6c7`：三张表 + 必要索引（actor_id、resource_id、timestamp、severity）
- `.env.example`：所有配置项默认值示例
- `alembic.ini` + `migrations/env.py`：开箱即用迁移脚手架

---

## 版本差异导航

| 版本 | 标签 | 核心交付 |
|------|------|----------|
| [0.4.0] | 生产加固 II | 速率限制（429）、审计不可篡改（触发器）、Docker 镜像、docker-compose |
| [0.3.0] | 生产加固 I | Prometheus 指标、统计/聚合 API、JSON/CSV 导出 |
| [0.2.0] | 权限 + 分级 | JWT 登录、RBAC 4 角色、敏感事件分级引擎、用户/规则管理 |
| [0.1.0] | MVP | 事件写入 / 批量、多维度查询、Alembic 迁移脚手架、结构化异常 |

[0.4.0]: https://github.com/your-org/19-audit-trail-api/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/your-org/19-audit-trail-api/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/your-org/19-audit-trail-api/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/your-org/19-audit-trail-api/releases/tag/v0.1.0
