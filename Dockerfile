# syntax=docker/dockerfile:1.6

# ============================================================
# Stage 1: Builder
#   构建 Python 虚拟环境（编译 bcrypt / cryptography 等原生扩展
# ============================================================
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv

# 编译 bcrypt / cryptography 需要的系统库
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
        libssl-dev \
        pkg-config \
 && rm -rf /var/lib/apt/lists/*

# 创建 venv
RUN python -m venv ${VIRTUAL_ENV}
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# 先复制 requirements 再装依赖，最大化 layer cache
WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip wheel setuptools \
 && pip install -r requirements.txt

# ============================================================
# Stage 2: Runtime
#   生产镜像，只保留运行时依赖
# ============================================================
FROM python:3.12-slim AS runtime

ARG APP_VERSION=0.4.0
ARG BUILD_DATE

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    APP_HOME=/app \
    DATA_DIR=/data \
    PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus_multiproc

LABEL org.opencontainers.image.title="Audit Trail API" \
      org.opencontainers.image.description="生产级审计日志服务（速率限制 + DB 级不可篡改）" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/your-org/19-audit-trail-api" \
      org.opencontainers.image.licenses="Internal"

# 仅保留运行时必需的 .so（cryptography / openssl），保持镜像轻量
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        tini \
        curl \
 && rm -rf /var/lib/apt/lists/*

# 非 root 用户运行
RUN groupadd --gid 10001 app \
 && useradd  --uid 10001 --gid app --no-create-home --shell /sbin/nologin app

# 从 builder 复制 venv
COPY --from=builder /opt/venv /opt/venv

# 数据目录（SQLite 数据持久化点）
RUN mkdir -p ${APP_HOME} ${DATA_DIR} ${PROMETHEUS_MULTIPROC_DIR} \
 && chown -R app:app ${APP_HOME} ${DATA_DIR} ${PROMETHEUS_MULTIPROC_DIR}

WORKDIR ${APP_HOME}

# 拷贝源码
COPY --chown=app:app . .

# 默认环境变量（可在 k8s/docker-compose 覆盖
ENV DATABASE_URL="sqlite:////data/audit_trail.db" \
    DEBUG="false" \
    ACCESS_TOKEN_EXPIRE_MINUTES="1440" \
    HOST="0.0.0.0" \
    PORT="8000" \
    WORKERS="2"

# 暴露 HTTP + Prometheus metrics（/metrics）
EXPOSE 8000

# 健康检查（/health 或 /docs 都可
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

USER app

# 启动脚本：先跑 alembic -> 再 uvicorn
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", \
     "mkdir -p /data && \
      alembic upgrade head && \
      uvicorn main:app --host 0.0.0.0 --port 8000 \
        --workers ${WORKERS} \
        --log-level info \
        --no-server-header \
        --proxy-headers \
        --forwarded-allow-ips='*'"]
