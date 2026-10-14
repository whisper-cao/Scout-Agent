FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SCOUT_HOME=/app

WORKDIR /app

# 系统依赖（证书库用于 TLS 探测）
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# 数据目录（SQLite + 产物）
RUN mkdir -p /app/data /app/artifacts \
 && useradd -m -u 10001 scout \
 && chown -R scout:scout /app
USER scout

VOLUME ["/app/data"]
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:5000/api/health || exit 1

# gthread：SSE 是长连接，必须多线程；单个 SSE 连接会独占一个线程
CMD ["gunicorn", "--bind", "0.0.0.0:5000", \
     "--workers", "2", "--threads", "16", "--worker-class", "gthread", \
     "--timeout", "0", "--graceful-timeout", "30", \
     "--access-logfile", "-", "app.server:app"]