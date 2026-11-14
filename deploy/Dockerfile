# ==========================================
# Multi-Stage Production Dockerfile
# ==========================================

# Stage 1: Build & wheels preparation
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt


# Stage 2: Final Minimal Runtime Image
FROM python:3.11-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data

# Create dedicated non-root user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

# Install curl for container health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built wheels from builder
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application source code
COPY --chown=appuser:appgroup cve_tracker /app/cve_tracker
COPY --chown=appuser:appgroup bot.py /app/bot.py
COPY --chown=appuser:appgroup README.md /app/README.md

# Prepare data storage directory with non-root ownership
RUN mkdir -p /app/data && chown -R appuser:appgroup /app/data

USER appuser

VOLUME ["/app/data"]

CMD ["python", "-m", "cve_tracker.main"]
