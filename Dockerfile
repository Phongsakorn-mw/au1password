# Au1Password Production Dockerfile
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AU1_DATA_DIR=/data \
    PORT=8765 \
    HOST=0.0.0.0 \
    HEADLESS=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python cryptographic dependencies
RUN pip install --no-cache-dir cryptography

# Copy application assets
COPY app /app/app

# Persistent volume for encrypted vault and configuration
VOLUME ["/data"]

EXPOSE 8765

# Healthcheck to verify local API is alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8765/api/vault/status || exit 1

# Launch headless Au1Password server
CMD ["python3", "/app/app/server.py", "--headless"]
