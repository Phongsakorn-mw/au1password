# Au1Password Production & Hugging Face Spaces Dockerfile
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=7860 \
    HOST=0.0.0.0 \
    HEADLESS=1

# Create non-root user (UID 1000 required by Hugging Face Spaces)
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python cryptographic dependencies
RUN pip install --no-cache-dir cryptography

# Set up application and data directories with UID 1000 ownership
RUN mkdir -p /app/data /data && chown -R appuser:appuser /app /data

COPY --chown=appuser:appuser app /app/app

ENV AU1_DATA_DIR=/app/data

USER appuser

EXPOSE 7860 8765 10000

# Healthcheck to verify local API is alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/api/vault/status || exit 1

# Launch headless Au1Password server
CMD ["python3", "/app/app/server.py", "--headless"]
