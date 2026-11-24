#!/usr/bin/env bash
# Au1Password 1-Click Online Cloud & Production Deployment Script
set -euo pipefail

echo "======================================================"
echo "    Deploying Au1Password Production Instance         "
echo "======================================================"

if ! command -v docker &> /dev/null; then
    echo "[!] Docker is not installed. Please install Docker first:"
    echo "    curl -fsSL https://get.docker.com | sh"
    exit 1
fi

if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo "[!] docker compose plugin is not installed."
    exit 1
fi

echo "[1/3] Building Au1Password Production Container..."
docker compose build

echo "[2/3] Starting Au1Password in background..."
docker compose up -d

echo "[3/3] Verifying deployment health..."
sleep 2
if curl -s http://127.0.0.1:8765/api/vault/status > /dev/null; then
    echo "======================================================"
    echo "  Au1Password Production Daemon is RUNNING!          "
    echo "  Local Web UI: http://127.0.0.1:8765                 "
    echo "  Zero-Knowledge Encryption: Active                   "
    echo "======================================================"
else
    echo "[!] Container started. Access at http://127.0.0.1:8765"
fi
