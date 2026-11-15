#!/usr/bin/env bash
set -e

echo "=================================================="
echo "  Inspectra — Cloudflare Tunnel Launcher         "
echo "=================================================="

if ! command -v cloudflared &> /dev/null; then
    echo "Error: 'cloudflared' binary is not installed or not in PATH."
    echo "Install it via: brew install cloudflared"
    exit 1
fi

# Start backend if not running
if ! curl -s http://127.0.0.1:8000/api/health &> /dev/null; then
    echo "Inspectra server is not running locally. Starting Inspectra on port 8000..."
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        source .venv/bin/activate
        pip install -r backend/requirements.txt
    else
        source .venv/bin/activate
    fi

    if [ ! -d "frontend/dist" ]; then
        echo "Building frontend static assets..."
        (cd frontend && npm install && npm run build)
    fi

    PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000 &
    SERVER_PID=$!
    trap "kill $SERVER_PID 2>/dev/null || true" EXIT INT TERM
    sleep 2
fi

echo "Opening Cloudflare Tunnel to http://127.0.0.1:8000..."
cloudflared tunnel --url http://127.0.0.1:8000
