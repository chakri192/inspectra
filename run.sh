#!/usr/bin/env bash
set -e

# Inspectra Startup Script

CLOUDFLARE_MODE=false
for arg in "$@"; do
    if [ "$arg" == "--cloudflare" ] || [ "$arg" == "--tunnel" ]; then
        CLOUDFLARE_MODE=true
    fi
done

echo "=================================================="
echo "  Inspectra — Suspicious Content Analyzer         "
echo "=================================================="

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r backend/requirements.txt
else
    source .venv/bin/activate
fi

# Run backend tests
echo "Running automated security tests..."
PYTHONPATH=backend pytest backend/tests -q

# Build frontend if needed
if [ ! -d "frontend/dist" ]; then
    echo "Building frontend static assets..."
    (cd frontend && npm install && npm run build)
fi

echo ""
echo "Starting Inspectra on http://127.0.0.1:8000"
echo "Press Ctrl+C to stop."
echo ""

if [ "$CLOUDFLARE_MODE" = true ]; then
    if ! command -v cloudflared &> /dev/null; then
        echo "Error: 'cloudflared' binary is not installed or not in PATH."
        exit 1
    fi
    PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000 &
    SERVER_PID=$!
    trap "kill $SERVER_PID 2>/dev/null || true" EXIT INT TERM
    sleep 2
    echo "Launching Cloudflare Tunnel..."
    cloudflared tunnel --url http://127.0.0.1:8000
else
    PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000
fi
