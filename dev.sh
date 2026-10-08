#!/usr/bin/env bash
set -e

# ThreatLens - Start backend and frontend
echo "=== Starting ThreatLens Dev Environment ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Environment file check
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
  fi
fi

# 2. Backend virtual environment
cd "$SCRIPT_DIR/backend"
if [ ! -d "venv" ]; then
  echo "Creating Python virtual environment in backend/venv..."
  python3 -m venv venv || python -m venv venv
fi

echo "Installing backend dependencies..."
source venv/bin/activate
pip install -r requirements.txt

# 3. Frontend setup
cd "$SCRIPT_DIR/frontend"
if [ ! -d "node_modules" ]; then
  echo "Installing frontend dependencies..."
  npm install
fi

# 4. Start servers
echo "Starting Backend on http://localhost:8000..."
cd "$SCRIPT_DIR/backend"
venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

echo "Starting Frontend on http://localhost:5173..."
cd "$SCRIPT_DIR/frontend"
npm run dev -- --host &
FRONTEND_PID=$!

cleanup() {
  echo "Stopping ThreatLens..."
  kill $BACKEND_PID 2>/dev/null || true
  kill $FRONTEND_PID 2>/dev/null || true
  exit 0
}

trap cleanup SIGINT SIGTERM
wait
