#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v npm >/dev/null || { echo "Install Node.js 20.19+ (or 22+) and npm"; exit 1; }
source scripts/setup-python.sh
mj_prepare_python
.venv/bin/python -m pip install --only-binary=:all: -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
(cd frontend && npm ci --no-audit --no-fund && npm run build)
.venv/bin/mj doctor
echo "Ready. Run bash scripts/start.sh, then open http://127.0.0.1:8765"
