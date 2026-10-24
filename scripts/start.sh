#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -x .venv/bin/mj ]]; then echo "Run bash scripts/setup.sh first"; exit 1; fi
.venv/bin/mj lab &
lab_pid=$!
trap 'kill "$lab_pid" 2>/dev/null || true' EXIT
.venv/bin/mj serve
