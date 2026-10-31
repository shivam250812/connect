#!/usr/bin/env bash
# Starts the platform + health page (:8100). CF_LAB=1 also starts the mock lab sources (:9100).
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  if command -v uv >/dev/null 2>&1; then uv venv --python 3.12 .venv; else python3 -m venv .venv; fi
fi
if command -v uv >/dev/null 2>&1; then uv pip install --python .venv/bin/python -q -r requirements.txt
else .venv/bin/pip install -q -r requirements.txt; fi

mkdir -p data/feeds
export CF_SYSLOG_PORT="${CF_SYSLOG_PORT:-5514}"          # UDP syslog/CEF receiver for push-only devices

if [ "${CF_LAB:-0}" = "1" ]; then                        # CF_LAB=1 ./run.sh adds the mock lab sources
  .venv/bin/python -m connectforge.cli seed-demo
  export MOCK_SYSLOG_TARGET_PORT="$CF_SYSLOG_PORT"         # lab: mock firewalls send syslog here
  .venv/bin/uvicorn connectforge.mock.sources:app --host 127.0.0.1 --port 9100 --log-level warning &
  MOCK=$!
  trap 'kill $MOCK 2>/dev/null' EXIT
  sleep 1
  echo "Mock sources  → http://127.0.0.1:9100/mock/status"
fi
echo "Health page   → http://127.0.0.1:8100"
echo "Syslog/CEF    → udp://127.0.0.1:$CF_SYSLOG_PORT (set CF_SYSLOG_HOST=0.0.0.0 to accept devices on the network)"
.venv/bin/uvicorn connectforge.server:app --host 127.0.0.1 --port 8100 --log-level warning
