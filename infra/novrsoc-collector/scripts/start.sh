#!/usr/bin/env bash
# Starts the NovrSOC Collector V1 appliance locally. Validates the config first (fails fast,
# before anything is pulled or started) and refuses to start without a filled-in .env.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "No .env found. Copy .env.example to .env and fill in NOVRSOC_COLLECTOR_TOKEN and NOVRSOC_BACKEND_URL first." >&2
  exit 1
fi
if ! grep -qE '^NOVRSOC_COLLECTOR_TOKEN=.+\..+' .env; then
  echo "NOVRSOC_COLLECTOR_TOKEN in .env is empty or not in <id>.<secret> form — enroll this collector in NovrSOC first (Collector Management -> New collector)." >&2
  exit 1
fi

./scripts/validate-config.sh
docker compose up -d
echo
echo "Started. Follow logs with: docker compose logs -f"
echo "Vector health:  docker compose exec vector wget -qO- http://127.0.0.1:8686/health"
