#!/usr/bin/env bash
# Validates config/vector.toml using Vector's own `validate` subcommand, inside the exact pinned
# image docker-compose.yml runs — never a locally installed Vector that might be a different
# version. Checks syntax AND semantics (unknown fields, type mismatches, missing required keys),
# without starting any listener or sending anything anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="$(grep -E '^\s*image:\s*timberio/vector' docker-compose.yml | head -n1 | sed -E 's/.*image:\s*//')"
if [ -z "$IMAGE" ]; then echo "Could not read the Vector image from docker-compose.yml" >&2; exit 1; fi

echo "Validating config/vector.toml against $IMAGE ..."
docker run --rm \
  -v "$(pwd)/config/vector.toml:/etc/vector/vector.toml:ro" \
  "$IMAGE" validate /etc/vector/vector.toml
echo "OK: config/vector.toml is valid for $IMAGE."
