#!/usr/bin/env bash
# Stops the appliance. The disk buffer volume is kept by default (--volumes to also remove it) —
# any events not yet forwarded survive a stop/start, but are lost if the volume is removed.
set -euo pipefail
cd "$(dirname "$0")/.."

REMOVE_VOLUME=0
for a in "$@"; do
  [ "$a" = "--volumes" ] && REMOVE_VOLUME=1
done

if [ "$REMOVE_VOLUME" = "1" ]; then
  echo "Stopping and removing the disk buffer volume — any buffered, not-yet-forwarded events will be lost."
  docker compose down --volumes
else
  docker compose down
  echo "Stopped. The disk buffer volume was kept; start.sh will resume from it."
fi
