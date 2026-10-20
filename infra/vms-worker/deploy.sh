#!/usr/bin/env bash
# Deploys a new worker.py (and service file) to this host, safely:
#   1. backs up the running worker.py, worker.env and service file (/opt/novrsoc-vms/backups/<time>/)
#   2. downloads the new files to a staging directory and checks they parse
#   3. runs the NEW worker's --self-test as the service user against the real backend
#      (configuration, tools, versions, Greenbone when enabled, heartbeat) — nothing is installed if it fails
#   4. installs, reloads systemd, restarts, and waits for "connected" in the journal
#   5. on any failure after installing: restores the backup and restarts the previous worker
# Secrets stay in /opt/novrsoc-vms/worker.env; this script never prints them.
#
# Interpreter (1.8.0): the worker keeps running on the interpreter the installed unit uses — e.g.
# /opt/novrsoc-vms/gvm-venv/bin/python, which has python-gvm — never silently /usr/bin/python3.
# Override with VMS_PYTHON=/path/to/python.
# Unit file: an installed unit that differs from the repository's (beyond the interpreter) was
# changed on this host on purpose (e.g. socket access); it is kept and the difference shown.
# --update-unit installs the repository's unit anyway (with the interpreter kept). Prefer
# drop-ins in /etc/systemd/system/novrsoc-vms-worker.service.d/ for local changes.
#
# Usage (as root):  ./deploy.sh [git-ref] [--update-unit]      default ref: main
set -euo pipefail

REF=main
UPDATE_UNIT=0
for a in "$@"; do
  case "$a" in
    --update-unit) UPDATE_UNIT=1 ;;
    -*) echo "unknown option $a"; exit 2 ;;
    *) REF="$a" ;;
  esac
done
SRC="https://raw.githubusercontent.com/novrGitLab/NovrSOC/${REF}/infra/vms-worker"
DIR=/opt/novrsoc-vms
UNIT=/etc/systemd/system/novrsoc-vms-worker.service
SVC=novrsoc-vms-worker
USER_=novrsoc-vms
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$DIR/backups/$STAMP"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -f "$DIR/worker.env" ] || { echo "missing $DIR/worker.env"; exit 2; }

# The interpreter the installed unit runs, unless VMS_PYTHON says otherwise.
CUR_PY="$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$UNIT" 2>/dev/null | head -1)"
PY="${VMS_PYTHON:-${CUR_PY:-/usr/bin/python3}}"
[ -x "$PY" ] || { echo "interpreter $PY is not executable; set VMS_PYTHON"; exit 2; }
runuser -u "$USER_" -- "$PY" -c 'import requests' || { echo "$PY cannot import requests for $USER_ (install it into that environment)"; exit 2; }
echo "== interpreter: $PY"

echo "== backup to $BACKUP"
install -d -m 700 "$BACKUP"
cp -a "$DIR/worker.py" "$BACKUP/worker.py"
cp -a "$DIR/worker.env" "$BACKUP/worker.env"
cp -a "$UNIT" "$BACKUP/novrsoc-vms-worker.service"

echo "== download $REF"
curl -fsSL "$SRC/worker.py" -o "$STAGE/worker.py"
curl -fsSL "$SRC/novrsoc-vms-worker.service" -o "$STAGE/novrsoc-vms-worker.service"
"$PY" -m py_compile "$STAGE/worker.py"
grep -q '^ExecStart=' "$STAGE/novrsoc-vms-worker.service"
# Keep the interpreter in the repository unit.
sed -i -E "s#^ExecStart=[^ ]+ #ExecStart=$PY #" "$STAGE/novrsoc-vms-worker.service"
chmod 0644 "$STAGE/worker.py"
NEW_VERSION="$(grep -oP "^VERSION = '\K[^']+" "$STAGE/worker.py")"
echo "   new worker version: $NEW_VERSION"

INSTALL_UNIT=1
if ! cmp -s "$UNIT" "$STAGE/novrsoc-vms-worker.service"; then
  if [ "$UPDATE_UNIT" = 1 ]; then
    echo "== the installed unit differs from the repository's; replacing it (--update-unit):"
  else
    INSTALL_UNIT=0
    echo "== the installed unit differs from the repository's; KEEPING the installed unit (pass --update-unit to replace it):"
  fi
  diff -u "$UNIT" "$STAGE/novrsoc-vms-worker.service" || true
fi

echo "== preflight: new worker --self-test against the backend (claims nothing)"
if ! runuser -u "$USER_" -- bash -c "set -a; . '$DIR/worker.env'; set +a; '$PY' '$STAGE/worker.py' --self-test"; then
  echo "PREFLIGHT FAILED: nothing installed; the running worker is unchanged"
  exit 1
fi

rollback() {
  echo "== ROLLBACK to $BACKUP"
  install -o "$USER_" -g "$USER_" -m 0755 "$BACKUP/worker.py" "$DIR/worker.py"
  install -m 0644 "$BACKUP/novrsoc-vms-worker.service" "$UNIT"
  systemctl daemon-reload
  systemctl restart "$SVC"
  echo "   previous worker restored and restarted"
}

echo "== install and restart"
install -o "$USER_" -g "$USER_" -m 0755 "$STAGE/worker.py" "$DIR/worker.py"
[ "$INSTALL_UNIT" = 1 ] && install -m 0644 "$STAGE/novrsoc-vms-worker.service" "$UNIT"
systemctl daemon-reload
SINCE="$(date '+%Y-%m-%d %H:%M:%S')"
systemctl restart "$SVC"

echo "== verify: version and connection in the journal (up to 90 s)"
for _ in $(seq 1 18); do
  sleep 5
  if ! systemctl is-active --quiet "$SVC"; then break; fi
  LOG="$(journalctl -u "$SVC" --since "$SINCE" --no-pager -o cat 2>/dev/null || true)"
  if echo "$LOG" | grep -q "version $NEW_VERSION" && echo "$LOG" | grep -q "connected: the backend accepted this worker"; then
    echo "OK: worker $NEW_VERSION running and connected on $PY"
    echo "   backup kept at $BACKUP (roll back with: ./rollback.sh $BACKUP)"
    exit 0
  fi
done
echo "NOT CONFIRMED: the new worker did not report version $NEW_VERSION and a connection in time"
journalctl -u "$SVC" --since "$SINCE" --no-pager -o cat | tail -20 || true
rollback
exit 1
