#!/usr/bin/env bash
# Restores a worker backup made by deploy.sh and restarts the service.
# Usage (as root):  ./rollback.sh /opt/novrsoc-vms/backups/<time>     (default: the newest backup)
set -euo pipefail
DIR=/opt/novrsoc-vms
BACKUP="${1:-$(ls -1d "$DIR"/backups/*/ 2>/dev/null | sort | tail -1)}"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -f "$BACKUP/worker.py" ] || { echo "no backup at '$BACKUP'"; exit 2; }
install -o novrsoc-vms -g novrsoc-vms -m 0755 "$BACKUP/worker.py" "$DIR/worker.py"
[ -f "$BACKUP/novrsoc-vms-worker.service" ] && install -m 0644 "$BACKUP/novrsoc-vms-worker.service" /etc/systemd/system/novrsoc-vms-worker.service
systemctl daemon-reload
systemctl restart novrsoc-vms-worker
sleep 10
journalctl -u novrsoc-vms-worker -n 15 --no-pager -o cat
echo "restored $BACKUP"
