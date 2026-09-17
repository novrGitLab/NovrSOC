#!/bin/bash
# NovrSOC Backup Agent
#
# Runs a backup, then reports the result to NovrSOC so it appears on
# Data Continuity → Backup Agent.
#
# Install:
#   sudo mkdir -p /opt/novrsoc
#   sudo cp novrsoc-backup-agent.sh /opt/novrsoc/backup.sh
#   sudo chmod +x /opt/novrsoc/backup.sh
#   sudo crontab -e     # then add:  0 2 * * * /opt/novrsoc/backup.sh
#
# Before first run, confirm BACKUP_SOURCE below matches what you want backed up.
#
# SECURITY NOTE: the reporting endpoint is currently unauthenticated so that a cron job with no
# interactive session can post to it. It only upserts a row in a reporting table. Do not expose
# this script's ORG_ID to untrusted hosts, and add a shared secret to both this script and the
# endpoint before running it outside a network you control.

set -uo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
BACKUP_SOURCE="/var/ossec/etc /var/ossec/logs/alerts"
BACKUP_DEST="/opt/backups/novrsoc"
NOVRSOC_API="https://novrsoc-production-1fb6.up.railway.app"
ORG_ID="cybernovr"
JOB_NAME="novrsoc-config-backup"
RETAIN_COUNT=7

# ── Run ──────────────────────────────────────────────────────────────────────
mkdir -p "$BACKUP_DEST"

ARCHIVE="$BACKUP_DEST/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
START=$(date +%s)

# --warning=no-file-changed keeps an actively-written log file from failing the whole run.
tar -czf "$ARCHIVE" --warning=no-file-changed $BACKUP_SOURCE 2>/tmp/novrsoc-backup.err
STATUS=$?

END=$(date +%s)
DURATION=$((END - START))

# tar exit 1 means "some files differed while reading" (a log rotated mid-read), not a failed
# archive. Only exit >= 2 is a real failure.
if [ "$STATUS" -le 1 ] && [ -f "$ARCHIVE" ]; then
  RESULT="success"
  ERROR=""
else
  RESULT="failed"
  ERROR="tar exited with code $STATUS: $(tr -d '"' < /tmp/novrsoc-backup.err | head -c 300)"
fi

SIZE=$(stat -c %s "$ARCHIVE" 2>/dev/null || echo 0)
FILES=$(tar -tzf "$ARCHIVE" 2>/dev/null | wc -l || echo 0)

# ── Report to NovrSOC ────────────────────────────────────────────────────────
curl -s -X POST "$NOVRSOC_API/api/recovery/jobs/report" \
  -H "Content-Type: application/json" \
  -d "{
    \"job_name\": \"$JOB_NAME\",
    \"status\": \"$RESULT\",
    \"size_bytes\": ${SIZE:-0},
    \"duration_seconds\": $DURATION,
    \"files_transferred\": ${FILES:-0},
    \"org_id\": \"$ORG_ID\",
    \"error_message\": \"$ERROR\"
  }" > /dev/null

# ── Retention ────────────────────────────────────────────────────────────────
# Keep the newest RETAIN_COUNT archives. Runs only on success so a failed run can never delete
# the last known-good backup.
if [ "$RESULT" = "success" ]; then
  ls -t "$BACKUP_DEST"/backup-*.tar.gz 2>/dev/null | tail -n +$((RETAIN_COUNT + 1)) | xargs -r rm -f
fi

echo "[novrsoc-backup] $RESULT  size=${SIZE}B  duration=${DURATION}s  archive=$ARCHIVE"
exit 0
