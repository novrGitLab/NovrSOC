#!/bin/sh
# NovrSOC Collector V1 — heartbeat sidecar.
#
# Every HEARTBEAT_INTERVAL_SECONDS: read Vector's own Prometheus metrics (never invent a number),
# and POST a heartbeat to NovrSOC. This is also what activates a newly enrolled collector — its
# status flips from "enrolling" to "connected" on the first heartbeat the backend accepts
# (backend/src/services/collectors.ts's recordHeartbeat()).
#
# Metric names below (vector_component_received_events_total, vector_component_sent_events_total,
# vector_component_errors_total, vector_buffer_byte_size, vector_buffer_max_byte_size) are
# Vector's long-documented internal_metrics counters and buffer gauges. This script has NOT been
# run against a live Vector instance in the environment this was written in (no Docker/Vector
# binary available there) — if your Vector version reports differently, run
# `curl $VECTOR_METRICS_URL` and compare before relying on this in production. Stated as a known
# limitation in the Collector V1 delivery report, not hidden.
#
# POSIX sh + curl + awk only (both present in the curlimages/curl / Alpine base image); no jq.
set -eu

: "${NOVRSOC_BACKEND_URL:?set in .env}"
: "${NOVRSOC_COLLECTOR_TOKEN:?set in .env}"
VECTOR_METRICS_URL="${VECTOR_METRICS_URL:-http://vector:9598/metrics}"
VECTOR_HEALTH_URL="${VECTOR_HEALTH_URL:-http://vector:8686/health}"
INTERVAL="${HEARTBEAT_INTERVAL_SECONDS:-60}"

# Sums every metric line whose name is exactly $1, across however many label-sets are present
# (e.g. one per syslog source) — Prometheus text format: "metric_name{labels} value". Prints 0,
# never nothing, if the metric is absent (a missing counter means zero events of that kind, not
# unknown — unlike a missing gauge below, which genuinely is unknown).
sum_metric() {
    printf '%s\n' "$METRICS" | awk -v want="$1" '
        { n = index($0, "{"); name = n ? substr($0, 1, n - 1) : $1 }
        name == want { sum += $NF }
        END { printf "%d", sum }
    '
}

# The first matching gauge's value, or empty (not "0") when the metric is genuinely absent.
one_metric_value() {
    printf '%s\n' "$METRICS" | awk -v want="$1" '
        { n = index($0, "{"); name = n ? substr($0, 1, n - 1) : $1 }
        name == want { print $NF; found = 1; exit }
        END { if (!found) print "" }
    '
}

while true; do
    HEALTH_STATUS="down"
    if curl -fsS --max-time 5 "$VECTOR_HEALTH_URL" >/dev/null 2>&1; then HEALTH_STATUS="up"; fi

    if [ "$HEALTH_STATUS" = "up" ]; then
        METRICS="$(curl -fsS --max-time 5 "$VECTOR_METRICS_URL" 2>/dev/null || echo '')"
        RECEIVED="$(sum_metric vector_component_received_events_total)"
        FORWARDED="$(sum_metric vector_component_sent_events_total)"
        FAILURES="$(sum_metric vector_component_errors_total)"
        BUFFER_SIZE="$(one_metric_value vector_buffer_byte_size)"
        BUFFER_MAX="$(one_metric_value vector_buffer_max_byte_size)"
        BUFFER_PCT="null"
        if [ -n "$BUFFER_SIZE" ] && [ -n "$BUFFER_MAX" ] && [ "$BUFFER_MAX" != "0" ]; then
            BUFFER_PCT="$(awk -v s="$BUFFER_SIZE" -v m="$BUFFER_MAX" 'BEGIN { printf "%.2f", (s / m) * 100 }' 2>/dev/null || echo null)"
        fi

        BODY=$(cat <<JSON
{"vector_version":"${VECTOR_VERSION:-unknown}","events_received":${RECEIVED:-0},"events_forwarded":${FORWARDED:-0},"delivery_failures":${FAILURES:-0},"buffer_pct":${BUFFER_PCT},"sources":[{"source_key":"syslog_tcp","kind":"syslog_tcp"},{"source_key":"syslog_udp","kind":"syslog_udp"},{"source_key":"syslog_tls","kind":"syslog_tls"}]}
JSON
)
        if curl -fsS --max-time 10 -X POST "$NOVRSOC_BACKEND_URL/api/collectors/ingest/heartbeat" \
            -H "Authorization: Bearer $NOVRSOC_COLLECTOR_TOKEN" -H 'Content-Type: application/json' \
            -d "$BODY" >/dev/null 2>&1; then
            echo "[heartbeat] sent: received=$RECEIVED forwarded=$FORWARDED failures=$FAILURES buffer_pct=$BUFFER_PCT"
        else
            echo "[heartbeat] send failed — will retry next interval"
        fi
    else
        echo "[heartbeat] vector health check failed — skipping this interval"
    fi
    sleep "$INTERVAL"
done
