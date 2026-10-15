# P10: scanner worker presence

**The problem.** The VMS dashboard decided whether a scanner worker was connected from scan-job heartbeats, and those exist only while a job runs. A healthy worker polling an empty queue left no trace, so the dashboard said "No scanner worker has connected yet".

**The fix.**
- The backend now records every request that carries the worker token: the worker's new heartbeat, every job poll (including an empty queue) and every job heartbeat.
- The dashboard shows a worker as connected while such a request arrived in the last 3 minutes.
- A process that runs but cannot authenticate is never shown as connected.

## Changes

| Where | What |
|---|---|
| `backend/sql/2026-10-18_p10_vms_worker_presence.sql` | New `vms_workers` table and `purge_vms_workers()`; additive |
| `POST /api/vms/worker/heartbeat` | Worker token; `{ worker_id, kinds, version?, tools? }`; 30 requests/min; answers with the queued job count |
| `POST /api/vms/worker/claim` | Unchanged contract; now also records presence |
| `GET /api/vms/overview` | `worker.state` (`online` / `offline` / `never`), `source`, and a worker list for staff. `seen_recently` and `last_heartbeat_at` are kept |
| Platform Health → VMS scanner | Uses the same status |
| `infra/vms-worker/worker.py` 1.1.0 | Sends a heartbeat every 60 s, explains failures, logs a status line every 10 min, adds `--check` |

## Order

The backend works with or without the SQL. Without it, the heartbeat endpoint answers 503 naming the SQL file, and the dashboard falls back to job heartbeats and says so.

1. **SQL.** Run `backend/sql/2026-10-18_p10_vms_worker_presence.sql` in the Supabase SQL editor. Optional retention (pg_cron):
   ```sql
   SELECT cron.schedule('purge-vms-workers', '50 4 * * *', $$SELECT public.purge_vms_workers()$$);
   ```
2. **Backend and frontend.** Merge to `main`; Railway and Vercel redeploy. Then check:
   ```bash
   cd backend && NOVRSOC_API=https://novrsoc-production-1fb6.up.railway.app npm run verify:deployment
   ```
   `Worker heartbeat without token refused` must be `PASS (HTTP 401)`. `NOT SET UP (404)` means the new backend is not live yet; `HTTP 503` means `VMS_WORKER_TOKEN` is unset on Railway.
3. **Worker host.** Install the new worker and restart it:
   ```bash
   sudo install -o novrsoc-vms -g novrsoc-vms -m 0755 worker.py /opt/novrsoc-vms/worker.py
   sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; python3 /opt/novrsoc-vms/worker.py --check'
   sudo systemctl restart novrsoc-vms-worker
   journalctl -u novrsoc-vms-worker -n 20 --no-pager
   ```
   `--check` must print `OK: the backend accepted worker vps3-demo-worker …`. The journal must show `connected: the backend accepted this worker`.
4. **Dashboard.** VMS overview, signed in as staff: the Scanner workers table lists `vps3-demo-worker` as connected, with any missing tools. Platform Health shows **VMS scanner: up — 1 worker(s) online**.

## Rollback

- **Code:** redeploy the previous commit. The old backend ignores `vms_workers`.
- **Worker:** an old backend answers the new heartbeat with 404. The worker logs that once and keeps polling.
- **SQL:** leave `vms_workers` in place; it holds no tenant data.

## First real scan (authorised test target only)

Use a domain or address you own, or have written permission to test.

1. **Scope.** In VMS → Authorised Scope, as a SOC manager, add the target with:
   - its authorisation reference;
   - an expiry date;
   - **active checks** enabled (`allow_discovery`). Discovery uses DNS and one HTTP request per host.
   - Leave port and vulnerability scanning off for this first test.
2. **Scan.** VMS → Scans → queue a **Discovery** scan on that scope entry. With no targets given, it covers the entry itself.
3. **Watch the worker:** `journalctl -u novrsoc-vms-worker -f`. Expect `claimed job … (discovery)`, the tools running, then `job … succeeded`. The dashboard shows the job going from queued to running (with progress) to succeeded.
4. **Results.** VMS → Assets shows the hostnames found, their DNS and HTTP details. The scan's summary counts accepted results and anything rejected as out of scope (expected: 0).
5. **Cancelling.** Revoking the scope entry stops a running scan at its next heartbeat and cancels queued ones.
