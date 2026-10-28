# Deploying P31: Collector V1 (client-site log collection)

**Status: implemented and unit-tested locally against a fake backend. Not deployed.** Nothing
here has run against Supabase, Railway/Render or Vercel. No collector appliance has been run
against a live Vector/Docker instance either (see `infra/novrsoc-collector/README.md`'s "Known
limitations"). Each stage needs approval.

## What this release does

| Area | Change |
|---|---|
| Ingestion | A new, dedicated gateway (`POST /api/collectors/ingest/{heartbeat,events}`) for client-site Vector appliances, with per-collector authentication (never the shared `ALERT_INGEST_TOKEN`) |
| Tenancy | A collector's organisation is resolved server-side from its authenticated identity only, never from anything in the request body (`services/collectors.ts`'s `authenticateCollector()`) |
| Storage | `collector_log_events` — raw collected logs, deliberately separate from `alerts` (see `WAZUH_COMPATIBILITY.md`); `collectors`, `collector_sources`, `collector_heartbeats` for lifecycle and throughput |
| Management | Staff-only `routes/collectors.ts`: enroll, list, inspect, revoke, rotate. New permissions `collectors:read`/`collectors:manage` (super_admin, soc_manager only — not analyst, executive or portal_user) |
| Platform health | `services/pipelineHealth.ts` gained "Log collectors" and "Collector log ingestion" checks, on the existing Platform Health page — no new health UI |
| Frontend | New staff-only "Collector Management" nav section (`/admin/collectors`), same role gating as the backend permissions |
| Infra | `infra/novrsoc-collector/` — the Vector appliance (Docker Compose, pinned image, buffered HTTP sink, heartbeat sidecar) |

**Unchanged**: `infra/soar/soar.py`, `ALERT_INGEST_TOKEN`, the `alerts` table and everything that
reads it, every existing permission, Wazuh's own configuration.

## Order

1. Supabase SQL → 2. backend (Render/Railway) → 3. frontend (Vercel) → 4. enroll the first
   collector → 5. deploy the appliance at the client site → 6. checks.

The backend works before the SQL is applied, in the sense that it won't crash — every collector
route answers `PGRST205`-derived 502/503s (table not found) instead of 200s, so nothing silently
pretends to work. Run the SQL first anyway.

## 1. Supabase

Run `backend/sql/2026-11-12_p31_collector_v1.sql` in the SQL editor (production project).
Additive and idempotent — safe to re-run. Check:

```sql
SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'
  AND table_name IN ('collectors', 'collector_sources', 'collector_heartbeats', 'collector_log_events');  -- 4
SELECT relrowsecurity FROM pg_class WHERE relname = 'collectors';  -- true
```

No backfill needed — every table is new.

## 2. Backend

No new required environment variables; the gateway's own rate limiter and body-size limit are
hardcoded constants (`routes/collectorIngest.ts`'s `INGEST_BODY_LIMIT`, `EVENTS_MAX_BATCH`), same
pattern as `routes/ingest.ts`. If a future release wants these tunable, follow that file's
existing env-var precedent rather than adding new ad-hoc ones here.

## 3. Frontend

No new environment variables. Confirm `/admin/collectors` is reachable for super_admin/soc_manager
and returns 403 (not a blank page) for analyst/executive — the nav item is hidden for them, but
the page itself should still refuse the API calls honestly if reached directly by URL.

## 4. Enroll the first collector

Staff → Collector Management → New collector. Copy the one-time token immediately — see
`docs/collector-v1/LINUX_SYSLOG_ONBOARDING.md` step 1.

## 5. Deploy the appliance

Follow `infra/novrsoc-collector/README.md` at the client site. This is the step most likely to
surface something this release's local testing couldn't — the first real Docker/Vector run.

## 6. Checks

- Platform Health: "Log collectors" and "Collector log ingestion" both report real state (not
  "off" once a collector is enrolled and running; "off" is the honest answer until then).
- Collector Management → the enrolled collector moves from "enrolling" to "connected" within one
  heartbeat interval of the appliance starting.
- A forged `X-Org-Id` from a staff token still cannot see another organisation's collectors (the
  management API resolves org the same way every other staff route does — `requestOrg(req)`).
- Revoke the test collector and confirm its appliance starts getting 401s on its next heartbeat.

## Rollback

Redeploy the previous backend and frontend. The SQL needs no rollback: its tables are unused by
the previous code (the rollback comment block at the end of the SQL file lists the `DROP`
statements, for a deliberate full removal if ever wanted — not required for a simple backend
rollback). Stop the appliance at the client site (`infra/novrsoc-collector/scripts/stop.sh`) if
the backend is rolled back far enough that the gateway routes disappear; until then it will just
accumulate 404s/401s harmlessly into its own disk buffer and retry.
