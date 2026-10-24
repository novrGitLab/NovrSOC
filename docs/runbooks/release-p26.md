# Release P26 (`release/novrsoc-p26`): deployment checklist

**Base.** Production `9429743` (`/health` reports it; `main` and `release/novrsoc-unified` point there).

**Adds:**

| Commit | Content |
|---|---|
| `5857078` | Integration sprint (P26): incremental read-only MISP sync, private-intelligence boundaries in enrichment, TI context for SecOps AI, VMS stale-job and verification fixes. |
| `9c92f6d` | Worker 1.8.2: whole, valid evidence targets. |
| `166ab7a` | Worker 1.8.2 deployment runbook. |
| release commit | IOC lookup cache per organisation, a migration, `npm run misp:check`, this checklist. |

Nothing below has been run against production. Every step needs approval.

## 1. Order

1. Supabase migrations (section 2).
2. MISP compatibility check (section 3).
3. Render backend (section 4).
4. Vercel frontend (section 5).
5. Worker VPS (section 6).
6. Post-deploy checks (section 7).

The backend must follow the migrations: it writes the IOC cache per organisation, which needs P26. Before P26 the cache simply is not written and reads return nothing (fail closed).

## 2. Supabase (SQL editor, production project)

### Pre-checks (read-only)

```sql
-- uuid-ossp must live in the `extensions` schema (Supabase default); P25 calls extensions.uuid_generate_v5.
select extname, extnamespace::regnamespace from pg_extension where extname in ('uuid-ossp','pgcrypto');
-- Prerequisites
select to_regclass('public.organisations') org, to_regclass('public.ti_indicators') ti, to_regclass('public.ioc_enrichments') ioc,
       to_regclass('public.staff_org_assignments') p21_already, to_regclass('public.ti_reports') p25_already;
select count(*) total, count(*) filter (where true) from public.ti_indicators;       -- P25 rewrites this table once
select count(*) from public.ioc_enrichments;                                          -- P26 rewrites this table once
```

If `uuid-ossp` is installed in a schema other than `extensions`, stop and ask first: P25's generated column needs `extensions.uuid_generate_v5`.

### Migrations, in this order

All are additive and idempotent. Each was applied twice to Postgres (PGlite, Postgres 16) built from the repository's prerequisites: the second run changed nothing, and the checks passed.

| # | File | Depends on | Notes |
|---|---|---|---|
| 1 | `backend/sql/2026-10-27_p21_staff_org_assignments.sql` | `organisations (slug unique)` | New table. Until it exists, analysts are limited to their own organisation. After it, assign analysts in Settings. |
| 2 | `backend/sql/2026-10-30_p25_ti_v1.sql` | P6 `2026-10-15_p6_threat_info.sql`; `uuid-ossp` in `extensions` | Adds columns to `ti_indicators`, including the generated `stix_uuid` (one table rewrite: run at a quiet moment). Backfills TLP. Switches off OpenCTI. Adds `ti_reports`, `ti_indicator_geo`, `ti_taxii_clients` with RLS. |
| 3 | `backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` | `ioc_enrichments` | Adds `org_id` and the surrogate `id`; primary key becomes `id`; unique `(org_id, ioc_value)`. Existing rows keep `org_id` NULL and are shown to no organisation (one table rewrite, small). |

P20 and P24 are already applied in production; re-running them is harmless but unnecessary.

**Optional, only if every existing IOC-cache row is known to be Cybernovr's.** The commented statement at the end of the P26 file attributes unattributed rows to one organisation. Check the count first.

### Post-checks

```sql
select count(*) from public.staff_org_assignments;                                              -- 0, table exists
select count(*) filter (where stix_uuid is null) missing_stix, count(*) from public.ti_indicators;  -- missing_stix = 0
select tlp, count(*) from public.ti_indicator_sources group by tlp;
select id, enabled from public.ti_feeds where id in ('opencti','misp_events');                    -- opencti false, misp_events true
select count(*) filter (where org_id is null) unattributed, count(*) from public.ioc_enrichments;
select indexname from pg_indexes where tablename = 'ioc_enrichments';                           -- includes ioc_enrichments_org_value_key
```

## 3. MISP (existing gateway / Cloudflare Quick Tunnel)

### What the new client needs from whatever `MISP_URL` points at

| Requirement | Why |
|---|---|
| `https` with a certificate that validates normally | A Quick Tunnel's `*.trycloudflare.com` certificate does. |
| `MISP_CA_CERT` **empty** when `MISP_URL` is the tunnel | A pinned certificate trusts only MISP's own certificate, and the tunnel presents Cloudflare's. If it is still set from the direct connection, every call fails the TLS handshake. |
| **No redirects** on API paths | The new client never follows them, by design. The earlier "capability check PASSED" ran on the old client, which did follow redirects, so a gateway that redirects (http→https, a trailing slash, a login page) would have passed then and fail now. |
| JSON answers (`content-type: application/json`) | An HTML page (a gateway error page, a login page) is reported as such. |
| Allowed paths | `GET /servers/getVersion`, `GET /users/view/me`, `POST /attributes/restSearch` and `POST /events/restSearch`, with the `Authorization` header passed through unchanged. If a gateway blocks `/users/view/me`, the check reports the key's write permission as "unknown" (not fatal). |
| Cloudflare Access headers | Sent only when both `MISP_CF_ACCESS_*` are set. A Quick Tunnel has no Access: leave them empty. |

**Quick Tunnel limitations** (Cloudflare's own):

- intended for testing;
- no uptime guarantee;
- the hostname **changes whenever `cloudflared` restarts**, and `MISP_URL` on Render must then be updated;
- no Access policies;
- a cap on concurrent requests.

During an outage, runs fail with "could not be reached" or "the Cloudflare Tunnel to MISP is down", and the next run catches up from the last success. For production, move to a named tunnel with an Access service token (`docs/runbooks/misp-integration.md`).

### Verify with the new client (read-only; prints no secrets)

On a machine with the same environment as Render (or in a Render shell):

```bash
cd backend && npm ci && npm run misp:check
# expect: Reachable: true · version: 2.5.50 · key can write: false · STIX 2 export: supported
#         Attribute search ... OK · Event search ... OK · MISP CHECK: COMPATIBLE
```

Raw equivalent (no redirects followed; shows status, content type and any redirect target):

```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type} redirect=%{redirect_url}\n' \
  -H "Authorization: $MISP_API_KEY" -H 'Accept: application/json' "$MISP_URL/servers/getVersion"
curl -sS -o /dev/null -w '%{http_code} %{content_type} redirect=%{redirect_url}\n' -X POST \
  -H "Authorization: $MISP_API_KEY" -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -d '{"returnFormat":"json","limit":1,"page":1,"timestamp":"0","metadata":true}' "$MISP_URL/events/restSearch"
# both: 200 application/json redirect=   (empty)
```

## 4. Render (backend)

**Environment.** Set these in the dashboard; the values come from your secret store and never go in the repository.

| Variable | Value |
|---|---|
| `NOVRSOC_ENV` | `production` |
| `NOVRSOC_DISABLE_JOBS` | `false` on the single host that runs jobs |
| `MISP_URL` | the current tunnel `https://…` |
| `MISP_API_KEY` | the read-only key |
| `MISP_CA_CERT` | **empty** for a tunnel |
| `MISP_WRITE_ENABLED` | `false` |
| `MISP_CF_ACCESS_CLIENT_ID`, `MISP_CF_ACCESS_CLIENT_SECRET` | empty for a Quick Tunnel; set for a named tunnel behind Access |
| Optional | `MISP_BACKFILL_DAYS` (default 7), `MISP_PAGE_SIZE` (1000), `MISP_MAX_PAGES` (20), `MISP_PAGE_DELAY_MS` (250), `MISP_MAX_ATTEMPTS` (3) |
| Unchanged | `VMS_WORKER_TOKEN`, `VMS_OPENVAS_ENABLED=false`, `VMS_OPENVAS_SCOPE_IDS=` (empty), `NVIDIA_API_KEY`, `THREATFOX_API_KEY`, `NVD_API_KEY`, `JWT_SECRET`, `ENCRYPTION_KEY`, Supabase, Wazuh, ingest, SOAR |

**Deploy** (after the approved push):

```bash
git push origin <release commit>:refs/heads/release/novrsoc-p26
```

Then, in Render, either point the service at `release/novrsoc-p26` (Settings → Branch) and **Manual Deploy → Deploy latest commit**, or fast-forward the branch Render tracks to that commit and deploy it.

```bash
curl -fsS https://novrsoc.onrender.com/health    # "version" must be the release commit's first 12 characters
```

## 5. Vercel (frontend)

- Deploy the same commit. Only the Sources page changed (MISP run window and backfill button).
- `NEXT_PUBLIC_BACKEND_URL=https://novrsoc.onrender.com` (unchanged).

## 6. Worker VPS (worker 1.8.2)

Follow `docs/runbooks/deploy-vms-worker-1.8.2.md`:

- **Pre-checks:** section 0.
- **Deploy only while idle:** section 1.
- **Deploy:** section 3, Option A, after the push. `9c92f6d` is in this release:
  ```bash
  cd /opt/novrsoc-vms && ./deploy.sh 9c92f6d51b39b04d50b1426b6c5579a75a11d3a6
  ```
- **Expected `worker.py` hash:** `f5d3c9b686d262e5a35be54a62ff7b1d829cc94a0499d68ceed275fb413fc513`. It was checked to match this release.
- **Evidence contract:** the backend's evidence validation is unchanged from production, and both sides pass the shared contract (`infra/vms-worker/fixtures/evidence-targets.json`).
- **Worker environment:** unchanged.
  - `NOVRSOC_API_URL=https://novrsoc.onrender.com`.
  - `VMS_WORKER_KINDS` as in the 1.8.2 runbook (OpenVAS not advertised).
- **No scan is started by the deployment.**

## 7. After deploying (read-only)

- `curl -fsS https://novrsoc.onrender.com/health`: the release version.
- **Sources** (as a manager) → MISP → **Check capabilities**: 2.5.50, key can write: no.
- **Sources** → MISP → **Run now**: Current, with counts and "backfill since … · N page(s)".
- **Organisation isolation of the IOC cache:** two accounts in different organisations each see only their own lookups on *IOC Lookup* and in the STIX download.
- **Worker:** VMS → Monitoring shows 1.8.2 online. The next discovery job stores its evidence (no `Invalid evidence` in `journalctl`).

## 8. Rollback

- **Backend / frontend:** redeploy `9429743` on Render and Vercel.
  - The migrations stay; they are additive.
  - Note that `9429743` reads the IOC cache without an organisation filter, so the exposure returns with a rollback.
- **Worker:** section 5 of `deploy-vms-worker-1.8.2.md` (`rollback.sh`).
