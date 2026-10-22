# Release: NovrSOC on Render (`deploy/novrsoc-render`)

Hosts NovrSOC on Render while Railway is unavailable. Same Supabase database, same secrets,
same behaviour as `main` at `adc82f3`, plus Render deployment config. **OpenVAS stays disabled.**

Nothing in this runbook deploys anything by itself: `render.yaml` sets `autoDeploy: false`, and
every step below is done by a person.

## 1. Release manifest

Base: `adc82f3` (local `main`). Production today (Railway `/health`): `c0fa465`.

| Commit | Content | Tests |
|---|---|---|
| `7f5c50b` | P20 VMS redesign: eight-section VMS, `/api/vms/insights` (dashboard, risk, audit, tasks, AI plans), risk-history snapshot columns | backend suite, nav check |
| `1ea9529` | Responsive app shell (off-canvas sidebar below `lg`), Header lint fix | lint, build |
| `cf7f53a` | `/api/vms/overview` in one round of queries (median 10.0 s → 3.1 s) | backend suite |
| `c1425f5` | P21: analysts limited to assigned organisations, `/api/org-access`, client-portal VMS (`/client/vms`), portal tokens confined to `/api/client/` | permissions and route tests |
| `00e977a` | VMS organisation picker from `/api/org-access/mine` | build |
| `1b78d58` | P22: OpenVAS ingestion pipeline, execution policy (`lib/openvasPolicy.ts`), CVSS version/vector, worker 1.8.1 | `openvasIngest.test.ts`, `test_openvas_report.py` |
| `e79f382` | P23: CNII national drill-down (`/api/cnii/national`, `/admin/cnii/...`) | `cniiNational.test.ts` |
| `adc82f3` | OpenVAS data path to CNII under the policy; worker 1.8.1 runbook | `openvasIngest.test.ts` (15) |
| release commit | Render config: `render.yaml`, `/health` and VMS admin version read `RENDER_GIT_COMMIT`, `tsx` pinned in the Dockerfile, OpenVAS policy vars in `.env.example`, this runbook | full suites below |

The OpenVAS policy code is identical to `deploy/openvas-policy` (`eb0aa53`); its `.env.example`
lines are included here.

**Not included** (unfinished, or not reviewed for this release):

- P24 Wazuh sources / tenancy, OPNsense and client SecOps work: uncommitted in the shared checkout and on
  `backup/wazuh-tenancy-wip` (`45b605f`). The P24 *SQL* is already applied in production (it is additive,
  and `c0fa465` runs on it today), so this release is unaffected. P24 code can follow as one commit on top
  of this branch once it is finished and the user approves.
- `worker-1.8.1.py` at the shared checkout's root (a local copy, not part of the repository).

## 2. Validation (in the release worktree)

| Check | Result |
|---|---|
| Backend `tsc --noEmit` | pass |
| Backend `npm run build` | pass |
| Backend `npm test` | 580 tests: 577 pass, 0 fail, 3 skipped |
| Frontend `tsc --noEmit` | pass |
| Frontend `npm test` | 13/13 pass |
| Frontend `npm run check:nav` | 99 nav links and 21 VMS section pages resolve |
| Frontend lint, VMS / CNII / client VMS / layout / config | clean |
| Frontend lint, whole `src` | 31 problems (18 errors, 13 warnings), **all in files unchanged since `c0fa465`** (already in production) |
| Frontend `npm run build` | pass (120 static pages) |
| `render.yaml` | parses: backend 35 vars, frontend 3 |
| `/health` | 200 `{"status":"healthy","version":"<RENDER_GIT_COMMIT[0:12]>"}` |
| Startup guard | `NOVRSOC_ENV` unset → refuses to start on the production DB; `production` + `NOVRSOC_DISABLE_JOBS=true` → starts, jobs off; `=false` → starts, jobs on |
| Docker image | **not built locally** (no Docker here). Same Dockerfile Railway builds today; only change is `tsx@4.23.11` (the lockfile's version, exists on npm). The first Render build is the check. |

## 3. Database migrations

No migration is required by this release. All but one are already in production (read-only check):

| Migration | Production | Needed by |
|---|---|---|
| P6–P19 (VMS, CNII, OSV, submissions) | applied | already in production |
| `2026-10-26_p20_vms_insights.sql` | applied | VMS dashboard, risk history |
| `2026-10-27_p21_staff_org_assignments.sql` | **not applied** | analysts' cross-org access (see below) |
| P24 Wazuh sources | applied | not used by this release |

**Decision before go-live: P21.** Production today lets analysts open any organisation. This release
limits analysts to organisations assigned in `staff_org_assignments`; while the table is missing,
analysts keep their own organisation and every other one returns 403 (fail closed, audited).
super_admin, soc_manager and client accounts are unaffected. Either:

- apply `backend/sql/2026-10-27_p21_staff_org_assignments.sql` (additive) and add each analyst's
  organisations before switching traffic, or
- accept that analysts work in their own organisation only until it is applied.

## 4. Environment

`render.yaml` declares every variable. Values marked `sync: false` are entered in the Render dashboard,
**copied from Railway**, never committed. They must be the same values as production:

- `JWT_SECRET`: otherwise every session and portal token is invalid.
- `ENCRYPTION_KEY`: otherwise stored integration secrets cannot be decrypted.
- `VMS_WORKER_TOKEN`, `ALERT_INGEST_TOKEN`, `SOAR_ENGINE_TOKEN`: must match the worker, forwarder and SOAR engine.

Fixed in `render.yaml`:

- `NOVRSOC_ENV=production` is required. Without it the backend refuses to start against the production database.
- `VMS_OPENVAS_ENABLED=false` and `VMS_OPENVAS_SCOPE_IDS=""`: no OpenVAS scan can be queued or claimed.

**Scheduled jobs run on one host only** (`NOVRSOC_DISABLE_JOBS`):

- Railway down, Render serving: `false` on Render.
- Railway still running its jobs: `true` on Render.
- When Railway comes back while Render runs the jobs: stop Railway's (set `NOVRSOC_DISABLE_JOBS=true` there) before it restarts, or both run them.

Copy any other variable Railway has (threat-intel keys, SMTP, SpiderFoot, M365, `TI_ENABLED`,
`VMS_INTEL_ENABLED`, `AUTO_CASE_ENABLED`, …) as-is. `render.yaml` lists the main ones only.

Frontend:

- `NEXT_PUBLIC_BACKEND_URL` = the Render backend URL. It is inlined at build time: a change needs a rebuild. Without it the frontend calls Railway.
- `NEXT_PUBLIC_GOOGLE_CLIENT_ID` stays the same. Add the Render frontend origin to that Google OAuth client's authorised JavaScript origins.
- On the backend, set `FRONTEND_URL` to the Render frontend URL (CORS). `*.vercel.app` stays allowed.

## 5. Connected services to repoint

These call the backend URL and keep calling Railway until changed:

| Service | Setting |
|---|---|
| VMS scanner worker (VPS) | `NOVRSOC_API_URL` in its env file, then restart the worker |
| SOAR / alert forwarder | `NOVRSOC_BACKEND` |
| Vercel frontend (if kept) | `NEXT_PUBLIC_BACKEND_URL`, then redeploy |

Worker 1.8.0 and 1.8.1 both work with this backend. Do not change the worker's OpenVAS settings.

**Known issue, not caused by this release:** alert ingest has stored nothing since
2026-10-16 07:21 UTC (production is on `c0fa465`). Check the forwarder after repointing it, but do not
expect this release to fix it.

## 6. Go-live checklist

1. Create the Blueprint from `render.yaml` on branch `deploy/novrsoc-render`; enter the `sync: false` values.
2. Decide P21 (section 3) and `NOVRSOC_DISABLE_JOBS` (section 4).
3. Deploy the backend by hand. Then `curl https://<backend>/health` returns `200` with the release commit's first 12 characters.
4. Read the backend log for `[env] Scheduled jobs ENABLED` or `DISABLED`, and check that it matches step 2.
5. Deploy the frontend (after the backend URL is known). Then sign in, and open `/admin/vms`, `/admin/cnii` and one client portal account's `/client/vms`.
6. Confirm OpenVAS is off. In VMS, the OpenVAS engine (from `/api/vms/operations`) must read
   "Switched off on this server (VMS_OPENVAS_ENABLED)…", and OpenVAS must not be selectable when
   requesting a scan. Do not request a scan.
7. Repoint the worker and forwarder (section 5). Confirm the worker heartbeat in VMS → Monitoring.

## 7. Rollback

The release changes no data, so rollback is only about where traffic goes:

- **Render, bad deploy:** Render dashboard → service → Deploys → redeploy the previous deploy.
- **Back to Railway** (once it is available): it still runs `c0fa465` on the same database.
  1. Point the worker's `NOVRSOC_API_URL` and the forwarder's `NOVRSOC_BACKEND` back to Railway.
  2. Point the frontend's `NEXT_PUBLIC_BACKEND_URL` back to Railway, or use the Vercel frontend.
  3. On Render, set `NOVRSOC_DISABLE_JOBS=true` or suspend the service, so jobs do not run twice.
- **If P21 was applied:** the table is unused by `c0fa465`, so leave it in place. Do not drop tables or delete records.

## 8. GO / NO-GO

**GO for the code:** every check in section 2 passes, OpenVAS is off by policy and configuration, and the release
contains only committed, tested work.

**Before go-live, the operator must:**

- decide P21 (section 3);
- choose which host runs jobs (section 4);
- copy the secrets from Railway exactly;
- confirm the first Render Docker build succeeds (it was not built locally).
