# Deploying phases P1–P8 (branch `build/p1-security`)

This runbook covers the unified SecOps, Vulnerability Management and Threat Information work:
security fixes, staff sign-in, audit, approvals, the AI service, VMS Releases 1–3, the Threat
Information System and weekly insights. Nothing in it has been deployed, and none of the SQL has
been applied.

## 1. Before you start

- **Stellar forwarding:** confirm `STELLAR_PUSH_ENABLED` on Railway is absent or `false`. This
  branch does not change it.
- **Signing secret:** `JWT_SECRET` must be set on Railway. There is no fallback any more: without
  it, nobody can sign in.
- **Backups:** take a Supabase backup (or note the point-in-time-recovery timestamp).

## 2. Apply the SQL (Supabase SQL editor), in this order

Each file is additive and idempotent: it only creates tables, columns and functions, never drops
or rewrites data. Apply all of them **before** deploying the code. The code already deployed keeps
working, because it does not use the new objects.

| # | File | Creates |
|---|---|---|
| 1 | `backend/sql/2026-10-14_p1_quarantine.sql` | `alert_quarantine` — alerts whose Wazuh group maps to no organisation, or to several |
| 2 | `backend/sql/2026-10-14_p2_identity_audit.sql` | password columns on `platform_users`, `auth_links`, `audit_log` |
| 3 | `backend/sql/2026-10-14_p3_secops_ai.sql` | alert triage columns, `alert_events`, `cases.due_at`, `response_approvals`, `ai_requests`, `ai_artifacts` |
| 4 | `backend/sql/2026-10-14_p4_vms_asm.sql` | `vms_scopes`, `vms_scan_jobs`, `vms_assets`, `vms_services`, `vms_technologies`, `vms_asset_events`, `vms_claim_job()` |
| 5 | `backend/sql/2026-10-14_p5_vms_findings.sql` | `cve_intel`, `vms_findings` and their evidence, events and remediation tasks, `vms_wazuh_sync` |
| 6 | `backend/sql/2026-10-15_p6_threat_info.sql` | `ti_*` tables; seeds the four feeds |
| 7 | `backend/sql/2026-10-16_p7_vms_continuous.sql` | `vms_scan_schedules`, `vms_risk_snapshots`, `vms_notify_state` |

**Earlier files:** if `2026-10-11_push_state.sql` (Stellar push) was never applied, apply it too.

**Retention:** if pg_cron is enabled, schedule the purges each file suggests in its last lines:

```sql
SELECT cron.schedule('purge-alert-quarantine', '30 3 * * *', $$SELECT public.purge_alert_quarantine(14)$$);
SELECT cron.schedule('purge-audit-and-links', '45 3 * * *', $$SELECT * FROM public.purge_audit_and_links()$$);
SELECT cron.schedule('purge-threat-info', '15 4 * * *', $$SELECT * FROM public.purge_threat_info()$$);
SELECT cron.schedule('purge-vms-history', '30 4 * * *', $$SELECT * FROM public.purge_vms_history()$$);
```

## 3. Railway variables

Variables marked *required* are needed for that feature to work at all. Everything else has a
safe default.

| Variable | Purpose | Default if unset |
|---|---|---|
| `JWT_SECRET` | Signs sessions. *Required.* | sign-in fails |
| `FRONTEND_URL` | Base URL for one-time password links (`https://novr-soc.vercel.app`). *Required for invites/resets.* | links cannot be built (503) |
| `DEV_ADMIN_LOGIN_ENABLED` | Break-glass shared admin login. Set it to `false` once staff have their own passwords. | on (if `DEV_ADMIN_EMAIL`/`DEV_ADMIN_PASSWORD` are set) |
| `NVIDIA_API_KEY` | NVIDIA API Catalog key (`nvapi-…`, from build.nvidia.com) for summaries, reports, plans, assessments, insights and NovrAI chat. *Required for AI.* Server-side only. | AI panels say "unavailable"; NovrAI chat falls back to Gemini if `GEMINI_API_KEY` is set |
| `AI_MODEL` / `AI_FALLBACK_MODEL` / `AI_TIMEOUT_MS` | NVIDIA model id, optional model to retry a refusal on, and timeout | `nvidia/nemotron-3-super-120b-a12b` / none / 120000 |
| `RESPONSE_ALLOW_SELF_APPROVAL` | Lets someone approve their own block or isolate request | `false` (a second person must approve) |
| `AUTO_CASE_ENABLED` (+ `AUTO_CASE_MIN_LEVEL`, `AUTO_CASE_GROUP_HOURS`, `AUTO_CASE_LOOKBACK_HOURS`, `AUTO_CASE_MAX_NEW_PER_RUN`) | Opens cases from stored alerts automatically | off |
| `ALERT_STALE_MINUTES` | When alert ingestion counts as stale on Platform Health | 60 |
| `VMS_WORKER_TOKEN` | Shared with the scanner worker; at least 32 characters (`openssl rand -hex 32`). *Required for scanning.* | worker calls refused |
| `NVD_API_KEY` | Faster NVD lookups for CVE details | slower, rate-limited lookups |
| `VMS_INTEL_ENABLED` | KEV/EPSS/NVD refresh and the Wazuh vulnerability sync | on (`false` turns it off) |
| `VMS_NOTIFY_ENABLED` | Email digests of attack-surface and finding changes to the SOC mailbox | off |
| `THREATFOX_API_KEY` | abuse.ch Auth-Key, used by ThreatFox and URLhaus | those two feeds fail with that reason; Feodo and KEV still run |
| `TI_ENABLED` | Threat feeds, expiry and correlation | on (`false` turns it off) |

Email for digests uses the existing provider settings (`EMAIL_ENABLED`, a provider key, and the SOC
recipient variables).

## 4. Deploy

1. Merge `build/p1-security` into `main`, or open a PR and merge it after review.
2. Railway redeploys the backend and Vercel redeploys the frontend.
3. Background jobs start only where mutating jobs are allowed (`announceJobPolicy`, production).

## 5. Verify (read-only)

Sign in as a super_admin and copy the session token from the browser's storage. Then, from
`backend/`:

```bash
NOVRSOC_API=https://novrsoc-production-1fb6.up.railway.app NOVRSOC_TOKEN=<token> npm run verify:deployment
```

The script only sends GET requests and never prints the token. It reports one of four results per
check:

| Result | Meaning |
|---|---|
| `PASS` | The endpoint answered as expected |
| `NOT SET UP` | The SQL for that phase is missing, or the route is not deployed |
| `FAIL` | Anything else, including a protected route that answers without a token |
| `SKIPPED` | No token was given |

A `PASS` means the endpoint answered as expected at that moment. It does not mean the feature has
been used, or that its external services work.

**Before this branch was deployed:** an anonymous run against production on 2026-10-15 showed that
`/api/assets` answered without a token (HTTP 200). The P1 fix closes that, so re-run the script
after deploying to confirm it now returns 401.

Then check by hand:
- **Platform Health:** pipelines show real states: Alert ingestion, Quarantine, Threat feeds, VMS
  scanner, CVE intelligence.
- **Staff passwords:** under **Customers → account**, issue a password link to each staff member.
  Once everyone has signed in with their own password, set `DEV_ADMIN_LOGIN_ENABLED=false`.
- **Wazuh Groups (super_admin):** map every Wazuh group that carries alerts, including `default`,
  to an organisation. Then replay the quarantine.
- **Threat Information System:** after about 2 minutes, Feodo and KEV show "current". ThreatFox
  and URLhaus show "failing" until `THREATFOX_API_KEY` is set.

## 6. External setup

1. **Scanner worker host:** follow `infra/vms-worker/README.md`. You need a dedicated VM with
   subfinder, dnsx, httpx, nmap and nuclei, and optionally Greenbone/OpenVAS. Give clients its
   egress IP.
2. **Authorised scope:** a SOC manager adds each client's domains and ranges, with the
   authorisation reference (letter of authority) and an expiry date. Nothing is scanned outside
   that scope.
3. **abuse.ch:** get a free Auth-Key at https://auth.abuse.ch/ and set it as `THREATFOX_API_KEY`.
4. **NVD (optional):** request an API key at https://nvd.nist.gov/developers/request-an-api-key.

## 7. Rollback

- **Code:** redeploy the previous `main` commit on Railway and Vercel. The old code ignores the
  new tables and columns.
- **SQL:** leave it in place. It is additive and unused by old code. Do not drop tables that hold
  audit or remediation history.
- **Switching features off:** each background feature can be stopped without a redeploy:
  - `TI_ENABLED=false` (threat feeds)
  - `VMS_INTEL_ENABLED=false` (CVE intelligence and Wazuh sync)
  - leave `VMS_NOTIFY_ENABLED` and `AUTO_CASE_ENABLED` unset (digests, automatic cases)
  - stop the scanner worker service (scanning)
