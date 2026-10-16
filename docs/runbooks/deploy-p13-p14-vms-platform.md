# Deploying P13–P15: Full Assessment, policies, attack-surface map, VMS Admin, Wazuh check, worker 1.5.0

Branch `feat/vms-platform`. **Nothing here has been deployed.** Migrations P13 and P14 have **not** been applied. P15 (review fixes and the Wazuh integration check) needs no SQL.

## What it adds

**P13 — Full Assessment**
- An assessment groups every check of the profile for one asset: discovery, ports, Nuclei and OpenVAS.
- Each check is planned before dispatch against scope permissions, exclusions, worker kinds, tools, features and private-network routes. A check that cannot run is recorded as **not attempted** or **unsupported** with the reason, and never queued.
- Statuses are derived from the scan jobs.
- Submitting the same target twice returns the open assessment; retry keeps completed checks and their evidence.
- Includes a Markdown management report.
- Scope exclusions are enforced when queueing, at ingest, and by worker 1.4.0+. Jobs under a scope with exclusions go only to workers that announce `exclusions`.

**P14**
- **Attack-surface map:** built from stored records only. Every relationship is labelled **confirmed**, **observed** or **inferred**.
- **Linked records:** Wazuh endpoints and scanned addresses are linked ("same address", inferred), never merged.
- **Automatic assessment policies:** created disabled; managers only; audited; hourly, with a cooldown and a per-run cap; blocked assets are reported with the reason.
- **VMS Admin:** workers, policies, integration freshness, AI status, evidence retention and audit.
- **Overview:** coverage metrics.
- **`/health`:** reports the deployed commit.
- **Worker 1.5.0:** tool versions, `--self-test`, and deploy, rollback and tool-verification scripts.

**P15 — review fixes, no SQL**
- **Inconclusive checks:** a check that ran but could not reach the target (the worker reports `unreachable` or `insufficient_evidence`) is **inconclusive**. It is not counted as completed, it is retried, and the report says so.
- **Coverage:** "assessed" counts only targets the last scan actually reached.
- **No duplicates:** concurrent requests for one target create one assessment.
- **Cancel:** refused for a finished assessment. It never cancels an identical scan another request had already queued.
- **Policy runs:** each run tries at most 4 × the per-run cap of blocked assets and reports how many it left for later.
- **VMS Admin:** shows only the caller's organisation's policy results and audit entries. Before this fix, the hourly run's results for every organisation were visible.
- **Wazuh sync:**
  - An indexer error reply, or a missing `wazuh-states-vulnerabilities-*` index, is an **incomplete** sync, never "no vulnerabilities".
  - Freshness (VMS Admin, Platform Health, period report) is judged on the last **complete** sync.
- **Wazuh integration check:** VMS Admin → "Check Wazuh integration" (managers only, read-only, audited) reports:
  - the manager API version (`GET /` → `api_version`);
  - the agents in the organisation's mapped groups (`wazuh-monitoring-*`);
  - the presence of `wazuh-states-vulnerabilities-*` and the organisation's record count by severity;
  - sync freshness.

  Only counts are returned, never documents or credentials.

## Migration review (done before applying anything)

| | P13 `2026-10-20_p13_vms_assessments.sql` | P14 `2026-10-21_p14_vms_policies.sql` |
|---|---|---|
| Depends on | `vms_assets`, `vms_scopes`, `vms_scan_jobs` (P4), `vms_workers` (P10): all present in production | `vms_assessments` (P13): **P13 must be applied first** |
| Changes to existing tables | add columns only: `vms_scan_jobs.assessment_id` (nullable), `vms_scopes.exclusions` (default `{}`), `vms_workers.features` (default `{}`) | add columns only: `vms_assessments.trigger` (default `manual`) and `policy_id`, `vms_workers.tool_versions` (default `{}`) |
| New tables | `vms_assessments` (RLS on, service role only) | `vms_assessment_policies` (RLS on, service role only; `enabled` defaults to **false**) |
| Re-runnable | yes (`IF NOT EXISTS`, policy guarded) | yes (constraint dropped and re-added, policy guarded) |
| Effect on the running P12 backend | none (it neither reads nor writes the new columns) | none |
| Destructive statements | none | `DROP CONSTRAINT IF EXISTS vms_assessments_trigger_check` (its own constraint only) |

Foreign keys follow the existing pattern. `scope_id` has no `ON DELETE`, like `vms_scan_jobs.scope_id`; scopes are revoked, never deleted.

## Order

Each step can be done and checked on its own. Do them in this order.

### 1. Database

Run these in the Supabase SQL editor, in order. Both only add things.

1. `backend/sql/2026-10-20_p13_vms_assessments.sql`
2. `backend/sql/2026-10-21_p14_vms_policies.sql`

Check that they took effect: a zero-row select on each must succeed.

```sql
select id, trigger, policy_id from vms_assessments limit 0;
select exclusions from vms_scopes limit 0;
select features, tool_versions from vms_workers limit 0;
select id from vms_assessment_policies limit 0;
```

The backend runs without them. Assessments and policies then answer 503 and name the file; everything else is unchanged.

### 2. Backend and frontend

Merge `feat/vms-platform` into `main` and push. Railway and Vercel redeploy. Then run:

```bash
cd backend && NOVRSOC_API=https://novrsoc-production-1fb6.up.railway.app npm run verify:deployment
```

`Backend /health` must show `deployed <commit>` matching the merge. If it says "deployed version not reported", Railway is not exposing `RAILWAY_GIT_COMMIT_SHA`, and the version cannot be confirmed this way.

No new Railway variables are needed.

### 3. Worker

Do this only after step 2. Worker 1.4.0+ sends `features` and `tool_versions`, and a backend before P14 rejects them.

On the VPS, as root:

```bash
cd /opt/novrsoc-vms
curl -fsSL -O https://raw.githubusercontent.com/novrGitLab/NovrSOC/main/infra/vms-worker/deploy.sh
curl -fsSL -O https://raw.githubusercontent.com/novrGitLab/NovrSOC/main/infra/vms-worker/rollback.sh
curl -fsSL -O https://raw.githubusercontent.com/novrGitLab/NovrSOC/main/infra/vms-worker/verify-tools.sh
chmod +x deploy.sh rollback.sh verify-tools.sh
./verify-tools.sh                 # read-only: tools, versions, httpx sanity
./deploy.sh main                  # backup -> stage -> new worker --self-test -> install -> confirm, or roll back
```

`deploy.sh` installs nothing if the new worker's self-test fails. If the new worker doesn't report its version and a connection within 90 seconds, it restores the backup and restarts the previous worker. Roll back by hand at any time with `./rollback.sh` (newest backup) or `./rollback.sh /opt/novrsoc-vms/backups/<time>`.

### 4. Check it works

**Wazuh**
- In VMS Admin → Integrations, press **Check Wazuh integration**.
  - **"Working":** the manager version is shown, and the organisation's vulnerability records are counted.
  - **Anything else:** the result names the failing part (not configured, refused, no index, timeout).
- Record the manager version. This is the first live confirmation of the Wazuh version.

**Admin and Overview**
- **VMS Admin** shows the worker at v1.5.0 (v1.6.0 if `main` already includes P16; see [deploy-p16-shared-findings.md](deploy-p16-shared-findings.md)) with its tool versions and `exclusions` under "Enforces".
- **Overview** shows the coverage tiles.

**Asset Inventory**
- The Wazuh endpoint `rayneops` shows its map and its linked records.
- The ports scan of `10.88.1.139`, if there is one, appears under the endpoint's "Linked records".

**Assessments**
- Start one on an authorised **public** test target. Discovery and ports are queued; Nuclei and OpenVAS show **Unsupported**, with the reason, until enabled.
- A Full Assessment of `rayneops` (`10.88.1.139`) shows discovery and ports as **Not attempted**: no worker has a route to that network. This is correct.

## Worker environment (`/opt/novrsoc-vms/worker.env`, placeholders only)

```
NOVRSOC_API_URL=https://<backend-host>
VMS_WORKER_TOKEN=<same 32+ character value as Railway>
VMS_WORKER_ID=<unique id per host>
VMS_WORKER_KINDS=discovery,ports
VMS_WORKER_NETWORKS=
VMS_POLL_SECONDS=20
VMS_TOOL_TIMEOUT_SECONDS=3600
VMS_HTTPX_RATE=50
VMS_NMAP_MAX_RATE=300
VMS_NUCLEI_RATE=50
# VMS_HTTPX_PATH=/usr/local/bin/httpx     (if the Python httpx client is first on PATH)
```

- **`VMS_WORKER_NETWORKS`:** keep it empty on the public VPS. Set it only on a host with a real, tested route.
- **Nuclei:** add `vuln_nuclei` to `VMS_WORKER_KINDS` only after testing it against an authorised target under a scope entry that allows vulnerability scanning.
- **OpenVAS:** stays unavailable until Greenbone, its credentials (`GVM_USER`, `GVM_PASSWORD`, `GVM_SOCKET`) and `python-gvm` are installed and a test run has been ingested.

Python requirements are in `infra/vms-worker/requirements.txt`.

## Wazuh integration

Read-only, on the backend:

| What | Where | Variables (on Railway) |
|---|---|---|
| Agents → `endpoint` assets | `services/wazuhVulnSync.ts`, hourly | `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_PORT`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` (indexer: `wazuh-monitoring-*`) |
| Vulnerabilities → findings (`source_class wazuh`, `package_inventory`) | same | same (`wazuh-states-vulnerabilities-*`, the index layout Wazuh 4.8+ uses) |
| Raw Wazuh vulnerability page | `/admin/secops/vulnerabilities` | same |
| Agent API (endpoint pages, isolation) | `lib/wazuh.ts` | `WAZUH_HOST`, `WAZUH_PORT`, `WAZUH_USER`, `WAZUH_PASSWORD` |

**Organisations:** an agent belongs to an organisation through **Settings → Wazuh Groups**. Agents in unmapped groups are not synced.

**Least privilege:** give the indexer user read-only roles on those two index patterns only.

**Freshness:** `vms_wazuh_sync` holds the last sync per organisation. VMS Admin and Platform Health show it.

**Not verified here:** the live Wazuh version, and whether the vulnerability index is populated. This needs the credentials and network path the backend has; it was not tested from this workstation. After deployment, VMS Admin → **Check Wazuh integration** answers both from the backend.

## Recommended initial policy settings

All policies are created **disabled**.

| Policy | Assets | Cooldown | Per run | Notes |
|---|---|---|---|---|
| External hosts weekly | external | 168 h | 5 | Discovery and ports only, while the worker runs only those kinds. Only assets inside an authorised scope are assessed |
| Wazuh endpoints monthly | wazuh | 720 h | 5 | **Expect "not attempted (no route)"** until a worker inside the client network exists. The assessment records that honestly and the cooldown stops repeats |

Existing schedules (VMS → schedules) keep working. They remain the place for per-scope recurring scans.

## Rollback

- **Backend and frontend:** redeploy the previous `main` commit on Railway and Vercel. Old code ignores the new tables and columns.
- **Worker:** `./rollback.sh` on the VPS.
- **SQL:** leave it in place. If policies must stop at once, disable them in VMS Admin, or run `update vms_assessment_policies set enabled = false;`.

## Remaining blockers

- **Wazuh live test:** needs the backend's Wazuh indexer credentials and network path; not tested from here.
- **Private endpoints** (all six Wazuh agents have private addresses): need a worker inside each client network with a tested route. No change to configuration alone solves this.
- **Nuclei:** a test against an authorised target, then adding `vuln_nuclei` to the worker's kinds. The procedure is in [vms-nuclei-validation.md](vms-nuclei-validation.md).
- **OpenVAS:** not installed. It needs its own host (about 4 vCPU and 8 GB), Greenbone, credentials and an ingestion test.
- **Not built in this change set:**
  - OSV enrichment;
  - new notification types (KEV, coverage, deadlines);
  - report filters and new report types beyond the existing period report and the assessment report;
  - TLS/certificate checks;
  - administrator-assisted asset merge;
  - a scan-window and timezone policy.
