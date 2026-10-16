# Deploying P16: shared findings, Wazuh integration, verified closure, OSV, worker 1.6.0

Branch `feat/vms-platform`, on top of P13–P15 ([deploy-p13-p14-vms-platform.md](deploy-p13-p14-vms-platform.md)). **Nothing here has been deployed, and the P16 migration has not been applied.**

## What it changes

**Cross-source CVE correlation**
- Built in `services/vmsCorrelation.ts`, worked out from stored records each time it is read. There is no link table, so re-ingesting cannot duplicate a link.
- **Confirmed:** findings on the same asset that share a CVE.
- **Inferred:** a Wazuh endpoint whose agent reports address A, and the scanned IP asset A. This is the existing linked-records relationship.
- **Never linked:** two assets that only share a CVE; a hostname resolving to an address; anything across organisations.
- Each link names the shared CVEs, the relationship and the record values it rests on.
- Nothing is merged. Each finding keeps its source, asset, severity, timestamps, evidence and status.

**Wazuh Vulnerabilities page** (`/admin/secops/vulnerabilities`)
- **Default view, Shared findings:** reads `GET /api/vms/wazuh/vulnerabilities`. This uses `vms:read` and returns only the caller's organisation (the old endpoint is not filtered by organisation).
- **Freshness states:** `not_synced`, `never_complete`, `incomplete` (showing the last complete sync), `stale` (over 3 h) and `fresh`.
- **No complete sync means no totals at all,** rather than zeros.
- **Each row shows** the package and version from the newest Wazuh evidence, and links to the same CVE found elsewhere.
- **Live indexer tab:** the previous view is kept. `GET /api/wazuh/vulnerabilities` now answers HTTP 502 with the reason (`problem`) instead of zeros when the indexer returns an error or no index matches.

**Wazuh sync**
- When a package version changes but the CVE is still present: same finding, new evidence row, title updated. Earlier evidence is kept.

**Verified closure**
- **The rule:** a verification rescan verifies a finding only if it succeeded, did not detect the issue, **and shows it reached the target** (`summary.target_outcomes[target]` reachable, or job outcome `assessed`).
- **Otherwise** the finding stays "fixed, awaiting verification", and its history says why.
- **Before this change,** a rescan that never reached the host would have closed the finding.

**Worker 1.6.0**
- Before running Nuclei, the worker checks reachability: a TCP connection to the job's ports (the finding's port for a verification), or 443 and 80. A routing check comes first.
- **Unreachable targets** are not scanned. The job succeeds with outcome `unreachable`, so the Full Assessment shows the check as **inconclusive**.
- **Private addresses without a route** are reported as `no_route`, as before.

**Period report** (`GET /api/vms/report`)
- **`closure`:**
  - verified by rescan and verified by Wazuh, counted separately;
  - marked fixed by people, which is a claim;
  - awaiting verification;
  - verification attempts that proved nothing;
  - tasks completed, split by whether their findings were verified;
  - risk accepted and false positive, counted separately;
  - reopened after verification;
  - examples, with the evidence text.
- **`coverage`:**
  - inventory by source;
  - latest checks, reached or not;
  - Full Assessments by status, by check status and by what started them.
  - **Without the P13 migration,** this says "not set up".

**OSV**
- The CVE intelligence job looks up each tracked CVE at `GET https://api.osv.dev/v1/vulns/<CVE>`. It stores the related ids and the fixed versions per package.
- **Limits:** 15 s timeout per request, 250 ms between requests, 50 per run, refresh after 7 days.
- **On HTTP 429** it stops for the run.
- **Errors and timeouts store nothing**, so the CVE is retried next run. A failed lookup is never stored as "no record".
- OSV runs after KEV, EPSS and NVD and can't affect them. It never changes risk, priority or status.
- **Shown in:** the finding detail and VMS Admin.

## Migration

`backend/sql/2026-10-22_p16_osv.sql`
- **Contents:** nullable columns on `cve_intel` (`osv_ids`, `osv_summary`, `osv_affected`, `osv_status`, `osv_fetched_at`), its own check constraint and an index. No row changes value.
- **Not required by anything else in P16.** Without it:
  - the OSV step reports "OSV is not set up (run sql/2026-10-22_p16_osv.sql)" and stores nothing;
  - VMS Admin shows OSV as "not set up";
  - everything else works.
- **Depends on** P5 (`cve_intel`), which is present in production.
- **Re-runnable:** yes.
- **Rollback:** the backend ignores the columns. To remove them, use the `DROP COLUMN` statement in the file header.

The other P16 changes need no SQL. They use the P13 tables where present (coverage) and say "not set up" where absent.

## Staged deployment

Do one stage at a time. Don't go on until the gate passes.

| Stage | Action | Gate (all must hold) | Rollback |
|---|---|---|---|
| 0 | P13–P15 deployed and checked, as in its runbook | Its stage-4 checks pass | That runbook's rollback |
| 1 | Merge P16 into `main`; Railway and Vercel deploy. **Leave worker 1.5.0 running** | (a) `/health` shows the merge commit. (b) The Shared findings view shows a freshness state that matches VMS Admin's Wazuh line. Before a complete sync it shows no totals. (c) The Live indexer tab still loads, or shows "could not read" with a reason. (d) Findings detail shows "Same CVE elsewhere" for the `rayneops` ↔ `10.88.1.139` pair, if both have the CVE, labelled **inferred**. (e) The period report shows the Verified closure and Assessment coverage sections | Redeploy the previous `main` (no data written by P16 needs undoing) |
| 2 | Apply `2026-10-22_p16_osv.sql` in the Supabase SQL editor | `select osv_ids, osv_status, osv_fetched_at from cve_intel limit 0;` succeeds. After the next 6-hourly intel run, the Railway log line shows `OSV done (n found, m none)` or `rate_limited`. VMS Admin shows an OSV time | Leave the columns; or drop them with the statement in the file |
| 3 | Worker 1.6.0 on the VPS: `./verify-tools.sh`, then `./deploy.sh main` | `deploy.sh` reports version 1.6.0 and connected. VMS Admin shows v1.6.0 | `./rollback.sh` |
| 4 | Only after the Nuclei validation runbook: a verification rescan on the authorised test asset | Unreachable: the finding stays "awaiting verification", with the reason in its history. Reached and clean: verified, with "which reached …" in its history | Disable `vuln_nuclei` again |

**Between stages 1 and 3:** worker 1.5.0 reports no reachability for Nuclei, so a verification rescan can't verify anything. The finding stays "awaiting verification", with "worker before 1.6.0" as the reason. This is intended: no closure without evidence. Nuclei is not enabled in production, so nothing changes in practice.

## Not changed

- Nuclei stays out of `VMS_WORKER_KINDS` until [vms-nuclei-validation.md](vms-nuclei-validation.md) has passed.
- OpenVAS stays unavailable.
- Automatic policies stay disabled.
- No scans were run while building this.
