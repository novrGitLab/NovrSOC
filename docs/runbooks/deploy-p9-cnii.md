# Deploying P9: CNII Watch on VMS and the Threat Information System

P9 rebuilds CNII Watch on top of the VMS scope, inventory and findings and the Threat Information System. It adds passive collection, evidence classes, OpenCTI and MISP feeds, and an AI sector briefing.

**Status:**
- Nothing here has been deployed.
- The SQL has not been applied.
- P9 builds on P1–P8. Follow [deploy-p1-p8.md](deploy-p1-p8.md) first.

## What changes for users

- **Old scanner removed.** The old IP scanner (`POST /api/cnii/scan`) is gone. It ran an active TCP port scan against any IP an analyst typed in, without recorded authorisation. SpiderFoot now runs passive modules only.
- **Organisations, not IPs.** CNII Watch now lists organisations classified into sectors. Their assets and findings are VMS records.
- **Scope required.** Nothing is collected about an organisation until a manager approves a scope entry with an authorisation reference and an expiry. A new entry can allow:
  - **Passive only:** third parties are asked about the target; nothing connects to it.
  - **Active discovery:** the scanner worker probes the target.
  - **Port and vulnerability scans:** each needs its own flag.

  An AS number can be registered for passive monitoring only.
- **Evidence classes on findings.** Every finding carries an evidence class. A CVE that Shodan reports from a software version is a `version_match`: it shows as unconfirmed and never rises above P3 until a scanner check confirms it.
- **Sector pages are for SOC staff.** Executives see only their own organisation, under **CNII Watch → My organisation**.
- **Old rows are imported, not shown.** Rows from the old `cnii_assets` table are no longer displayed as monitoring. A manager can import each one into an organisation once that organisation is classified and has a scope covering the address.

## 1. Before you start

- Apply the P1–P7 SQL first ([deploy-p1-p8.md](deploy-p1-p8.md), section 2). P9 alters P4, P5, P6 and P7 tables.
- Take a Supabase backup, or note the point-in-time-recovery timestamp.

## 2. Apply the SQL

Run `backend/sql/2026-10-17_p9_cnii.sql` in the Supabase SQL editor. It is additive and safe to re-run.

**Creates:**
- `cnii_org_profiles` and `cnii_profile_events`;
- `vms_observations`;
- the `vms_findings_evidence_default` trigger, which labels Wazuh findings `package_inventory` without any change to the Wazuh sync;
- the `opencti` and `misp` feed rows;
- the `purge_cnii_history()` function.

**Alters:**
- `vms_scopes`: adds `allow_discovery` (default `true`, so existing entries keep their meaning) and the `asn` kind.
- `vms_scan_jobs` and `vms_scan_schedules`: adds the `passive_osint` kind.
- `vms_assets`: adds the `asn` and `cidr` types and a `confidence` column.
- `vms_findings`: adds the `passive_intel` source and the `evidence_class` column. Existing Wazuh findings are backfilled as `package_inventory`.
- `cnii_assets`, only if that table exists: adds the import columns.

**Retention** (if pg_cron is enabled):

```sql
SELECT cron.schedule('purge-cnii-history', '45 4 * * *', $$SELECT * FROM public.purge_cnii_history()$$);
```

This removes observations not seen for 365 days. It also clears the old `cnii_assets` raw SpiderFoot and OpenCTI payloads after 30 days, because they can hold e-mail addresses and phone numbers.

## 3. Railway variables

Names only. Everything has a safe default.

| Variable | Purpose | If unset |
|---|---|---|
| `SPIDERFOOT_URL` | SpiderFoot web UI, used with passive modules only | passive collection runs without SpiderFoot; Platform Health shows it "off" |
| `SPIDERFOOT_USER`, `SPIDERFOOT_PASSWORD` | Basic auth for SpiderFoot behind a TLS reverse proxy | no credentials sent |
| `CNII_PASSIVE_ENABLED` | Passive collection runner | on (`false` turns it off) |
| `CNII_SPIDERFOOT_MAX_TARGETS` | SpiderFoot scans per passive job | 20 |
| `CNII_SPIDERFOOT_TIMEOUT_SECONDS` | Time limit per SpiderFoot scan | 300 |
| `OPENCTI_URL`, `OPENCTI_TOKEN` | OpenCTI IP lookups and the `opencti` indicator feed | not used; feed shows "not configured" |
| `MISP_URL`, `MISP_API_KEY`, `MISP_CA_CERT` | The `misp` indicator feed | feed shows "not configured" |
| `MISP_NIGERIA_EVENT_ID` | The event NovrSOC's collector writes to; the feed skips it | `1` |
| `TI_ENABLED` | All threat feeds and correlation | on |
| `NVIDIA_API_KEY`, `AI_MODEL`, `AI_FALLBACK_MODEL` | Sector briefing and the other AI purposes | AI panels say "unavailable" |

No Wazuh variable is needed by CNII.

## 4. Deploy

Merge `build/p1-security` once reviewed. Railway and Vercel redeploy. The passive runner starts with the other background jobs (production only, `announceJobPolicy`).

## 5. Verify (read-only)

```bash
NOVRSOC_API=https://novrsoc-production-1fb6.up.railway.app NOVRSOC_TOKEN=<token> npm run verify:deployment
```

Expected results:

| Check | Expected after P9 |
|---|---|
| Anonymous `/api/cnii/sectors` and `/api/cnii/inventory` | `PASS` (refused) |
| CNII Watch sectors (P9) | `PASS`, with counts. `NOT SET UP` means the P9 SQL is missing |
| CNII Watch profile (P9) | `PASS` |

Then check **Platform Health**:
- **CNII passive collection:** "Never run" until the first job.
- **SpiderFoot (passive)** and **OpenCTI connection:** `degraded` while their URLs are plain `http://` to a public address. This is expected until section 6.1 is done.
- **Threat feeds:** OpenCTI and MISP count only when configured.

## 6. Manual infrastructure and credential tasks

Each of these is a separate, reviewed operational change. None of them was done by this work.

### 6.1 Put SpiderFoot and OpenCTI behind TLS

Today both are reached over plain `http://`, so the OpenCTI token and all results cross the network unencrypted, and SpiderFoot sends no credentials.

On Server A, put a reverse proxy in front of both:
- TLS on both services;
- basic auth for SpiderFoot;
- an allowlist of the Railway egress addresses.

Then set `SPIDERFOOT_URL`/`OPENCTI_URL` to `https://`, and set `SPIDERFOOT_USER`/`SPIDERFOOT_PASSWORD`.

**Rollback:** restore the old proxy configuration and URLs.

**Test:**
- Unauthenticated access from outside is refused.
- Platform Health shows both `up`.
- A passive job's summary shows `spiderfoot ok`.

Before changing anything, check whether either interface is reachable from the internet today. If it is, treat that as a security issue in its own change.

### 6.2 SpiderFoot module keys

Configure Shodan, Censys, ipinfo and VirusTotal keys inside SpiderFoot (its own settings, not NovrSOC's). Without them those modules return nothing; the job still succeeds with the other sources.

### 6.3 OpenCTI user

Create a dedicated read-only OpenCTI user for NovrSOC and use its token as `OPENCTI_TOKEN`.

**Test:** `CNII_SMOKE=1 OPENCTI_URL=… OPENCTI_TOKEN=… npm test`. The live introspection test passes. Then run the `opencti` feed from the Threat Information overview and check that it records a run.

The indicator query was written for the OpenCTI 6 GraphQL schema and has not been run against the live instance. Confirm the server version first.

### 6.4 MISP

Confirm the API key belongs to an API-enabled user, and that `MISP.baseurl` is no longer `https://localhost` (see `backend/src/services/misp.ts`). Then run the `misp` feed once by hand.

### 6.5 Scanner worker

Follow `infra/vms-worker/README.md`:
- **Host:** a dedicated VM (2 vCPU / 4 GB). Not Server B (Wazuh), and preferably not Server A, which shares its egress IP with MISP and OpenCTI.
- **Tools:** subfinder, dnsx, httpx (set `VMS_HTTPX_PATH` explicitly), nmap, nuclei.
- **Token:** set the same `VMS_WORKER_TOKEN` on Railway.

The worker refuses passive-only scope entries itself.

### 6.6 Greenbone/OpenVAS (optional)

Only on its own host (about 4 vCPU / 8 GB plus disk for the feeds), and only if Nuclei coverage proves insufficient.

### 6.7 Server A resources

Before adding anything to Server A, check memory use per container (the Elasticsearch heap in particular) and why Tenzir is busy. Nothing in this repository uses Tenzir.

## 7. First use

1. **Classify.** CNII Watch → Organisations → open one → **Classify**: sector, sub-entity, and `designated` (with its reference) or `candidate`.
2. **Approve scope.** **Add scope**, with the authorisation reference and expiry. Choose **Passive only** unless active testing is authorised in writing.
3. **Collect.** Click **Collect now** on an active entry. The job appears under VMS scans; results appear on the organisation page within minutes. To repeat it, add a schedule (VMS → schedules, kind `passive_osint`, at least every 24 h).
4. **Import old rows.** On the overview, import each earlier record into its organisation once steps 1 and 2 are done.

## 8. Rollback

- **Code:** redeploy the previous `main` commit. The old code ignores the new tables and columns.
  - The old `/api/cnii` routes come back with it, including the active SpiderFoot scan. Set `SPIDERFOOT_URL` empty if you roll back.
- **Passive collection only:** `CNII_PASSIVE_ENABLED=false`. Queued passive jobs then wait; Platform Health says so.
- **OpenCTI/MISP feeds only:** unset their URL variables. They show "not configured".
- **SQL:** leave it in place. Do not drop `cnii_profile_events`, `vms_observations` or finding evidence: they are the history.
