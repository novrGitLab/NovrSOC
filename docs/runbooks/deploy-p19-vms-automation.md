# Deploying P19: automatic Wazuh VMS, scan profiles, scanner operations and worker 1.8.0

**Status:** implemented and tested locally. **Not deployed.** Nothing here has run against Supabase, Railway, Vercel or the VPS, and no real scan has been run. Each stage needs approval and has its own rollback.

## What this release does

| Area | Change |
|---|---|
| Wazuh endpoints | The sync stores OS, agent status, the agent's own keep-alive and groups. It matches agents by agent id, so a rename or reinstall keeps the asset, and records address and name changes as events |
| Scan eligibility | Each endpoint is evaluated: eligible only at an address inside the organisation's **agreed coverage** (an active authorised scope entry) that a worker can reach. Otherwise it is not covered, private with no scanner route, offline, has no address, or has a shared address (DHCP reuse, or NAT). The reason is stored and shown. A telemetry address alone never authorises a scan |
| Automation | Enabled assessment policies assess eligible endpoints with no per-scan approval. They keep the cooldown and per-run cap, and assess an endpoint early when its eligible address changes (trigger `event`). Each covered asset gets `next_scan_at` |
| Profiles | **Discovery** (discovery + top-1000 ports), **Standard** (+ Nuclei), **Full** (all TCP ports 1–65535 + Nuclei + OpenVAS). **Authenticated** is shown honestly: Wazuh agent-side detection is available, Greenbone credentialed checks are not. **Verification** stays per finding |
| Queue | Job priority: verification 80, manual 60, event 50, schedule 40, policy 30. The claim function orders by priority, then arrival, and stays `SKIP LOCKED` for several workers |
| API | `GET /api/vms/profiles`, `/operations`, `/services`, `/endpoints`; `POST /api/vms/eligibility/refresh`, `/scans/:id/retry`; `profile` on `POST /assessments` and on policies; `most_vulnerable_assets` on `/overview` |
| Frontend | New pages: Managed Endpoints, Services & Technology, Scanner Operations. Overview gains exposure by severity, KEV, overdue, endpoint coverage, active and failed scans, engine health and most vulnerable assets. Profile selectors on Assessments and VMS Admin policies. Endpoint agent detail and eligibility in Attack Surface. Deep links between the pages |
| Worker 1.8.0 | Greenbone adapter (see [vms-openvas.md](vms-openvas.md)), `--health [--gvm-permission-probe]`, GMP and feed state in the heartbeat (cached 6 h), Nmap `cpe` fix |
| `deploy.sh` | Keeps the interpreter the installed unit runs (e.g. `/opt/novrsoc-vms/gvm-venv/bin/python`). Keeps a locally changed unit unless `--update-unit` is given. Also backs up `worker.env` |

**Unchanged:** CNII, the Threat Information System, the worker job protocol, scope approval, and the permission model.

## Order

1. Supabase SQL → 2. backend (Railway) → 3. frontend (Vercel) → 4. worker 1.8.0 with OpenVAS still off → 5. Greenbone readiness → 6. authorised integration test → 7. enable OpenVAS → 8. agree coverage and enable policies.

The backend works before the SQL: it falls back to P18 behaviour and says "not set up". So steps 1 and 2 can be swapped, but run the SQL first.

## 1. Supabase

Run `backend/sql/2026-10-25_p19_vms_automation.sql` in the SQL editor (production project). It is additive and idempotent. Then check:

```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'vms_assets' AND column_name IN ('os','agent_status','agent_last_keepalive','agent_groups','scan_eligibility','next_scan_at');   -- 6 rows
SELECT column_name FROM information_schema.columns WHERE table_name = 'vms_scan_jobs' AND column_name = 'priority';                                                                               -- 1 row
SELECT pg_get_functiondef('public.vms_claim_job(text,text[])'::regprocedure) LIKE '%ORDER BY priority DESC, requested_at%';                                                                       -- true
SELECT conrelid::regclass, pg_get_constraintdef(oid) FROM pg_constraint WHERE contype = 'c' AND conrelid IN ('public.vms_assessments'::regclass, 'public.vms_assessment_policies'::regclass) AND pg_get_constraintdef(oid) ~ 'profile|trigger';
-- exactly one profile CHECK per table, listing discovery, standard, full; the trigger CHECK lists event
```

The migration changes no existing row. Existing jobs get priority 50 and existing assessments keep `profile = 'full'`. It was checked against a throwaway Postgres built from the repository's migrations: it applies, a second run changes nothing, data is preserved, and the claim order is as described.

**Rollback:** none needed to roll back the code, because the P18 backend runs on the P19 schema. If the claim order itself must revert, run the `vms_claim_job` definition commented at the end of the SQL file; it changes no data. Do not narrow the constraints or drop the columns.

## 2. Backend (Railway) and 3. frontend (Vercel)

Push the reviewed commit to `main` with approval. Railway deploys from `main`; confirm the frontend's Vercel project does too, or trigger its deployment.

```bash
curl -fsS https://novrsoc-production-1fb6.up.railway.app/health     # "version" must be the new commit
```

Signed in as an analyst, check each page:
- **Scanner Operations:** engines show the worker's real state.
- **Managed Endpoints:** shows the Wazuh endpoints with an eligibility state and reason each. The amber "not stored yet" note must be absent once step 1 ran.
- **Services & Technology:** loads.
- **Overview:** shows the new sections.

No new Railway variable is needed.

**Rollback:** redeploy the previous Railway deployment and Vercel deployment.

## 4. Worker 1.8.0, OpenVAS still off

The commit must be on GitHub (a pushed branch is enough). `deploy.sh` downloads `worker.py` from `raw.githubusercontent.com` at the ref you give it.

**Fetch the new `deploy.sh` first.** The copy already on the VPS is the old one: it always runs `python3` and overwrites the unit, which would revert the worker to `/usr/bin/python3`.

On the VPS, as root:

```bash
REF=<branch or commit>
cd /opt/novrsoc-vms
for f in deploy.sh rollback.sh audit-greenbone.sh verify-tools.sh; do curl -fsSL "https://raw.githubusercontent.com/novrGitLab/NovrSOC/$REF/infra/vms-worker/$f" -o "$f.new" && install -m 0750 "$f.new" "$f" && rm "$f.new"; done
bash audit-greenbone.sh > /root/greenbone-audit.txt 2>&1     # read-only
/opt/novrsoc-vms/gvm-venv/bin/python -c 'import requests, gvm; print("venv ok")'   # deploy.sh refuses to continue without requests
./deploy.sh "$REF"             # keeps /opt/novrsoc-vms/gvm-venv/bin/python; keeps a locally changed unit (shows the diff)
sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; /opt/novrsoc-vms/gvm-venv/bin/python /opt/novrsoc-vms/worker.py --health'
```

What `deploy.sh` does:
- **Interpreter:** prints `interpreter: /opt/novrsoc-vms/gvm-venv/bin/python`. It refuses to continue if `requests` cannot be imported there.
- **Backup:** backs up `worker.py`, `worker.env` and the unit.
- **Self-test first:** runs the new worker's `--self-test` before installing anything.
- **Automatic rollback:** rolls back by itself if the worker does not report `1.8.0` and `connected`.

`VMS_WORKER_KINDS` is unchanged in this step.

**Rollback:**
```bash
sudo /opt/novrsoc-vms/rollback.sh /opt/novrsoc-vms/backups/<stamp>
```

## 5. Greenbone readiness (no scan)

In `/opt/novrsoc-vms/worker.env`:
- **Socket:** `GVM_SOCKET=/run/novrsoc-gvm/gvmd.sock`, the existing mount. Do not recreate it, do not add the worker to the docker group, do not change Docker directory permissions.
- **Credentials:** `GVM_USER=novrsoc-worker`, and the password stays where it is.
- **Scan configuration:** clone "Full and fast" in GSA, set the scanner preference `expand_vhosts` to `no` and keep `safe_checks` at `yes`, then set `GVM_CONFIG_ID` to the clone. The worker refuses OpenVAS jobs until vhost expansion is confirmed off. In the container install it cannot read `openvas.conf`, so the scan configuration must say it.

Then:

```bash
sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; VMS_WORKER_KINDS=vuln_openvas /opt/novrsoc-vms/gvm-venv/bin/python /opt/novrsoc-vms/worker.py --health --gvm-permission-probe'
```

Every Greenbone row must be `OK`: reachability (GMP 22.7), authentication, scanner verified, scan configuration safe, feeds, and **permissions**. The permission probe creates a target for 192.0.2.1 (TEST-NET, never routed) and a task, deletes both, and **starts nothing**. It is the first check of the `novrsoc-worker` account's task-creation rights, which are not yet verified.

## 6. Authorised integration test (manual)

Follow "Integration test against an authorised target" in [deploy-vms-worker-1.8.0.md](deploy-vms-worker-1.8.0.md).

- **Target:** an owned test host, under one IP scope entry allowing vulnerability scans, with every policy disabled.
- **Run:** a Full Assessment of that IP from Assessments.
- **Pass:** the findings travel **scanner → worker → backend → database → frontend**:
  - findings with source OpenVAS appear on the Findings page, with CVE, CVSS, port, solution and the Greenbone task and report ids in their evidence;
  - Scanner Operations shows the job as assessed, not inconclusive;
  - nothing named `novrsoc-<job id>` is left in GSA.

Record the job ids. **Until this passes, end-to-end is unverified.**

## 7. Enable OpenVAS

Add `vuln_openvas` to `VMS_WORKER_KINDS`, then `systemctl restart novrsoc-vms-worker`. Scanner Operations shows Greenbone / OpenVAS as Available, with the GMP and feed state the worker reports.

**Rollback:** remove the kind and restart.

## 8. Wazuh-managed automation (per client organisation)

1. **Coverage:** record the agreed vulnerability-assessment coverage from the client's service agreement as authorised scope:
   - the client's public ranges or addresses, with the agreement reference and its end date;
   - private ranges only if a worker inside that network declares them in `VMS_WORKER_NETWORKS`.
2. **Endpoint check:** Managed Endpoints → **Re-evaluate**. Check the eligible count and the reasons for the rest.
3. **Policy:** VMS Admin → create a policy:
   - assets: Wazuh endpoints;
   - profile: Standard (or Full once OpenVAS passed step 6);
   - a cooldown, e.g. 168 h;
   - `max_per_run`.
   Policies are created disabled. **Run now** once and read the result: queued, cooldown, not eligible by reason, and blocked. Then enable it.

From then on:
- **New endpoints:** endpoints Wazuh reports in that organisation are assessed on the next hourly policy run, once eligible.
- **Re-assessment:** each endpoint is re-assessed after the cooldown, and early when its address changes. No per-scan approval is needed.

## Limits that remain

- **Credentials:** Greenbone credentialed (authenticated) checks are not supported; NovrSOC stores no scan credentials. Authenticated coverage comes from the Wazuh agent.
- **Private networks:** a private endpoint is only assessed by a worker inside its network. The public VPS reports such endpoints as "private, no scanner route".
- **NAT:** endpoints behind NAT that report the same public address are not scanned automatically, because the address would assess the gateway.
- **Cross-organisation view:** no "highest-risk organisations" view across clients. VMS views are per organisation, as the existing tenancy model requires.
- **Rendering tests:** the frontend has no component-rendering test framework. The new pages are verified by type-check, lint and production build only.
- **Unverified:** the integration scan (step 6), feed reporting from a real gvmd, and the permission probe against the real account. These need the VPS.
