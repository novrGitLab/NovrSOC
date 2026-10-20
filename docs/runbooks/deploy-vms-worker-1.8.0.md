# Deploying the Nmap observation fix and VMS worker 1.8.0 (Greenbone adapter, health report)

**Status:** not deployed. Nothing below has been run against the VPS or Railway. Each stage needs approval, and each stage can be rolled back on its own.

## What changes

| Part | Change | Effect |
|---|---|---|
| Backend (`services/vmsIngest.ts`) | Service observations accept `cpe: null` | Fixes the Nmap "invalid observations". Worker 1.7.0 sent `cpe: null` for every service nmap gave no CPE, the backend rejected it, and the job still "succeeded" with those services missing from inventory |
| Backend (`vmsIngest.ts`, `vmsFindings.ts`) | Results answers include `invalid_reasons`: the field and rule, never the value; at most 5. Rejections are logged as `[vms] job <id>: N observation(s) rejected as invalid: …` | A rejection is explained, not just counted |
| Worker 1.8.0 | Omits `cpe` instead of sending `null`; keeps the backend's `invalid_reasons` in the job summary and logs them once | The fix holds even against an old backend |
| Worker 1.8.0 | The hardened Greenbone adapter for `vuln_openvas` ([vms-openvas.md](vms-openvas.md)) | Off until `vuln_openvas` is added to `VMS_WORKER_KINDS`. Greenbone is contacted only then, or when `GVM_USER` is set |
| Worker 1.8.0 | `worker.py --health [--json]` | Health by layer; see "Health report" below |
| Worker scripts | `audit-greenbone.sh` (read-only), `verify-tools.sh` (socket check) | Operator checks |

**Compatibility, checked by running both parsers on the same nmap output** (one host with an SSH service with a CPE, two open web ports and one closed port without a CPE):

| | Old backend | New backend |
|---|---|---|
| Worker 1.7.0 | 3 of 5 invalid (the reported incident: 4 of 5) | 0 invalid |
| Worker 1.8.0 | 0 invalid | 0 invalid |

So the backend can go first: it fixes the running 1.7.0 worker without touching the VPS.

**No new Railway variable, no SQL migration and no frontend change.**

## Stage 0: audit (read-only, before anything else)

Copy `infra/vms-worker/audit-greenbone.sh` to the VPS and run it:

```bash
sudo bash audit-greenbone.sh 2>&1 | tee greenbone-audit.txt
```

It installs, changes, restarts and scans nothing, and prints no secret.

It answers what this plan cannot assume:
- whether Greenbone runs natively or in containers;
- where the gvmd socket is, and whether the worker user can reach it;
- the python-gvm version, and the gvmd and GMP versions;
- the effective `expand_vhosts` / `safe_checks`;
- the Greenbone users and scanners;
- whether any Greenbone port is exposed.

The Greenbone part of stage 3 is written from that output.

## Stage 1: backend (Railway)

1. **Deploy:** merge to `main` with approval. Railway deploys from `main`; check that the deploy succeeded in the Railway dashboard.
2. **Verify:**
   ```bash
   curl -fsS https://<backend>/health              # backend process up (not proof the VMS path works)
   ```
   Then on the VPS, as root:
   ```bash
   sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; python3 /opt/novrsoc-vms/worker.py --check'
   ```
   Queue one `ports` scan of an authorised test asset you own (VMS → Scans). Then:
   - the job summary shows `rejected_invalid: 0`, and no `invalid_reasons`;
   - the asset's services include the open ports **without** a CPE (e.g. `http`, `https`), not only those with one;
   - the Railway log has no `[vms] job … rejected as invalid` line for that job.
3. **Rollback:** redeploy the previous Railway deployment, or revert the commit. The only effect is that worker 1.7.0's `cpe: null` services are rejected again.

## Stage 2: worker 1.8.0, Greenbone still off

`VMS_WORKER_KINDS` is not changed in this stage, so OpenVAS stays off.

1. **Backup:**
   ```bash
   sudo install -d -m 700 /opt/novrsoc-vms/backups/manual-$(date -u +%Y%m%dT%H%M%SZ)
   sudo cp -a /opt/novrsoc-vms/worker.env /opt/novrsoc-vms/backups/manual-*/worker.env   # deploy.sh does not back up worker.env
   ```
2. **Deploy:**
   ```bash
   cd /opt/novrsoc-vms && sudo ./deploy.sh <git ref>
   ```
   `deploy.sh` backs up `worker.py` and the unit file. It then runs the new worker's `--self-test` as the service user against the real backend, and installs nothing if that fails. Finally it restarts the service, waits for `version 1.8.0` and `connected` in the journal, and rolls back by itself if they do not appear.
3. **Verify:**
   ```bash
   systemctl is-active novrsoc-vms-worker
   journalctl -u novrsoc-vms-worker --since -10min -o cat | grep -E 'version 1\.8\.0|connected'
   sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; python3 /opt/novrsoc-vms/worker.py --health'
   ```
   `--health` must show no `FAIL` for the worker, its tools or the backend. Greenbone shows `n/a` (not configured). Then repeat the stage 1 port scan: `rejected_invalid: 0`.
4. **Rollback:**
   ```bash
   sudo /opt/novrsoc-vms/rollback.sh /opt/novrsoc-vms/backups/<stamp printed by deploy.sh>
   ```

## Stage 3: enable Greenbone (written after stage 0; every step needs approval)

The general steps are in [vms-openvas.md](vms-openvas.md). For a container install, these differ, and are settled from the audit output:
- **Socket path and access:** the socket is in a Docker volume under `/var/lib/docker`. That directory is root-only, so adding a group may not be enough; it may need a compose change, which must be backed up first.
- **Creating the NovrSOC Greenbone user:** run inside the gvmd container.
- **Vhost expansion:** use a cloned scan configuration with `expand_vhosts = no`. The worker cannot read `openvas.conf` inside the container.

In outline:
1. **Back up** `worker.env` (as in stage 2). If the compose file is changed, back that up too.
2. **Dependency:** install `python3-gvm`. It is the client library only, not a second Greenbone.
3. **Configuration:** add `GVM_SOCKET`, `GVM_USER`, `GVM_PASSWORD` and `GVM_CONFIG_ID` to `worker.env`. Do not add `vuln_openvas` yet.
4. **Verify without scanning:**
   ```bash
   sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; python3 /opt/novrsoc-vms/worker.py --health'
   ```
   Every Greenbone row must be `OK` or an understood `WARN`. A feed that is syncing, or a few days old, is a warning.
5. **Integration test** (below). Only after it passes, add `vuln_openvas` to `VMS_WORKER_KINDS` and restart the worker.
6. **Rollback:** remove `vuln_openvas` from `VMS_WORKER_KINDS` (and the `GVM_*` lines if wanted), then `systemctl restart novrsoc-vms-worker`. The other kinds are unaffected.

## Health report (`worker.py --health [--json]`)

One row per component and layer. A component is never reported healthy because its process runs, its socket exists or its port answers.

| Layer | Evidence required |
|---|---|
| `local` | Configured and installed, e.g. the tool is on PATH, the socket exists and this user may use it |
| `reachability` | The service answered: the backend sent an HTTP reply; gvmd answered GMP and gave its version |
| `authentication` | Credentials accepted: the worker token; the GVM user's login |
| `functional` | It does its job: the tool reports its version when run; the heartbeat was recorded; gvmd verified the scanner (`verify_scanner`, which reaches ospd-openvas); the scan configuration passes the safety gate; feed versions and ages, and whether a feed is syncing; NovrSOC tasks in Greenbone and their states |
| `end_to_end` | Always `not_checked` here. Only a completed, authorised job whose results the backend accepted proves it |

- **Exit code:** 1 if any row is `FAIL`.
- **Side effects:** sends one heartbeat to the backend, the same as `--check`. Towards Greenbone it is read-only: nothing is created and nothing is scanned.
- **Secrets:** none is printed.

## Integration test against an authorised target (manual; never part of the automated tests)

- **Preconditions:**
  - an owned test host, with written permission;
  - one IP scope entry for it, allowing vulnerability scans;
  - every assessment policy disabled;
  - `--health` clean.
- **Run:** queue one `vuln_openvas` scan of that IP from VMS → Scans.

Pass when all of the following hold:
1. **Progress:** shows the Greenbone status and percentage, e.g. `Running 40%`.
2. **Job result:**
   - the job succeeds, with `openvas.task_id` and `openvas.report_id` in its summary;
   - `openvas.unattributed` is 0, or explained;
   - `rejected_invalid` is 0.
3. **Findings:**
   - source OpenVAS, on that IP;
   - each with an NVT OID, severity and CVSS, CVEs where the NVT names them, and a solution;
   - evidence holding the task, report and result ids.
4. **Outcome:** the target's outcome is `reachable_open`.
5. **Clean-up:** no `novrsoc-<job id>` task or target remains in GSA.
6. **Re-run:** queuing the same scan again updates the same findings; it creates no duplicates.
7. **Cancel:** cancelling a third run stops the task in Greenbone, and the job ends `cancelled`.

Record the job ids and the evidence. Until then, end-to-end is unverified.
