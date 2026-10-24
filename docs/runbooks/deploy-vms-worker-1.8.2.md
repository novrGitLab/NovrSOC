# Deploy VMS worker 1.8.2 (discovery evidence target fix)

**Scope.** This procedure replaces worker 1.8.1 with 1.8.2 on the Contabo VPS. It does not touch the backend, the Greenbone containers, the GMP socket, scopes or `worker.env`. **`VMS_WORKER_KINDS` stays `discovery,ports,vuln_nuclei`, so this deployment does not enable OpenVAS.**

**What changes.** Worker 1.8.1 sent discovery's httpx evidence with the target `','.join(probe)[:253]`, which causes two problems:

- **The 400 error.** When a domain has many subdomains, the 253-character cut leaves a fragment such as `...,portal.` or `s`. The backend correctly refuses it with `400 Invalid evidence: target not a host, IP or CIDR` (job `39ed0425-0ab2-4ccb-8edb-b21301dab3f2`).
- **Evidence lost for the rest of the job.** After the 400, `send_evidence` switches evidence off for the rest of the job. The job's structured results (hosts, DNS, HTTP) were still stored, but its raw httpx output and any later evidence were not.

A cut can also leave a name that is wrong but looks valid (`remote.example.tes`), which the backend would accept.

Worker 1.8.2 builds every evidence target from whole targets only:

- each part must pass the backend's own rule (`parseTarget` or `parseCidr`, with a prefix from 1 to the maximum);
- the whole target is at most 253 characters;
- it never posts a target that the backend contract refuses: it logs the problem and skips that evidence.

The contract is pinned in `infra/vms-worker/fixtures/evidence-targets.json`, which both the worker tests (`test_worker.py`, `EvidenceTarget`) and the backend tests (`vmsOutcomes.test.ts`) read. **Backend validation is unchanged.**

**Compatibility.** 1.8.2 uses the same request format as 1.8.1. It works with any backend that 1.8.1 works with: Render (`deploy/novrsoc-render`) and `main`. No dependency, setting, unit file or scan kind changes.

**Build.**

| | |
| --- | --- |
| Commit | `9c92f6d51b39b04d50b1426b6c5579a75a11d3a6` on branch `fix/vms-evidence-target`, on top of `main` `9429743` |
| `sha256(worker.py)` | `f5d3c9b686d262e5a35be54a62ff7b1d829cc94a0499d68ceed275fb413fc513` (LF line endings, as `git show` writes it) |
| Tests | worker: 114 pass (`python -m unittest test_worker test_greenbone test_openvas_report`); backend: 641 tests, 0 failures; `tsc --noEmit` clean |

**Never during this procedure:**

- add `vuln_openvas` to `VMS_WORKER_KINDS`;
- queue, start or re-run a scan, or start a task in GSA;
- run `--gvm-permission-probe` (it creates a target and a task);
- change scopes, `worker.env` or the backend's `VMS_OPENVAS_*` settings;
- print `worker.env`.

Each approval covers one step: the push in step 3 Option A, and the restart in step 3.

---

## 0. Read-only pre-checks (VPS, as root): record the output

```bash
systemctl is-active novrsoc-vms-worker
grep -oP "^VERSION = '\K[^']+" /opt/novrsoc-vms/worker.py                   # expect 1.8.1
sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' /etc/systemd/system/novrsoc-vms-worker.service   # expect /opt/novrsoc-vms/gvm-venv/bin/python
ls /etc/systemd/system/novrsoc-vms-worker.service.d/ 2>/dev/null
grep -E '^(NOVRSOC_API_URL|VMS_WORKER_ID|VMS_WORKER_KINDS|GVM_SOCKET)=' /opt/novrsoc-vms/worker.env   # none of these is secret
journalctl -u novrsoc-vms-worker --since -2h --no-pager -o cat | grep -E 'Invalid evidence|raw .* not kept|claimed|re-received|handed back|job .* (succeeded|failed|cancelled)' | tail -20
```

**Stop** in any of these cases:

- the service is not active;
- the version is not `1.8.1`;
- `VMS_WORKER_KINDS` contains `vuln_openvas`;
- `NOVRSOC_API_URL` is not the production backend (`https://novrsoc.onrender.com`, or whatever host the backend is currently served from).

## 1. Active jobs: deploy only while the worker is idle

The worker runs one job at a time. On restart, systemd sends SIGTERM (`KillMode=mixed`, `TimeoutStopSec=30`). The worker then stops the running tool and calls `POST /jobs/{id}/release`, which hands the job back to the queue. Results it has already sent stay stored. Consequences:

- **Each release counts as an attempt.** After `MAX_RELEASES` (3) attempts, the backend fails the job instead of requeueing it.
- **A released job restarts from the beginning,** so a released Nuclei job sends its requests to the target a second time.
- **If the release call fails,** the job stays assigned to this worker and is re-sent the next time the worker asks for work (`re-received unfinished`).

Interrupting a job is therefore safe, but the job's work is wasted. **Deploy when no job is running.** Two read-only ways to check:

```bash
# On the VPS: the last job line should be a completion, not "claimed" / "re-received"
journalctl -u novrsoc-vms-worker --since -24h --no-pager -o cat | grep -E "claimed|re-received|job [0-9a-f-]+ (succeeded|failed|cancelled|handed back)" | tail -5
```

```sql
-- Supabase SQL editor (read-only): jobs this worker holds, and jobs about to be claimed
select id, kind, status, claimed_at, heartbeat_at, attempts, progress->>'message' as progress
from public.vms_scan_jobs
where (status = 'running' and worker_id = '<VMS_WORKER_ID from step 0>')
   or status = 'queued'
order by created_at desc limit 20;
```

- **No running job for this worker:** go on to step 2.
- **A job is running:** wait for it to finish. Re-check every few minutes; a running discovery or Nuclei job shows `heartbeat_at` advancing. Do not cancel it to make room.
- **Queued jobs are waiting:** the worker claims the next one within seconds of becoming idle. If one is claimed between the check and the restart, step 3 hands it back once (attempts + 1), and the restarted worker claims it again. That is acceptable for `discovery` and `ports`. For a queued `vuln_nuclei` job, prefer to wait until it has finished.

Pausing schedules or the queue is not part of this procedure, because it would change production.

## 2. Greenbone health, read-only (VPS, as root): optional for this release

1.8.2 does not change any Greenbone code, so this step only records a baseline. `--health` is read-only towards Greenbone. It:

- logs in and reads the GMP version;
- verifies the scanner, the scan configuration (safe checks on, vhost expansion off) and the port list;
- reads each feed and its age, the NovrSOC task list and the report list;
- sends one heartbeat to the backend.

It creates, starts and deletes nothing in Greenbone. Run it inside the service's own sandbox:

```bash
systemd-run --wait --pipe --quiet --uid=novrsoc-vms --gid=novrsoc-vms \
  -p SupplementaryGroups="$(id -Gn novrsoc-vms | tr ' ' '\n' | grep -v '^novrsoc-vms$' | xargs)" \
  -p EnvironmentFile=/opt/novrsoc-vms/worker.env -p ProtectSystem=strict -p ProtectHome=true \
  -p PrivateTmp=true -p NoNewPrivileges=true -p ReadWritePaths=/opt/novrsoc-vms \
  /opt/novrsoc-vms/gvm-venv/bin/python /opt/novrsoc-vms/worker.py --health
```

Use `--health --json` for machine-readable output.

**Which rows count.** The Greenbone rows run only when `vuln_openvas` is in `VMS_WORKER_KINDS` or `GVM_USER` is set. Otherwise the output shows `greenbone local not_configured`, which is expected with the current kinds. When they do run, these rows must be `ok` before OpenVAS can ever be enabled:

- `greenbone local` (python-gvm present; socket present and usable);
- `reachability`;
- `authentication`;
- `scanner`;
- `scan configuration`;
- `port list`;
- each `feed`;
- `tasks`;
- `reports`.

Any `fail` blocks enabling OpenVAS, but it does not block this deployment.

## 3. Deploy worker 1.8.2 (approval required: restarts the service)

`deploy.sh` does the following:

- downloads the worker from GitHub by git ref;
- backs up the running files;
- runs the new worker's `--self-test` as `novrsoc-vms`, which claims nothing, before installing anything;
- restarts the service and confirms the version and the connection in the journal;
- rolls back by itself if that confirmation fails.

### Option A: after an approved push of commit `9c92f6d…` to GitHub (recommended)

```bash
cd /opt/novrsoc-vms     # or wherever deploy.sh / rollback.sh were copied
./deploy.sh 9c92f6d51b39b04d50b1426b6c5579a75a11d3a6
```

### Option B: without pushing (copy the committed file)

On the workstation:

```bash
git show 9c92f6d51b39b04d50b1426b6c5579a75a11d3a6:infra/vms-worker/worker.py > worker-1.8.2.py
sha256sum worker-1.8.2.py      # f5d3c9b686d262e5a35be54a62ff7b1d829cc94a0499d68ceed275fb413fc513
scp worker-1.8.2.py root@<VPS>:/root/worker-1.8.2.py
```

On the VPS, as root, run the same steps as `deploy.sh`, but from the local file:

```bash
set -euo pipefail
DIR=/opt/novrsoc-vms; UNIT=/etc/systemd/system/novrsoc-vms-worker.service; SVC=novrsoc-vms-worker
PY="$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$UNIT" | head -1)"
echo "f5d3c9b686d262e5a35be54a62ff7b1d829cc94a0499d68ceed275fb413fc513  /root/worker-1.8.2.py" | sha256sum -c -
B="$DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)"; install -d -m 700 "$B"
cp -a "$DIR/worker.py" "$DIR/worker.env" "$UNIT" "$B/"; echo "backup: $B"
install -o novrsoc-vms -g novrsoc-vms -m 0644 /root/worker-1.8.2.py "$DIR/worker-1.8.2.staged.py"
"$PY" -m py_compile "$DIR/worker-1.8.2.staged.py"
runuser -u novrsoc-vms -- bash -c "set -a; . '$DIR/worker.env'; set +a; '$PY' '$DIR/worker-1.8.2.staged.py' --self-test"   # must pass; claims nothing
# step 1 again, immediately before the restart: no running job for this worker
install -o novrsoc-vms -g novrsoc-vms -m 0755 "$DIR/worker-1.8.2.staged.py" "$DIR/worker.py"; rm -f "$DIR/worker-1.8.2.staged.py"
SINCE="$(date '+%Y-%m-%d %H:%M:%S')"; systemctl restart "$SVC"; sleep 20
journalctl -u "$SVC" --since "$SINCE" --no-pager -o cat | grep -E 'version 1\.8\.2|connected: the backend accepted|handed back'
```

Both the `version 1.8.2` line and the `connected` line must appear. A `handed back` line means a job was running after all: it is requeued, and the restarted worker claims it again. If the `version 1.8.2` or `connected` line is missing, roll back (step 5).

## 4. After deploying (read-only)

```bash
systemctl is-active novrsoc-vms-worker
journalctl -u novrsoc-vms-worker -n 30 --no-pager -o cat
```

In NovrSOC, under Scanner Operations → Worker Health, the worker should:

- show `v1.8.2` and be online;
- run Discovery, Ports and Nuclei, with OpenVAS **not** listed among its kinds.

**Proof of the fix.** The next discovery job that runs in the normal course of work shows its httpx evidence on the scan's Evidence tab, and the journal has no `Invalid evidence` line. No scan is started to prove this.

Job `39ed0425…` does not need a re-run for data integrity. Its structured results were stored; only its raw httpx output was not. Re-running it is a separate decision that needs its own approval.

## 5. Roll back

```bash
cd /opt/novrsoc-vms && ./rollback.sh "$B"        # or: ./rollback.sh  (newest backup)
```

To roll back by hand instead:

```bash
install -o novrsoc-vms -g novrsoc-vms -m 0755 "$B/worker.py" /opt/novrsoc-vms/worker.py && systemctl restart novrsoc-vms-worker
```

Rolling back restores 1.8.1 and its evidence bug, and nothing else. The same rule as step 1 applies: roll back while no job is running. `worker.env` is never changed by this procedure; its backup is in `$B`, a mode-600 directory.

---

## Why the worker advertises only `discovery,ports,vuln_nuclei`

This is by design, not a fault. The worker advertises exactly the kinds listed in `VMS_WORKER_KINDS` in `/opt/novrsoc-vms/worker.env` (`worker.py`: `KINDS = os.environ['VMS_WORKER_KINDS']`, default `discovery,ports`). The OpenVAS code is present but idle until `vuln_openvas` is listed. That was deliberately left out in the 1.8.0 and 1.8.1 deployments, because OpenVAS is not yet authorised.

Adding the kind alone would still not run OpenVAS scans, because the backend gates them separately (`backend/src/lib/openvasPolicy.ts`, on Render too):

- `VMS_OPENVAS_ENABLED` must be exactly `true`, and `VMS_OPENVAS_SCOPE_IDS` must list the approved scope UUIDs.
- In `render.yaml` both are unset, so the engine reports "Switched off". The backend refuses OpenVAS jobs when they are queued, and fails any that is claimed with `Not run: …` (audit `VMS_SCAN_REFUSED`).

When `vuln_openvas` is listed, the worker's `preflight` / `--self-test` also requires:

- `GVM_USER` and `GVM_PASSWORD` set;
- python-gvm importable by the unit's interpreter (`/opt/novrsoc-vms/gvm-venv/bin/python`);
- the gvmd socket `GVM_SOCKET` present and usable by `novrsoc-vms` (Contabo container install: the hardened path from the 1.8.1 runbook, step 2);
- `GVM_ALIVE_TEST`, if set, being one of the allowed values.

`GVM_CONFIG_ID`, `GVM_SCANNER_ID` and `GVM_PORT_LIST_ID` default to Full and fast, OpenVAS Default and All IANA TCP. Set them to the safe configuration and the restricted port list before enabling OpenVAS.

## Enabling OpenVAS later (not part of this deployment)

The sequence is unchanged from `deploy-vms-worker-1.8.1.md` ("Enabling OpenVAS later"): the provider's permission, a signed authorisation for the target scope, the backend switch for that one scope, step 2 all `ok`, then the kind added and one authorised test scan. The one difference is that the policy gate now ships with the deployed backend (Render), so step 3 of that list is an environment change, not a new backend deployment. Each item needs its own approval.
