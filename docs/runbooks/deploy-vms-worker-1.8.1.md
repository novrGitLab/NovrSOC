# Deploy VMS worker 1.8.1 (Greenbone report detail) — with socket hardening

**Scope.** Replaces worker 1.8.0 with 1.8.1 on the Contabo VPS. 1.8.1 changes only how an OpenVAS
report is read (CVSS version and vector, scan start/end, the reported threat level when a result has
no score) and adds a read-only report-list check to `--health`. No dependency, setting or scan kind
changes. **`VMS_WORKER_KINDS` stays `discovery,ports,vuln_nuclei`: this deployment does not enable
OpenVAS.**

**Compatibility.** The backend now on Railway (`c0fa465`) accepts 1.8.1's findings: its finding
schema ignores unknown fields, so `cvss_version` / `cvss_vector` are dropped until the P22 backend is
deployed (they then reach the finding detail). Nothing else in the worker ↔ backend exchange changes.

**Never during this procedure:** add `vuln_openvas` to `VMS_WORKER_KINDS`, start a scan or a task in
GSA, use `--gvm-permission-probe` (it creates a target and a task), change scopes, or print
`worker.env`. The backend on Railway (`c0fa465`) has **no OpenVAS policy gate**; the gate
(`VMS_OPENVAS_ENABLED` / `VMS_OPENVAS_SCOPE_IDS`) exists only in the unreleased `feat/vms-redesign`
backend. Until that backend is deployed, advertising `vuln_openvas` would let any scope with
`allow_vuln_scan` (all 23 current, unverified entries) receive OpenVAS jobs.

Worker 1.8.1 is commit `1b78d5802f7cccc9c1c9e75577f075cd204ace75`;
`sha256(worker.py) = d91456e5317a87dba0d028260fe81763624fa72398222707f54dfa6c9865d68d` (LF line endings).

---

## 0. Read-only pre-checks (VPS, as root) — record the output

```bash
systemctl is-active novrsoc-vms-worker
grep -oP "^VERSION = '\K[^']+" /opt/novrsoc-vms/worker.py                   # expect 1.8.0
sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' /etc/systemd/system/novrsoc-vms-worker.service   # expect /opt/novrsoc-vms/gvm-venv/bin/python
ls /etc/systemd/system/novrsoc-vms-worker.service.d/ 2>/dev/null
grep -E '^(VMS_WORKER_KINDS|GVM_SOCKET|GVM_CONFIG_ID|GVM_PORT_LIST_ID)=' /opt/novrsoc-vms/worker.env   # no secrets in these four
grep -cE '^GVM_(USER|PASSWORD)=.+' /opt/novrsoc-vms/worker.env                 # 2 = both set (values not shown)
runuser -u novrsoc-vms -- /opt/novrsoc-vms/gvm-venv/bin/python -c 'import gvm, requests; print("python-gvm", gvm.get_version())'
cd /root/greenbone-community-container && docker compose ps --format 'table {{.Name}}\t{{.State}}\t{{.Health}}'
```

**Stop** if `VMS_WORKER_KINDS` contains `vuln_openvas`, the service is not active, or a Greenbone
container is unhealthy.

## 1. Greenbone validation, read-only (VPS, as root)

`--health` logs in, reads the GMP version, verifies the configured scanner, reads the scan
configuration and checks it is safe (safe checks on, vhost expansion off), reads the restricted port
list, each feed and its age, the NovrSOC task list and (1.8.1) the report list. It creates, starts and
deletes nothing, and prints no secret. It needs `GVM_USER` / `GVM_PASSWORD` in `worker.env`.

Run it **inside the service's own sandbox** (same user, `ProtectSystem=strict`), so it proves what the
running service can do — not what root can:

```bash
systemd-run --wait --pipe --quiet --uid=novrsoc-vms --gid=novrsoc-vms \
  -p SupplementaryGroups="$(id -Gn novrsoc-vms | tr ' ' '\n' | grep -v '^novrsoc-vms$' | xargs)" \
  -p EnvironmentFile=/opt/novrsoc-vms/worker.env -p ProtectSystem=strict -p ProtectHome=true \
  -p PrivateTmp=true -p NoNewPrivileges=true -p ReadWritePaths=/opt/novrsoc-vms \
  /opt/novrsoc-vms/gvm-venv/bin/python /opt/novrsoc-vms/worker.py --health
```

(1.8.0 runs every check except `greenbone reports`; after step 3, 1.8.1 runs that too.)
Required rows: `greenbone reachability ok`, `authentication ok`, `greenbone scanner ok`,
`greenbone scan configuration ok`, `greenbone port list ok`, each `greenbone feed ok` (a `warn` for
an old feed blocks enabling OpenVAS, not this deployment), `greenbone tasks ok` (no leftovers).
`end_to_end not_checked` is expected. **Any `fail`: stop and fix before going on.**

## 2. GMP socket: restrict it to the worker (VPS, as root; approval required — changes the host)

Independent of the worker upgrade: it can be done before or after step 3, or on its own.

The worker connects to `/run/novrsoc-gvm/gvmd.sock`. A world-writable socket lets **any local
account** speak GMP — and log in with any credentials it holds. The aim: only `novrsoc-vms` (and root)
can reach it, **without** changing the socket's own mode, Docker directory permissions or anything
inside Greenbone's containers.

Why not change the socket's mode: the Greenbone Community containers create it world-writable on
purpose — gsad (the web UI) connects from another container as another user. Tightening the socket
file would risk breaking GSA, and gvmd re-creates the socket on every restart anyway. Why not bindfs:
a Unix socket cannot be connected through a FUSE mount.

**Design: restrict the path, not the socket.** Connecting to a socket needs search permission on
every directory above it. `/run/novrsoc-gvm` becomes a plain directory, mode `0750`, `root:novrsoc-vms`;
the Greenbone socket volume is bind-mounted **under** it at `/run/novrsoc-gvm/sock`. Other accounts
cannot traverse `/run/novrsoc-gvm`, so they cannot reach the socket; the worker can. The volume's
files and modes, and the containers, are untouched. The worker's socket path becomes
`/run/novrsoc-gvm/sock/gvmd.sock` (`GVM_SOCKET`, not a secret).

### 2a. Inspect (read-only)

```bash
stat -c '%A %U:%G (%u:%g) %n' /run/novrsoc-gvm/gvmd.sock /run/novrsoc-gvm
findmnt -T /run/novrsoc-gvm/gvmd.sock -o TARGET,SOURCE,FSTYPE,OPTIONS
grep -rln novrsoc-gvm /etc/systemd /etc/fstab /etc/tmpfiles.d 2>/dev/null     # how the current mount is made
docker volume ls --format '{{.Name}}' | grep -i gvmd_socket
docker volume inspect -f '{{.Mountpoint}}' "$(docker volume ls -q | grep -i gvmd_socket | head -1)"
```

**Continue only if** `findmnt` shows `/run/novrsoc-gvm` as a **bind mount of the gvmd socket
volume's `_data` directory** (TARGET `/run/novrsoc-gvm`, SOURCE ending in `…gvmd_socket_vol/_data`
or shown as `/dev/…[/…/_data]`). Anything else (a symlink, a different source, no mount): stop and
report what 2a printed — the steps below assume that layout.

Back up whatever creates the current mount (from the `grep` above):
`cp -a <file> <file>.bak-$(date -u +%Y%m%dT%H%M%SZ)`.

### 2b. Change

```bash
set -euo pipefail
VOL="$(docker volume inspect -f '{{.Mountpoint}}' "$(docker volume ls -q | grep -i gvmd_socket | head -1)")"
echo "volume: $VOL"; test -S "$VOL/gvmd.sock"

systemctl stop novrsoc-vms-worker                           # it holds no Greenbone task (KINDS has no vuln_openvas)
umount /run/novrsoc-gvm                                     # the current bind mount
# disable whatever created it (unit: systemctl disable --now <unit>; fstab: comment the line) — from 2a

# 1) restricted parent, re-created at every boot (/run is tmpfs)
printf 'd /run/novrsoc-gvm 0750 root novrsoc-vms -\nd /run/novrsoc-gvm/sock 0755 root root -\n' > /etc/tmpfiles.d/novrsoc-gvm.conf
systemd-tmpfiles --create /etc/tmpfiles.d/novrsoc-gvm.conf

# 2) bind the socket volume below it
UNITNAME="$(systemd-escape -p --suffix=mount /run/novrsoc-gvm/sock)"
cat > "/etc/systemd/system/$UNITNAME" <<UNIT
[Unit]
Description=gvmd socket volume for the NovrSOC worker (path restricted by /run/novrsoc-gvm, 0750 root:novrsoc-vms)
After=docker.service systemd-tmpfiles-setup.service
Requires=docker.service

[Mount]
What=$VOL
Where=/run/novrsoc-gvm/sock
Type=none
Options=bind

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now "$UNITNAME"

# 3) point the worker at the new path (non-secret line), keeping a backup of worker.env
cp -a /opt/novrsoc-vms/worker.env "/opt/novrsoc-vms/worker.env.bak-$(date -u +%Y%m%dT%H%M%SZ)"
sed -i 's#^GVM_SOCKET=.*#GVM_SOCKET=/run/novrsoc-gvm/sock/gvmd.sock#' /opt/novrsoc-vms/worker.env
systemctl start novrsoc-vms-worker
```

The worker runs as `novrsoc-vms`, whose primary group is `novrsoc-vms`, so it may traverse the
`0750` directory; no supplementary group or Docker group is needed.

### 2c. Verify

```bash
stat -c '%A %U:%G %n' /run/novrsoc-gvm /run/novrsoc-gvm/sock/gvmd.sock      # drwxr-x--- root:novrsoc-vms ; socket unchanged
runuser -u nobody -- test -e /run/novrsoc-gvm/sock/gvmd.sock && echo "STILL REACHABLE" || echo "closed to other accounts: ok"
runuser -u novrsoc-vms -- test -w /run/novrsoc-gvm/sock/gvmd.sock && echo "worker can reach it: ok"
# step 1 again (the systemd-run health check): every greenbone row ok
cd /root/greenbone-community-container && docker compose ps                # all healthy, nothing restarted
# optional, restarts gvmd (no scan is running): proves the path survives gvmd re-creating the socket
# docker compose restart gvmd && sleep 20 && test -S /run/novrsoc-gvm/sock/gvmd.sock && echo "survives a gvmd restart: ok"
```
and log in to GSA in a browser: it must still work (it never used this path).

### 2d. Roll back

```bash
systemctl stop novrsoc-vms-worker
systemctl disable --now "$(systemd-escape -p --suffix=mount /run/novrsoc-gvm/sock)"
rm -f "/etc/systemd/system/$(systemd-escape -p --suffix=mount /run/novrsoc-gvm/sock)" /etc/tmpfiles.d/novrsoc-gvm.conf
systemctl daemon-reload; rmdir /run/novrsoc-gvm/sock /run/novrsoc-gvm 2>/dev/null || true
# restore the previous mount from its backup (2a) and re-enable/mount it
cp -a /opt/novrsoc-vms/worker.env.bak-<time> /opt/novrsoc-vms/worker.env      # GVM_SOCKET back to /run/novrsoc-gvm/gvmd.sock
systemctl start novrsoc-vms-worker
```

## 3. Deploy worker 1.8.1

`deploy.sh` (already on the VPS, unchanged since 1.8.0) downloads the worker from GitHub by git ref,
backs up the running files, runs the new worker's `--self-test` as `novrsoc-vms` **before** installing,
restarts, confirms version and connection in the journal, and rolls back by itself if that fails.

### Option A — after an approved push of commit `1b78d58…` to GitHub (recommended)

```bash
cd /opt/novrsoc-vms     # or wherever deploy.sh / rollback.sh were copied
./deploy.sh 1b78d5802f7cccc9c1c9e75577f075cd204ace75
```

### Option B — without pushing (copy the committed file)

On the workstation:

```bash
git show 1b78d5802f7cccc9c1c9e75577f075cd204ace75:infra/vms-worker/worker.py > worker-1.8.1.py
sha256sum worker-1.8.1.py      # d91456e5317a87dba0d028260fe81763624fa72398222707f54dfa6c9865d68d
scp worker-1.8.1.py root@<VPS>:/root/worker-1.8.1.py
```

On the VPS, as root (the same steps as `deploy.sh`, from a local file):

```bash
set -euo pipefail
DIR=/opt/novrsoc-vms; UNIT=/etc/systemd/system/novrsoc-vms-worker.service; SVC=novrsoc-vms-worker
PY="$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$UNIT" | head -1)"
echo "d91456e5317a87dba0d028260fe81763624fa72398222707f54dfa6c9865d68d  /root/worker-1.8.1.py" | sha256sum -c -
B="$DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)"; install -d -m 700 "$B"
cp -a "$DIR/worker.py" "$DIR/worker.env" "$UNIT" "$B/"; echo "backup: $B"
install -o novrsoc-vms -g novrsoc-vms -m 0644 /root/worker-1.8.1.py "$DIR/worker-1.8.1.staged.py"
"$PY" -m py_compile "$DIR/worker-1.8.1.staged.py"
runuser -u novrsoc-vms -- bash -c "set -a; . '$DIR/worker.env'; set +a; '$PY' '$DIR/worker-1.8.1.staged.py' --self-test"   # must pass; claims nothing
install -o novrsoc-vms -g novrsoc-vms -m 0755 "$DIR/worker-1.8.1.staged.py" "$DIR/worker.py"; rm -f "$DIR/worker-1.8.1.staged.py"
SINCE="$(date '+%Y-%m-%d %H:%M:%S')"; systemctl restart "$SVC"; sleep 20
journalctl -u "$SVC" --since "$SINCE" --no-pager -o cat | grep -E 'version 1\.8\.1|connected: the backend accepted' 
```

Both lines must appear (started … version 1.8.1; connected). If not: roll back (step 5).

## 4. After deploying (read-only)

```bash
systemctl is-active novrsoc-vms-worker
journalctl -u novrsoc-vms-worker -n 30 --no-pager -o cat
```
Then step 1 again with the new worker: the `greenbone reports` row now appears and must be `ok`.
In NovrSOC (Scanner Operations → Worker Health): the worker shows `v1.8.1`, online, runs
Discovery, Ports and Nuclei; OpenVAS is **not** listed among its kinds.

## 5. Roll back

```bash
cd /opt/novrsoc-vms && ./rollback.sh "$B"        # or: ./rollback.sh  (newest backup)
```
or by hand: `install -o novrsoc-vms -g novrsoc-vms -m 0755 "$B/worker.py" /opt/novrsoc-vms/worker.py && systemctl restart novrsoc-vms-worker`.
`worker.env` is never changed by this procedure; its backup is in `$B` (mode 600 directory).

---

## Enabling OpenVAS later — not part of this deployment

All of these, in order; each needs its own approval:

1. Written permission from Contabo to run vulnerability scans from the VPS.
2. A target with a signed authorisation for intrusive scans, recorded as its scope's
   `authorization_reference`, `allow_vuln_scan` on. None of the 23 current scopes qualifies.
3. The `feat/vms-redesign` backend (OpenVAS policy, P22 ingestion) deployed to Railway, with
   `VMS_OPENVAS_ENABLED=true` and only that scope's id in `VMS_OPENVAS_SCOPE_IDS`.
4. Step 1 all `ok`, step 2 done.
5. `vuln_openvas` added to `VMS_WORKER_KINDS`, `GVM_CONFIG_ID` = the safe configuration,
   `GVM_PORT_LIST_ID` = the restricted port list; restart; `--self-test` passes.
6. One authorised scan of an owned test host; check the findings in VMS (CVSS version and vector,
   scan times, evidence) and, if its organisation has a CNII profile, in CNII.
