# Greenbone / OpenVAS on the VMS worker (worker 1.8.0)

**Status:** Greenbone Community Edition runs in Docker Compose on the VPS (`/root/greenbone-community-container`). Its GMP socket is mounted for the worker at `/run/novrsoc-gvm/gvmd.sock`, and the worker uses `/opt/novrsoc-vms/gvm-venv/bin/python` (python-gvm 27.10.1, GMP 22.7) with the dedicated `novrsoc-worker` account. Connectivity, authentication and read access (scanners, scan configurations, port lists) are verified. Task creation, the worker integration and an end-to-end scan are **not** verified yet; that is steps 5 and 6 of [deploy-p19-vms-automation.md](deploy-p19-vms-automation.md). Worker 1.8.0 is not deployed, and `vuln_openvas` is not in `VMS_WORKER_KINDS`.

## How it connects

```
Railway backend  <── HTTPS, outbound only ──  VPS: novrsoc-vms-worker ── /run/gvmd/gvmd.sock (GMP) ──> gvmd ──> ospd-openvas ──> targets
```

- **Outbound only:** the worker polls Railway outbound, exactly as for discovery, ports and Nuclei. Railway never connects to the VPS, so nothing new is exposed.
- **Local socket:** the worker reaches gvmd over its **local Unix socket** with python-gvm. It needs no network port.
- **Keep Greenbone's ports private:**
  - GSA (9392/443) and gvmd's TLS port (9390) stay bound to localhost or firewalled, for example with `ufw deny 9392`.
  - Reach the web UI only through your SSH tunnel.
  - Check with `sudo ss -tlnp | grep -E ':(9390|9392|443)\b'`: anything listening on `0.0.0.0` or a public address there must be closed.
- **If Greenbone ever runs on a different host from the worker:** do not open GMP to the internet. Run a second worker on the Greenbone host (same `worker.py`, its own `VMS_WORKER_ID`, only `vuln_openvas` in its kinds). It polls Railway outbound in the same way. That keeps "nothing inbound" true and needs no adapter change.

## What the worker enforces

**Authorisation, in order:**
1. **Backend, when queueing:** the scope is active and unexpired, it allows vulnerability scanning, and every target is inside it. A CNII-pinned domain must resolve within its approved addresses. A range with exclusions cannot be queued whole.
2. **Worker, before submission:** the same scope checks, again. Each name is then resolved, and the target is refused if:
   - it does not resolve;
   - any address is private or non-public and outside `VMS_WORKER_NETWORKS` (so DNS cannot point the scanner into an internal network);
   - it is a CNII-pinned name resolving outside its approved addresses.

   Refused targets get an outcome with the reason. If none is left, the job fails with that reason.
3. **Greenbone receives exactly those targets.** Nothing is broadened: no subdomains and no extra addresses.
4. **Scan configuration gate:** the job is refused before anything is created unless:
   - **safe checks** are not off;
   - **vhost expansion is confirmed off** (`expand_vhosts`), read from the scan configuration or, if it is not set there, from `/etc/openvas/openvas.conf`. OpenVAS turns it on by default; when on, it adds hostnames it learns from reverse DNS and TLS certificates and tests those too.
5. **Results:**
   - A result is kept only if it maps to a submitted target: the submitted name at an address it resolved to, a submitted IP, or an address inside a submitted range.
   - Results for hosts OpenVAS found by itself are dropped and counted (`openvas.unattributed` in the job summary).
   - The worker drops anything out of scope before sending, and the backend re-checks every result against scope.

Nothing queues a scan because an address appears in Wazuh. Scans are queued only by a person with `vms:scan`, by a schedule or assessment a person created, or by a verification rescan of a finding.

**Lifecycle:**
- **Naming:** one task and one target per job, both named `novrsoc-<job id>`. Only objects with that exact name are ever stopped or deleted.
- **Resume after a crash:** when a job is re-sent to the worker, it reuses that job's task instead of scanning twice. A running task is resumed, a finished one is reported. A task for different targets, or one that ended badly, is stopped and replaced.
- **Status polling:** every `GVM_POLL_SECONDS` (30). A gvmd hiccup is tolerated up to 5 consecutive failed checks.
- **Time limit:** after `GVM_SCAN_TIMEOUT_SECONDS` (4 h) the task is stopped and the job fails with the reason.
- **Retries:** submission and report download are retried up to 3 more times (5 s, 15 s, 45 s), and only for transient failures (socket errors, gvmd 5xx). Authentication failures and refused requests are reported at once.
- **Cancel or stop:** cancelling the scan in NovrSOC, or stopping the service, stops the Greenbone task.
- **Clean-up:** when the job ends, the task (with its report) and the target are deleted. Findings are stored in NovrSOC first.
- **Report:** XML format, `apply_overrides=0 min_qod=70` (Greenbone's own quality threshold), all rows. Log, debug and false-positive results are not findings.

**Normalised into the existing findings schema** (`vms_findings`, deduplicated per organisation, asset, port and lowest CVE, else the NVT OID):
- **Copied straight across:** host or target, port and protocol, NVT OID, title, CVSS, CVE ids, description, solution, and reference URLs.
- **Severity:** derived from CVSS.
- **Evidence, per sighting:** task id, report id, result id, scan configuration, scanned IP, reported hostname, QoD and detection time.
- **Job evidence:** a bounded summary of what was scanned, kept 30 days.

**Outcomes:** each target gets one of three outcomes from the report:
- **reachable_open:** OpenVAS scanned it and at least one port produced a result.
- **insufficient_evidence:** it was scanned, but no port result came back, so closed and filtered can't be told apart.
- **unreachable:** OpenVAS did not report the host at all.

For a verification rescan, the finding's own port must have answered. Otherwise the finding stays "fixed, pending verification" instead of being closed on a scan that never reached it.

## Settings (`/opt/novrsoc-vms/worker.env`, chmod 600)

| Variable | Default | Meaning |
|---|---|---|
| `GVM_SOCKET` | `/run/gvmd/gvmd.sock` | gvmd's socket. Community container installs expose it elsewhere, e.g. the `gvmd_socket_vol` volume |
| `GVM_USER` / `GVM_PASSWORD` | none | A dedicated NovrSOC Greenbone user. Secret: this file only, never Railway, never the repository |
| `GVM_CONFIG_ID` | `daba56c8-…` "Full and fast" | Must pass the safety gate |
| `GVM_SCANNER_ID` | `08b69003-…` "OpenVAS Default" | |
| `GVM_PORT_LIST_ID` | `33d0cd82-…` "All IANA assigned TCP" | |
| `GVM_OPENVAS_CONF` | `/etc/openvas/openvas.conf` | Read only to confirm `expand_vhosts` when the configuration does not set it |
| `GVM_SCAN_TIMEOUT_SECONDS` | `14400` (minimum 600) | Whole scan |
| `GVM_POLL_SECONDS` | `30` (minimum 10) | Status checks |
| `GVM_SOCKET_TIMEOUT_SECONDS` | `300` (minimum 30) | One GMP call; large reports can be slow |
| `GVM_ALIVE_TEST` | unset (configuration default) | e.g. `Consider Alive` for hosts that drop ping. Unknown values fail the self-test |

Nothing is configured on Railway for OpenVAS: no new Railway variable, no backend change and no database change.

## Setup (on the VPS, with approval: each step changes the host)

**Production VPS:** steps 1–3 are already done differently, and must not be redone:
- the client library is in `/opt/novrsoc-vms/gvm-venv`;
- the socket is mounted at `/run/novrsoc-gvm/gvmd.sock` (no docker group, Docker directory permissions untouched);
- the `novrsoc-worker` account exists.

Start at step 4, and follow [deploy-p19-vms-automation.md](deploy-p19-vms-automation.md) steps 4–6.

1. **Client library:**
   ```bash
   sudo apt-get install -y python3-gvm
   sudo -u novrsoc-vms python3 -c 'import gvm; print(gvm.get_version())'
   ```
   If gvmd speaks a newer GMP version than the packaged python-gvm knows, the self-test says "update python-gvm". Then install a newer release for the service user's Python.
2. **Socket access:**
   ```bash
   ls -l /run/gvmd/gvmd.sock                              # note its group, e.g. _gvm or gvm
   sudo usermod -aG <that group> novrsoc-vms
   ```
   The group takes effect on the next service start.
3. **A dedicated Greenbone user:** not `admin`. Use the "User" role, which may create and run its own targets and tasks.
   ```bash
   sudo -u _gvm gvmd --create-user=novrsoc --role=User   # prints a generated password once
   ```
   Put the user and password in `worker.env` and nowhere else.
4. **Turn vhost expansion off.** Either:
   - clone "Full and fast" in GSA, set the scanner preference `expand_vhosts` to `no` (and check `safe_checks` is `yes`), then set `GVM_CONFIG_ID` to the clone's id; or
   - set `expand_vhosts = no` in `/etc/openvas/openvas.conf` and restart `ospd-openvas`.

   The clone is preferred: it changes nothing for scans people run in GSA.
5. **Deploy worker 1.8.0** without enabling the kind yet: `sudo ./deploy.sh <ref>`. Its preflight runs `--self-test` as the service user.
6. **Check Greenbone end to end**, without scanning anything:
   ```bash
   sudo /opt/novrsoc-vms/verify-tools.sh
   sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; VMS_WORKER_KINDS=vuln_openvas python3 /opt/novrsoc-vms/worker.py --self-test'
   ```
   It prints the GMP version, the scanner, the port list, and the scan configuration with its safety verdict. Every `FAIL:` line must be fixed before going on.
7. **Validate on one asset you own:** follow the "Before you start" and "Authorise the test asset" steps of [vms-nuclei-validation.md](vms-nuclei-validation.md), with:
   - an owned test host;
   - one IP scope entry allowing vulnerability scans;
   - every assessment policy disabled.

   Then add `vuln_openvas` to `VMS_WORKER_KINDS`, restart the worker, and queue **one** `vuln_openvas` scan of that IP.

   Expect:
   - the progress to show the task status and percentage;
   - findings with source OpenVAS;
   - the outcome "reachable — open ports";
   - the Greenbone task gone from GSA afterwards.

## Troubleshooting

| Worker log / job error | Cause | Fix |
|---|---|---|
| `cannot talk to gvmd at …: Socket … does not exist` | gvmd not running, or a different socket path | `systemctl status gvmd`; set `GVM_SOCKET` |
| `no permission to use the gvmd socket` | Worker user not in the socket's group | Setup step 2, then restart the worker |
| `Greenbone rejected GVM_USER / GVM_PASSWORD` | Wrong credentials | Reset with `gvmd --user=novrsoc --new-password=…` and update `worker.env` |
| `Greenbone could not process the request (GMP 503)` | gvmd busy, e.g. a feed sync holds its lock | Retried automatically. If it persists, wait for the sync (`greenbone-feed-sync` logs) |
| `Greenbone refused the request (GMP 404): Failed to find config/scanner/port_list` | An id does not exist here | Look up the ids in GSA; set `GVM_CONFIG_ID` / `GVM_SCANNER_ID` / `GVM_PORT_LIST_ID` |
| `OpenVAS scan refused: vhost expansion is on …` / `cannot confirm vhost expansion is off …` | The safety gate | Setup step 4 |
| `OpenVAS scan refused: … safe_checks off` | Configuration allows disruptive checks | Use a configuration with safe checks on |
| `the OpenVAS task ended as Stopped/Interrupted` | Stopped in GSA, or the scanner failed | `journalctl -u ospd-openvas`; `/var/log/gvm/gvmd.log`, `openvas.log` |
| `the OpenVAS scan did not finish within …` | Very slow target or scanner | Raise `GVM_SCAN_TIMEOUT_SECONDS`, or scan fewer targets per job |
| `Remote manager daemon uses an unsupported version of GMP … update python-gvm` | python-gvm older than gvmd | Install a newer python-gvm for the service user |
| Target outcome `no_route`: "resolves to 10.x…" | A public name resolving to a private address | Correct DNS, or run a worker inside that network |
| Target outcome `unreachable` | Nothing answered the alive test | Check from the VPS (`nc -vz <ip> 443`). For hosts that drop ping, consider `GVM_ALIVE_TEST=Consider Alive` |
| Job summary `openvas.unattributed` > 0 | Results for hosts not submitted (e.g. discovered vhosts) | Expected; they are dropped deliberately |
| A `novrsoc-<job id>` task left in GSA | The worker was killed (not stopped) mid-scan | Re-sending the job reuses it. Otherwise delete it in GSA |

Logs: `journalctl -u novrsoc-vms-worker`. They never contain the Greenbone password or the worker token: both are redacted from anything the worker logs or sends.
