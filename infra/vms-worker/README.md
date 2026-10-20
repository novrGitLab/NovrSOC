# NovrSOC VMS scanner worker

The worker runs the scanning tools for the Vulnerability Management module. It polls the NovrSOC backend for scan jobs, runs the tools against each job's targets, and sends normalised results back.

It decides nothing about scope itself:
- the backend checks every target against the organisation's **approved scope** before queueing a job;
- the worker checks again before each tool runs;
- the backend checks every result again before storing it.

## 1. Host

Use a dedicated Linux VM (Ubuntu 22.04 or later), **not** the Wazuh server or the Railway backend.

- **Size:** 2 vCPU and 4 GB is enough for Release 1 (discovery and port scans). OpenVAS in Release 2 needs its own larger host.
- **Network:** outbound HTTPS to the backend, and outbound access to the targets you are authorised to scan. Nothing inbound.
- **Egress IP:** give clients and your hosting provider the worker's fixed egress IP, so authorised scans are recognised as yours.

## 2. Tools

```bash
sudo apt-get update && sudo apt-get install -y nmap python3 python3-requests
# ProjectDiscovery tools: install the current releases from https://github.com/projectdiscovery
# (subfinder, dnsx, httpx), e.g. with Go:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp ~/go/bin/{subfinder,dnsx,httpx} /usr/local/bin/
```

**Optional:** Subfinder finds more with API keys for its passive sources. They go in `~/.config/subfinder/provider-config.yaml` of the `novrsoc-vms` user. That is optional; it works without them.

## 3. Install

```bash
sudo useradd --system --home /opt/novrsoc-vms --shell /usr/sbin/nologin novrsoc-vms
sudo mkdir -p /opt/novrsoc-vms && sudo cp worker.py /opt/novrsoc-vms/
sudo cp worker.env.example /opt/novrsoc-vms/worker.env   # then fill it in
sudo chown -R novrsoc-vms:novrsoc-vms /opt/novrsoc-vms && sudo chmod 600 /opt/novrsoc-vms/worker.env
sudo cp novrsoc-vms-worker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now novrsoc-vms-worker
journalctl -u novrsoc-vms-worker -f
```

Set the **same** `VMS_WORKER_TOKEN` on Railway; it must be at least 32 characters (`openssl rand -hex 32`). While it is unset, the backend refuses every worker call.

### Health report

```bash
sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; python3 /opt/novrsoc-vms/worker.py --health'
```

This reports each dependency by layer: local, reachability, authentication, functional, and end-to-end. End-to-end is never claimed; only a real authorised job proves it. Add `--json` for machine-readable output. It exits 1 on any failure. See [deploy-vms-worker-1.8.0.md](../../docs/runbooks/deploy-vms-worker-1.8.0.md).

`audit-greenbone.sh` is a read-only audit of the Greenbone installation, native or containers. Run it before enabling `vuln_openvas`.

### Check the connection

```bash
sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; python3 /opt/novrsoc-vms/worker.py --check'
```

This sends one heartbeat and claims nothing. It prints `OK: the backend accepted worker …` with the number of queued jobs and which tools are installed, or `FAIL:` with the reason:

| Message | Meaning |
|---|---|
| `rejected the worker token (HTTP 401)` | `VMS_WORKER_TOKEN` here is not the value on Railway |
| `endpoint not found (HTTP 404)` | `NOVRSOC_API_URL` is wrong, or the backend predates this worker version |
| `not ready for workers (HTTP 503)` | Railway has no valid `VMS_WORKER_TOKEN`, or the presence SQL (`sql/2026-10-18_p10_vms_worker_presence.sql`) is not applied |
| `cannot reach the backend` | DNS, firewall or outbound HTTPS from this host |

### Scan outcomes (worker 1.3.0)

Every target of a ports or discovery job gets a host result, stored on its IP asset and shown on the Scans and Attack Surface pages:

| Outcome | Meaning |
|---|---|
| Reachable — open ports found | Something answered, and at least one port is open |
| Reachable — no open ports | Something answered (closed ports reply), and nothing is open in the ports scanned |
| Unreachable from this scanner | Nothing answered this scanner. The device may still be online; a firewall dropping every probe looks the same |
| Not attempted — no route | A private, link-local or CGNAT address outside `VMS_WORKER_NETWORKS`. The job fails with the reason |
| Insufficient evidence | The tool reported nothing usable for the target (e.g. no HTTP answer during discovery) |

A tool error or unreadable output fails the job.

Private targets (for example a Wazuh endpoint's `10.x` address) are reachable only by a worker inside that network. Run the same `worker.py` there with its own `VMS_WORKER_ID`, and declare the network in `VMS_WORKER_NETWORKS`. Only declare a network on a host that really has a route to it.

### Raw output

The worker sends each tool's raw output, capped at 64 KB and with the worker token and bearer credentials removed. The backend redacts it again and keeps it 30 days (`vms_job_evidence`). If the backend cannot store it, the scan carries on.

### Stopping and restarting

`systemctl stop` or `restart` sends SIGTERM to the worker (`KillMode=mixed`). The worker then:
1. stops the running tool;
2. hands the job back to the queue, so another run picks it up (after three hand-backs the job fails, with the reason);
3. exits within `TimeoutStopSec`.

### What "connected" means

The worker sends its own heartbeat every `VMS_PRESENCE_SECONDS` (60) and polls for jobs every `VMS_POLL_SECONDS` (20). The backend records every request that carries the right token. The dashboard shows the worker as connected while one arrived in the last 3 minutes. A running process that cannot authenticate never shows as connected.

The log says `connected: …` when the backend first accepts the worker. Each failure is explained once (and again every 10 minutes while it persists). Every `VMS_STATUS_LOG_SECONDS` (600) it writes a status line:

```
status: connected; 30 poll(s), 0 job(s) in the last 10 min; backend reports 0 queued job(s) for this worker's kinds
```

## 4. What it runs

| Job | Tools | What touches the target |
|---|---|---|
| `discovery` | `subfinder` (passive; queries public sources, not the target), `dnsx`, `httpx` | DNS lookups; one HTTP(S) request per host, at most `VMS_HTTPX_RATE` per second |
| `ports` | `nmap -sT -sV -Pn -T3` | TCP connect scan with service detection, at most `VMS_NMAP_MAX_RATE` packets per second. No root. |
| `vuln_nuclei` | `nuclei` | HTTP/network checks from templates, excluding disruptive ones, at most `VMS_NUCLEI_RATE` requests per second |
| `vuln_openvas` | Greenbone over gvmd's local socket | The configured scan configuration ("Full and fast" by default; safe checks on and vhost expansion off are required) |

- **Shell:** tools run with argument lists, never through a shell.
- **Time limit:** a job that runs longer than `VMS_TOOL_TIMEOUT_SECONDS` is stopped.
- **Heartbeat:** the worker sends one every 30 s.
- **If it stops responding:** the backend requeues the job once, then fails it with the reason.
- **Cancelling:** revoking a scope or cancelling a scan stops the running tool at the next heartbeat.

## 5. Release 2: vulnerability scanning

### Nuclei

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && sudo cp ~/go/bin/nuclei /usr/local/bin/
sudo -u novrsoc-vms nuclei -update-templates
```

Add `vuln_nuclei` to `VMS_WORKER_KINDS`. How it runs:
- **Excluded templates:** `dos`, `fuzz`, `intrusive` and `bruteforce` are never run.
- **Rate:** at most `VMS_NUCLEI_RATE` requests per second.
- **Verification:** a rescan runs only the template that found the issue.
- **Stored output:** requests and responses are not stored; evidence is redacted.

**Template updates:** keep templates current with a daily cron of `nuclei -update-templates` under that user.

### OpenVAS / Greenbone (optional, worker 1.8.0)

Full setup, connectivity and troubleshooting: [docs/runbooks/vms-openvas.md](../../docs/runbooks/vms-openvas.md).

- **Connection:** the worker uses gvmd's **local socket** (GMP, via python-gvm) on the same host. No Greenbone port is opened, and Railway never connects to the VPS: the worker polls Railway outbound, as for every other kind.
- **Requirements:**
  - `python3-gvm` installed;
  - the `novrsoc-vms` user in the socket's group;
  - a dedicated, non-admin Greenbone user in `GVM_USER` / `GVM_PASSWORD`;
  - `vuln_openvas` in `VMS_WORKER_KINDS`.
- **Safety gate:** every job is refused unless the scan configuration has safe checks on and **vhost expansion off** (`expand_vhosts = no`). With expansion on, OpenVAS also tests hostnames it learns from reverse DNS and TLS certificates, which nobody authorised.
- **Targets:**
  - Greenbone gets exactly the job's authorised targets.
  - Names are resolved just before submission. A name is refused if it does not resolve, if it resolves to a private address the worker has no declared route to, or, for a CNII-pinned name, if it resolves outside its approved addresses.
  - Results are kept only for the submitted targets, and the backend re-checks each one against scope.
- **One task per job:** `novrsoc-<job id>`. A job re-sent after a crash resumes that task instead of scanning twice. The task, its report and its target are deleted when the job ends.
- **Limits and outcomes:**
  - Each scan is stopped after `GVM_SCAN_TIMEOUT_SECONDS` (4 h).
  - Transient gvmd failures are retried a bounded number of times.
  - Every target gets an outcome from the report, so a verification rescan verifies a fix only when it shows it reached the target (and the finding's port).

**Object ids:** the worker uses Greenbone's standard object ids. If your installation differs, override them with `GVM_CONFIG_ID`, `GVM_SCANNER_ID` or `GVM_PORT_LIST_ID`.

## 6. Tests

```bash
python3 -m unittest test_worker test_greenbone -v
```
