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
| `vuln_openvas` | Greenbone | "Full and fast" network vulnerability tests |

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

### OpenVAS / Greenbone (optional)

OpenVAS needs its own installation (Greenbone Community Edition). Use a larger host: about 4 vCPU and 8 GB.

1. Install it following Greenbone's documentation.
2. Install the client library on the worker: `pip install python-gvm`.
3. Give the `novrsoc-vms` user access to the gvmd socket.
4. Create a dedicated GVM user.
5. Set `GVM_SOCKET`, `GVM_USER` and `GVM_PASSWORD`, and add `vuln_openvas` to `VMS_WORKER_KINDS`.

**What runs:** the built-in "Full and fast" scan configuration (non-destructive checks) against "All IANA assigned TCP" ports. The temporary task and target are deleted after each run.

**Object ids:** the worker uses Greenbone's standard object ids. If your installation differs, override them with `GVM_CONFIG_ID`, `GVM_SCANNER_ID` or `GVM_PORT_LIST_ID`.

## 6. Tests

```bash
python3 -m unittest test_worker -v
```
