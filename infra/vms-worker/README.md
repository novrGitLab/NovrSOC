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

## 4. What it runs

| Job | Tools | What touches the target |
|---|---|---|
| `discovery` | `subfinder` (passive; queries public sources, not the target), `dnsx`, `httpx` | DNS lookups; one HTTP(S) request per host, at most `VMS_HTTPX_RATE` per second |
| `ports` | `nmap -sT -sV -Pn -T3` | TCP connect scan with service detection, at most `VMS_NMAP_MAX_RATE` packets per second. No root. |

- **Shell:** tools run with argument lists, never through a shell.
- **Time limit:** a job that runs longer than `VMS_TOOL_TIMEOUT_SECONDS` is stopped.
- **Heartbeat:** the worker sends one every 30 s.
- **If it stops responding:** the backend requeues the job once, then fails it with the reason.
- **Cancelling:** revoking a scope or cancelling a scan stops the running tool at the next heartbeat.

## 5. Tests

```bash
python3 -m unittest test_worker -v
```
