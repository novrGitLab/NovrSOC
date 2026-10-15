# VMS: first scan, end to end (repeatable)

Use this to show, and to re-check after any change, that a discovery scan runs from queue to dashboard. Use only a target you own or have written permission to test.

## Before you start

| Check | How | Expected |
|---|---|---|
| Backend has the P11 lifecycle repair | `cd backend && NOVRSOC_API=https://novrsoc-production-1fb6.up.railway.app npm run verify:deployment` | Both `Worker … without token refused` checks pass |
| Worker is 1.2.0 | `sudo -u novrsoc-vms bash -c 'set -a; . /opt/novrsoc-vms/worker.env; set +a; python3 /opt/novrsoc-vms/worker.py --check'` | `OK: the backend accepted worker vps3-demo-worker …` |
| Tools on the worker | same output, `Tools:` | `dnsx yes, httpx yes` (subfinder for domains) |
| Right httpx | `httpx -version` as the worker user | Prints the ProjectDiscovery banner. If it is the Python `httpx` client, set `VMS_HTTPX_PATH` to ProjectDiscovery's binary |
| Dashboard | VMS → Overview (staff) | Scanner workers: `vps3-demo-worker` connected |

## 1. Authorise the target

As a SOC manager, add the target under VMS → Authorised Scope:
- **Type and value:** your domain, or one IP address.
- **Authorisation reference:** for example `Internal test — owned by Cybernovr`, or the permission letter's reference.
- **Expiry:** no more than the length of the test window.
- **Flags:** leave port and vulnerability scanning off. Discovery only touches the target with DNS lookups and one HTTP request per host.

**Check:** the entry is `active`. Platform Health → VMS scanner is `up`.

## 2. Queue a discovery scan

VMS → Scans → Discovery on that scope entry, with no targets. With no targets, the scan covers the entry itself.

**Check:** the scan shows `queued`. Within about 20 seconds it should show `running` with a progress phase and a recent heartbeat.

## 3. Watch the worker

```bash
journalctl -u novrsoc-vms-worker -f
```

Expected lines:

```
claimed job <id> (discovery)
running subfinder | dnsx | httpx
job <id> succeeded: {'observations': …, 'accepted': …, 'rejected_out_of_scope': 0, …, 'http_responses': …}
```

## 4. Confirm results and completion

| Where | Expected |
|---|---|
| VMS → Scans | `succeeded`, finished time, summary with `accepted` ≥ 1 and `rejected_out_of_scope` 0 |
| VMS → Attack Surface | The target, and for a domain its names, with DNS and HTTP details. Sources `dnsx`/`httpx`/`subfinder`. Distinct from Wazuh endpoints (type `endpoint`, source `wazuh`) |
| VMS → Overview | "Recent scans" lists it; "Changes in the last 7 days" shows `New asset` for each |

An IP with no web server is still recorded as an asset. Its liveness stays unknown: no HTTP answer does not mean the host is down.

## 5. Confirm failures stay visible

Repeat with a scope entry whose value has no DNS records, such as an unused subdomain of your test domain.

**Expected:** the scan ends `succeeded` with 0 new assets.

A tool that fails, for example a wrong `VMS_HTTPX_PATH`, ends the scan `failed` with `httpx exited N: <reason>` shown on the Scans page. It is never reported as "found nothing".

## 6. Clean up

Revoke the scope entry when the test window ends. Queued scans under it are cancelled, and a running one stops at its next heartbeat.

## Not part of this test

Port scans (`ports`), vulnerability scans (`vuln_nuclei`, `vuln_openvas`), and anything outside the authorised entry. Each needs its own flag on the scope entry and its own written authorisation.
