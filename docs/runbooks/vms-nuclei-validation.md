# Validating Nuclei on the VMS worker (controlled, one authorised test asset)

**Status:** Nuclei is installed on the worker, but `vuln_nuclei` is not in its `VMS_WORKER_KINDS`. No production vulnerability scan has been run. The Full Assessment shows "Vulnerabilities (Nuclei): unsupported" until this procedure has passed and the kind has been enabled.

OpenVAS stays unavailable. Nothing in this procedure installs or enables it.

## Before you start

- **P13 and P14 deployed.** The backend, frontend and worker 1.5.0 are deployed and checked as in [deploy-p13-p14-vms-platform.md](deploy-p13-p14-vms-platform.md). VMS Admin shows the worker online at 1.5.0.
- **A test asset you own or have written permission to test.** It must be a host under your control (for example a throwaway VPS with a known vulnerable test application in a container), never a third-party or shared host.
  - `scanme.nmap.org` permits port scanning, not vulnerability scanning: do not use it.
  - Write down the asset's public IP and the permission reference.
- **Every assessment policy disabled.** Check VMS Admin → Assessment policies.
- **Existing scopes checked.** Look at the "allowing vulnerability scans" count in VMS Admin → Authorised scope. Once the worker runs `vuln_nuclei`, any active entry that allows vulnerability scanning can have Nuclei jobs queued against it. If any entry other than the test entry allows it, review it, or set its vulnerability permission off, before step 3.

## 1. Check the tools (read-only, on the VPS)

```bash
cd /opt/novrsoc-vms
./verify-tools.sh
sudo -u novrsoc-vms nuclei -version
sudo -u novrsoc-vms nuclei -tl -silent | wc -l     # templates installed for the service user; must be > 0
```

The worker runs Nuclei with:
- `-duc`, so it never updates itself during a job;
- `-etags dos,fuzz,intrusive,bruteforce`;
- `-severity` taken from `VMS_NUCLEI_SEVERITIES`;
- `-rl` set from `VMS_NUCLEI_RATE` (default 50 requests per second); keep 50 or lower for the test.

If no templates are listed, install them as the service user: `nuclei -update-templates`. That is a change to the VPS: do it only with approval.

## 2. Authorise the test asset

In **VMS → Authorised Scope**, add exactly one entry:

| Field | Value |
|---|---|
| Kind | IP |
| Value | the test asset's address |
| Activities | discovery, ports and vulnerability scanning |
| Expiry | 7 days |
| Reference | `NUCLEI-VALIDATION-<date>`, plus the permission reference |

## 3. Enable the kind on the worker (production change: needs approval)

1. Edit `/opt/novrsoc-vms/worker.env` and set `VMS_WORKER_KINDS=discovery,ports,vuln_nuclei`.
2. Run `systemctl restart novrsoc-vms-worker`.
3. Run `journalctl -u novrsoc-vms-worker -n 30`. The log must show `vuln_nuclei` among the kinds, and "connected".

Within a minute, VMS Admin must show the worker running `vuln_nuclei`, with `nuclei` installed and its version.

## 4. One scan

1. In **VMS → Scans**, queue `vuln_nuclei` with the test asset as the only target. Queue nothing else.
2. Watch the job go queued → running → succeeded or failed. On the VPS, `journalctl -u novrsoc-vms-worker -f` shows the same.

Pass criteria:

- **Job:** it finishes, and its summary shows `targets: 1`.
- **Findings:** every finding is under Findings with `evidence_class` = scanner check. Each finding has the template ID, the matched URL and the evidence.
- **Expected issue found:** the known issue of the test application is among the findings. If it is not, record which template should have matched and check whether it is installed (`nuclei -tl | grep <id>`).
- **Raw output:** it appears under the scan's evidence, redacted, with its SHA-256.
- **Nothing else touched:** no request reached any host but the test asset. Check the test asset's access log for the source IP and time window.

Then run **Rescan to verify** on one finding:
- With the issue still present, the finding stays open.
- After the issue is removed from the test application, the finding is verified.

## 5. Full Assessment

Start a Full Assessment of the test asset.

- Discovery, ports and Nuclei must be queued.
- OpenVAS must show **Unsupported**.
- The report lists every check with its status.

## 6. Decide

- **Passed:** keep `vuln_nuclei` enabled. Record the date, the Nuclei version and the number of templates in the change log. Revoke the test scope entry, or let it expire.
- **Failed:** set `VMS_WORKER_KINDS=discovery,ports` again and restart. Assessments again show Nuclei as unsupported.

## What a Nuclei result does and does not mean

- **No findings** means that none of the templates that ran matched. It does not prove the host is secure, and Nuclei does not report whether the host answered.
- **The ports check in the same Full Assessment** records reachability. If the ports check is **inconclusive** (unreachable), treat a Nuclei run with zero findings as giving no assurance either.
