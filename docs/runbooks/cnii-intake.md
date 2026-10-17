# CNII Watch intake: submit a domain or IP, link it, assess it

Branch `feat/cnii-intake`. **Not deployed.** It needs `backend/sql/2026-10-23_p17_cnii_intake.sql`, applied after P13 and P14.

## Enable

1. **Run the SQL.** In the Supabase SQL editor, run `backend/sql/2026-10-23_p17_cnii_intake.sql`. It is additive and can be re-run. Check it with:

   ```sql
   select id from cnii_submissions limit 0;
   select ends_at from vms_scan_schedules limit 0;
   ```

   Without it, intake answers 503 "CNII intake is not set up yet"; the rest of CNII Watch is unchanged.

2. **No new environment variables.** AI help uses the existing `ANTHROPIC_API_KEY` on Railway, with `AI_MODEL` optional.
   - **Without the key,** intake, classification, confirmation, assessment and scheduling all work; the AI panel shows "unavailable".

## Workflow

1. **CNII Watch → Asset intake:** submit `portal.example.gov.ng` or an IP.
   - The backend resolves A and AAAA records, and reverse DNS for each address.
   - It asks RIPEstat for the AS and holder of public addresses.
   - It records which organisation's authorised scope covers the value and each address.
2. **Confirmed automatically** only when exactly one organisation holds the submitted value itself in active authorised scope **and** that organisation's CNII profile is *designated*. Everything else is an **unverified candidate**, with the reason:
   - no scope covers it;
   - more than one organisation's scope covers it;
   - the organisation has no CNII profile;
   - the organisation is only a CNII candidate;
   - for a domain, only one of its addresses is in someone's scope, since shared hosting and CDNs are common.
3. **A manager can confirm** a candidate, choosing a CNII-classified organisation and writing the evidence, **or reject it**. A re-check keeps a person's decision.
4. **Confirmed values inside that organisation's scope** become its VMS assets. The sector view then counts them and lists them under "Confirmed watch-list assets". Values outside scope are not added; add a scope entry first.
5. **Run Full Assessment** (analysts and managers) queues the existing Full Assessment for each in-scope value. Scope permissions, exclusions, worker kinds and tools, and private routes all apply. Unsupported checks show as unsupported.
6. **Repeat every 2 days** (managers): one `full_assessment` schedule per in-scope value, every 48 h, ending after at most 60 days.
   - A run is skipped while the previous assessment of that target is still in progress.
   - At the end date the schedule is disabled and never runs again.
7. **The detail view** shows:
   - assessments, with each check's status (pending, running, completed, findings detected, inconclusive, failed, not attempted, unsupported);
   - open findings by severity;
   - each finding with its endpoint, latest evidence and remediation;
   - schedules.

   It refreshes every 15 s while an assessment is in progress. "No findings" is shown with the reminder that it is not proof of security.

## Permissions

| Action | Needs |
|---|---|
| Submit, list, view | `cnii:sector` (super_admin, soc_manager, analyst) |
| Confirm or reject | `cnii:manage` (super_admin, soc_manager) |
| Assess | `vms:scan` |
| Schedule | `vms:scope` (managers) |

Executives and portal users are refused. Every submission, re-check, decision, assessment and schedule is audited (`CNII_INTAKE_*`).

## Rollback

- **Code:** redeploy the previous commit.
- **Schedules:** to stop them, run `update vms_scan_schedules set enabled = false where kind = 'full_assessment';`.
- **Table:** `cnii_submissions` can stay, or be dropped.

## P18: bulk intake, manual registration and CNII scan authorisation

Needs `backend/sql/2026-10-24_p18_cnii_authorisation.sql`, applied after P17. It is additive and can be re-run. Check it with:

```sql
select origin, cnii_submission_id, pinned_addresses from vms_scopes limit 0;
select authorisation from cnii_submissions limit 0;
```

**Deployment order:**
1. P18 SQL.
2. Backend and frontend.
3. Worker 1.7.0 (`./deploy.sh main`).

Worker 1.7.0 announces the `pinned_addresses` feature, which a backend before P18 rejects. Until 1.7.0 runs, jobs under a CNII-pinned entry wait in the queue ("Waiting for a worker that enforces CNII pinned addresses"). They are never run by an older worker.

### Bulk

Enter up to 25 domains or IPs, separated by commas, spaces or new lines.
- Each entry is validated and normalised on its own, and gets its own result: confirmed, candidate, rejected, invalid, duplicate or failed.
- A bad or failing entry never blocks the rest.
- Values already submitted are re-checked, not duplicated.

### Manually Add Asset (sector page)

An analyst registers an IP against an organisation and a sector, with a justification.
- **The result is unverified:** it is listed under "Registered, not verified" and never on the watch list. It does not designate the operator, add inventory or authorise any scan.
- **Refused** if the organisation is classified in a different sector.
- **Verification:** a manager confirms it (the "Manager decision" control), which is separate.
- **Scanning** needs the separate authorisation below.

### Authorise scanning (managers: `cnii:manage` and `vms:scope`)

Only for a confirmed submission. It needs a reference, written evidence, an expiry of at most 90 days, and explicit port and vulnerability permissions. The approval is written as ordinary VMS scope entries in the operator's organisation (`origin = 'cnii'`), so every existing check enforces it; nothing is bypassed:

- **What it covers:**
  - **a domain:** that name only, no subdomains, pinned to the addresses it resolves to at approval;
  - **its public addresses,** or the ones chosen, as single-IP entries.
- **Refused** if the name doesn't resolve, resolves to a reserved address, or resolves to more than 16 addresses.
- **DNS changes are caught three times:**
  - when queueing, the name is resolved again, and a change means nothing is queued ("pinned to its approved addresses"; a manager must re-approve);
  - worker 1.7.0 resolves it again just before scanning, and refuses on a change;
  - at ingest, observations of the name at an address outside the pins are dropped.
- **Redirects:** httpx and Nuclei run without redirect following, and results for other hosts are dropped at ingest.
- **Existing general VMS scope entries** for the same value are left unchanged and reported.
- **Revoke:** revokes the entries and disables their Full Assessment schedules. Queued jobs are refused by the worker because the scope is no longer active.

**Audit actions:** `CNII_INTAKE_SUBMITTED` / `RECHECKED` (including bulk entries), `CNII_ASSET_REGISTERED`, `CNII_INTAKE_CONFIRMED` / `REJECTED`, `CNII_SCAN_AUTHORISED`, `CNII_SCAN_AUTHORISATION_REVOKED`.

**Residual risk:** between the worker's own lookup and the tool's lookup, a few seconds apart, DNS could change. Ingest drops results seen at other addresses, but a request may already have been sent. Fully closing that gap would need the tools to connect to a fixed address, which is not done here.
