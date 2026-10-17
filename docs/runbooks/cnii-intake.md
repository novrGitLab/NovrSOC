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
