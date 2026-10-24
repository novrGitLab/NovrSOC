# P27 VMS onboarding and automation: rollout

Branch `feat/vms-onboarding`. **Not deployed, and the migration has not been applied.** It needs `backend/sql/2026-11-01_p27_vms_onboarding.sql`, applied after P4, P9, P17 and P18. The production queue already holds P21, P25 and P26, so the order is P21 → P25 → P26 → P27.

## What changes for people

- **SOC managers request scope; they no longer approve it.** Any scope entry that permits active scanning (discovery, ports or vulnerability tests) is saved as *pending*. A pending entry authorises nothing.
- **The organisation approves, once.** The organisation's executive account approves the request on **VMS → Asset Management → Scan Authorisation**. To approve, they:
  1. read the exact declaration;
  2. give their name and job title;
  3. type the organisation's registered name;
  4. accept the declaration.
- **Super administrators** can approve in the platform only for their own organisation. For a client, they record the client's *signed document*, which needs the signatory's name, the signatory's title and the document reference.
- **The requester can never approve their own request.** Every decision is stored as an immutable record (`vms_scope_approvals`), and an audit event is written for it.
- **After approval, scans and schedules run without further approval** until the scope expires or is revoked. Executives can now revoke their organisation's scope.
- **Passive-only registrations are unchanged.** This covers CNII Watch monitoring registrations and AS numbers, which are still registered at once. CNII authorisations keep their own workflow.
- **Scan windows and job limits.** A scope can carry scan windows and a per-entry job limit, both approved with it:
  - outside a window, a manual scan is refused, with the time the next window opens;
  - a queued job is cancelled when a worker asks for it outside a window;
  - schedules wait for the window instead of failing;
  - at a job limit, schedules retry 30 minutes later.
- **New schedule kind: Verification rescans.** It rescans scanner findings marked fixed inside a scope that permits vulnerability tests, and never queues the same rescan twice.
- **Asset Import page** (VMS → Asset Management → Asset Import). It imports:
  - Wazuh agents by mapped group, with a preview and optional interface-address discovery;
  - IP addresses, domains and CIDR ranges typed in;
  - a CSV file.

  Each import is checked first and then stored. **Imports never create or widen scope.**
- **Asset Inventory** gains *Source* and *Scanning* (authorisation status) columns, and a matching filter.

## Rollout

1. **Before the migration, find who will approve.** Each client organisation that runs active scans needs an **executive** account (role `executive`, `org_id` = its slug), held by someone with authority over its systems. Without one, a super administrator records the client's signed authorisation (offline document).
   - Existing active scopes are **kept** and marked `legacy`; they keep working.
   - Only **new** requests and **renewals** need approval.
2. **Run the SQL** in the Supabase SQL editor: `backend/sql/2026-11-01_p27_vms_onboarding.sql`.
   - It is additive and idempotent, and ends with `NOTIFY pgrst, 'reload schema'`.
   - Check it with:

   ```sql
   select status, approval_method, count(*) from vms_scopes group by 1, 2;   -- active/legacy, active/cnii, revoked/…
   select id from vms_scope_approvals limit 0;
   select pg_get_constraintdef(oid) from pg_constraint where conname = 'vms_scan_schedules_kind_check';  -- includes 'verification'
   ```

3. **Deploy the backend (Render).**
   - **Optional environment variables:**
     - `VMS_MAX_ACTIVE_JOBS_PER_ORG` (default 50) and `VMS_MAX_ACTIVE_JOBS_PER_SCOPE` (default 20) cap the scans queued plus running at once. The defaults are above today's volumes, so existing automation is not cut short.
   - **No other new variables.** The Wazuh import uses the existing Wazuh Manager API settings.
   - **If the backend goes out before the SQL:**
     - active scope requests answer 503 ("run sql/…p27…");
     - passive registrations, scans under existing scopes, and imports keep working.
4. **Deploy the frontend (Vercel).**
5. **The worker is unchanged:** no VPS deployment and no restart.
   - The backend enforces windows and scope state when a worker claims a job.
   - The worker still re-checks every target against the active-only scope list the claim returns.
6. **Smoke test.** Use a test organisation and reserved targets, and run no scans:
   1. a manager requests a scope;
   2. confirm the scope shows "Waiting for approval" and that queueing a scan under it is refused;
   3. the executive approves it;
   4. check that the decision is listed with its declaration fingerprint;
   5. in Asset Import, run a check-only CSV import and confirm nothing is stored.

## Rollback

- **Code:** redeploy the previous backend and frontend.
- **Database:** leave the P27 columns and table in place; the previous code ignores them.
  - **Pending and rejected rows:** the older code does not expect them. If you roll back, revoke the pending ones first:

    ```sql
    update vms_scopes set status='revoked', revoked_by='rollback p27', revoked_at=now() where status in ('pending','rejected');
    ```

  - **Verification schedules:** disable them (`update vms_scan_schedules set enabled=false where kind='verification'`). The older scheduler would try to queue them as a scan kind and disable them itself.
- **Approval records are immutable by design**, enforced by a trigger. Do not drop the table to roll back; it is the evidence.
