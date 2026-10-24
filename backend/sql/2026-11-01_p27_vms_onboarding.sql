-- Phase P27 — VMS asset onboarding and scan authorisation. Additive and idempotent; no row is
-- deleted and no existing scope stops working.
--
-- Scope authorisation (routes/vms.ts, services/vmsAuthorisation.ts):
--   • A scope entry that permits active scanning (discovery, ports or vulnerabilities) is created
--     `pending`. It authorises nothing until an organisation administrator approves it, with an
--     explicit declaration of authority, recorded in vms_scope_approvals. A passive-only entry
--     (no active activity — CNII Watch's monitoring registrations) is registered at once, as before.
--   • CNII authorisations (origin 'cnii', services/cniiIntake.ts) keep their own workflow.
--   • Existing VMS scopes stay active; they are labelled approval_method = 'legacy' so the UI can
--     show they predate the approval workflow.
--   • scan_windows: when scans may run (NULL = any time). max_active_jobs: queued + running jobs
--     allowed at once under the scope (NULL = the platform default).
-- Scheduling: a 'verification' schedule kind re-tests findings marked fixed.
-- Requires: P4 (vms_scopes, vms_scan_schedules), P9 (allow_discovery), P18 (origin column), P17 (full_assessment kind).

-- ── Scope lifecycle ─────────────────────────────────────────────────────────────────────────
ALTER TABLE public.vms_scopes DROP CONSTRAINT IF EXISTS vms_scopes_status_check;
ALTER TABLE public.vms_scopes ADD CONSTRAINT vms_scopes_status_check CHECK (status IN ('pending', 'active', 'revoked', 'rejected'));
-- A pending request has no approver yet.
ALTER TABLE public.vms_scopes ALTER COLUMN approved_by DROP NOT NULL;
ALTER TABLE public.vms_scopes ALTER COLUMN approved_at DROP NOT NULL;
ALTER TABLE public.vms_scopes ALTER COLUMN approved_at DROP DEFAULT;

ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS request_group_id UUID;          -- entries requested (and approved) together
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS requested_by TEXT;
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS requested_at TIMESTAMPTZ;
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS approval_method TEXT;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vms_scopes_approval_method_check') THEN
    ALTER TABLE public.vms_scopes ADD CONSTRAINT vms_scopes_approval_method_check
      CHECK (approval_method IS NULL OR approval_method IN ('in_platform', 'offline_document', 'passive_registration', 'legacy', 'cnii'));
  END IF;
END $$;
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS approval_id UUID;               -- vms_scope_approvals.id
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS scan_windows JSONB;             -- { tz, windows: [{ days:[1..7], start:'HH:MM', end:'HH:MM' }] }
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS max_active_jobs INT;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vms_scopes_max_active_jobs_check') THEN
    ALTER TABLE public.vms_scopes ADD CONSTRAINT vms_scopes_max_active_jobs_check CHECK (max_active_jobs IS NULL OR max_active_jobs BETWEEN 1 AND 20);
  END IF;
END $$;
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS rejected_by TEXT;
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

-- Scopes that exist today: VMS ones predate the workflow; CNII ones have their own.
UPDATE public.vms_scopes SET approval_method = 'legacy' WHERE approval_method IS NULL AND COALESCE(origin, 'vms') = 'vms';
UPDATE public.vms_scopes SET approval_method = 'cnii'   WHERE approval_method IS NULL AND origin = 'cnii';
CREATE INDEX IF NOT EXISTS vms_scopes_group_idx ON public.vms_scopes (org_id, request_group_id);
CREATE INDEX IF NOT EXISTS vms_scopes_status_idx ON public.vms_scopes (org_id, status);

-- ── Approval records: one immutable row per decision ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.vms_scope_approvals (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                 TEXT NOT NULL,
  request_group_id       UUID NOT NULL,
  scope_ids              UUID[] NOT NULL,
  decision               TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
  method                 TEXT NOT NULL CHECK (method IN ('in_platform', 'offline_document')),
  -- Who decided (the platform account) …
  decided_by_user_id     TEXT NOT NULL,
  decided_by_email       TEXT NOT NULL,
  decided_by_role        TEXT NOT NULL,
  -- … and the person whose authority it is (the same person in-platform; the signatory offline).
  authority_name         TEXT,
  authority_title        TEXT,
  organisation_name      TEXT,                 -- as the approver typed it (checked against the organisation)
  signed_document_ref    TEXT,                 -- offline_document only
  declaration_version    TEXT,
  declaration_text       TEXT,                 -- the exact text accepted
  declaration_sha256     TEXT,
  snapshot               JSONB NOT NULL,       -- targets, activities, exclusions, windows, limits, expiry as approved
  reason                 TEXT,                 -- rejection reason
  ip                     TEXT,
  user_agent             TEXT,
  decided_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS vms_scope_approvals_org_idx ON public.vms_scope_approvals (org_id, decided_at DESC);
ALTER TABLE public.vms_scope_approvals ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'vms_scope_approvals' AND policyname = 'vms_scope_approvals_service') THEN
    CREATE POLICY vms_scope_approvals_service ON public.vms_scope_approvals FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
-- Approval records are evidence: no updates or deletes, even by the backend.
CREATE OR REPLACE FUNCTION public.vms_scope_approvals_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'vms_scope_approvals rows are immutable'; END $$;
DROP TRIGGER IF EXISTS vms_scope_approvals_no_change ON public.vms_scope_approvals;
CREATE TRIGGER vms_scope_approvals_no_change BEFORE UPDATE OR DELETE ON public.vms_scope_approvals
  FOR EACH ROW EXECUTE FUNCTION public.vms_scope_approvals_immutable();

-- ── Schedules: verification rescans ─────────────────────────────────────────────────────────
ALTER TABLE public.vms_scan_schedules DROP CONSTRAINT IF EXISTS vms_scan_schedules_kind_check;
ALTER TABLE public.vms_scan_schedules ADD CONSTRAINT vms_scan_schedules_kind_check
  CHECK (kind IN ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas', 'passive_osint', 'full_assessment', 'verification'));

NOTIFY pgrst, 'reload schema';

-- Rollback (only if the workflow is withdrawn; approval records are evidence — keep them):
--   UPDATE public.vms_scopes SET status = 'rejected' WHERE status = 'pending';
--   (older code ignores the new columns; pending/rejected rows authorise nothing either way)
