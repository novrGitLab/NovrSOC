-- Phase P18 — CNII scan authorisation and manual registration. Additive and idempotent: safe to
-- re-run. Needs P4 (vms_scopes) and P17 (cnii_submissions). RLS unchanged (service role only).
--
-- A CNII scan authorisation is an ordinary VMS scope entry, written by the CNII approval itself, so
-- every existing check (API, Full Assessment planning, scheduler, worker claim and target checks,
-- result ingest) enforces it unchanged — nothing is bypassed:
--   origin              'cnii' for entries created by a CNII approval ('vms' for every other entry)
--   cnii_submission_id  the intake submission it was approved for
--   pinned_addresses    for a domain: the addresses it resolved to at approval. The name may be scanned
--                       only while it resolves within them (checked when queueing, by worker 1.7.0+
--                       before each scan, and at ingest); a DNS change needs a new approval.
-- CNII entries are exact: a domain without subdomains, single IPs; they expire (at most 90 days) and
-- are revoked like any scope entry.
--
-- Manual registration: basis 'manual_registration' marks a submission an analyst registered against
-- an organisation and sector, with a justification. It stays a candidate (never on the watch list)
-- until a manager confirms it, and authorises nothing.
--
-- Rollback: the backend works without these (authorisation answers "not set up"). To remove:
--   UPDATE public.vms_scopes SET status = 'revoked', revoked_by = 'rollback', revoked_at = NOW() WHERE origin = 'cnii' AND status = 'active';
--   (the columns can stay; earlier code ignores them.)

ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'vms';
ALTER TABLE public.vms_scopes DROP CONSTRAINT IF EXISTS vms_scopes_origin_check;
ALTER TABLE public.vms_scopes ADD CONSTRAINT vms_scopes_origin_check CHECK (origin IN ('vms', 'cnii'));
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS cnii_submission_id UUID;
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS pinned_addresses TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS vms_scopes_cnii_idx ON public.vms_scopes (cnii_submission_id) WHERE cnii_submission_id IS NOT NULL;

-- { scope_ids, targets, approved_addresses, reference, evidence, activities, approved_by, approved_at, expires_at, revoked_* }
ALTER TABLE public.cnii_submissions ADD COLUMN IF NOT EXISTS authorisation JSONB;
ALTER TABLE public.cnii_submissions DROP CONSTRAINT IF EXISTS cnii_submissions_basis_check;
ALTER TABLE public.cnii_submissions ADD CONSTRAINT cnii_submissions_basis_check CHECK (basis IS NULL OR basis IN ('authorised_scope', 'analyst_confirmed', 'analyst_rejected', 'manual_registration'));
