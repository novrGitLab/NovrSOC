-- Phase P17 — CNII Watch intake: a submitted domain or IP, what it resolves to, and whether it can
-- be linked to a CNII organisation; plus an end date and a Full Assessment kind for scan schedules.
-- Additive and idempotent: safe to re-run. Needs P4 (vms_scopes), P7 (vms_scan_schedules), P9 (CNII)
-- and P13 (Full Assessment). RLS: on, service role only.
--
-- A submission is NOT an asset. It records what an analyst asked about and the evidence gathered:
--   status confirmed  linked to one organisation by trusted evidence (that organisation is a
--                     designated CNII operator and holds the value in active authorised scope —
--                     basis authorised_scope) or by a manager's decision (basis analyst_confirmed)
--          candidate  not (yet) linked, with the reason; never shown as CNII
--          rejected   a manager decided it is not CNII, with the reason
-- An AI suggestion never sets the status. Values inside the organisation's authorised scope are
-- added to that organisation's VMS inventory (vms_assets), which is what sector views count.
--
-- Rollback: the backend reports "not set up" without these. To remove:
--   DROP TABLE IF EXISTS public.cnii_submissions;
--   UPDATE public.vms_scan_schedules SET enabled = false WHERE kind = 'full_assessment';
--   (ends_at and the kind constraint can stay; they are unused by earlier code.)

CREATE TABLE IF NOT EXISTS public.cnii_submissions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  value           TEXT NOT NULL UNIQUE,              -- normalised domain or IP
  kind            TEXT NOT NULL CHECK (kind IN ('domain', 'ip')),
  status          TEXT NOT NULL DEFAULT 'candidate' CHECK (status IN ('confirmed', 'candidate', 'rejected')),
  basis           TEXT CHECK (basis IS NULL OR basis IN ('authorised_scope', 'analyst_confirmed', 'analyst_rejected')),
  reason          TEXT NOT NULL,
  org_id          TEXT,                               -- organisations.slug, once linked
  sector_id       TEXT,                               -- from that organisation's CNII profile
  subfield        TEXT,
  ips             TEXT[] NOT NULL DEFAULT '{}',       -- addresses the domain resolved to (or the IP itself)
  resolution      JSONB NOT NULL DEFAULT '{}',        -- per address: reverse DNS, registry holder, scope coverage
  evidence        JSONB NOT NULL DEFAULT '[]',        -- [{ kind, detail, source, strength }]
  suggestion      JSONB,                              -- keyword sector suggestion from registry data (not evidence of ownership)
  asset_ids       UUID[] NOT NULL DEFAULT '{}',       -- vms_assets created or linked for in-scope values
  decided_by      TEXT,
  decided_at      TIMESTAMPTZ,
  decision_note   TEXT,
  submitted_by    TEXT NOT NULL,
  submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at     TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS cnii_submissions_status_idx ON public.cnii_submissions (status, sector_id);
CREATE INDEX IF NOT EXISTS cnii_submissions_org_idx ON public.cnii_submissions (org_id);

-- Schedules: an end date (a schedule never runs after it), and Full Assessment as a kind.
ALTER TABLE public.vms_scan_schedules ADD COLUMN IF NOT EXISTS ends_at TIMESTAMPTZ;
ALTER TABLE public.vms_scan_schedules DROP CONSTRAINT IF EXISTS vms_scan_schedules_kind_check;
ALTER TABLE public.vms_scan_schedules ADD CONSTRAINT vms_scan_schedules_kind_check CHECK (kind IN ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas', 'passive_osint', 'full_assessment'));

ALTER TABLE public.cnii_submissions ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'cnii_submissions' AND policyname = 'cnii_submissions_service') THEN
    CREATE POLICY cnii_submissions_service ON public.cnii_submissions FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
