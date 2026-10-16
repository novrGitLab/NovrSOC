-- Phase P13 — asset-centric Full Assessment. Additive and idempotent: safe to re-run.
-- Needs P4 (scope, jobs), P10 (vms_workers) and P12 (evidence). RLS: on, service role only.
--
-- An assessment groups the scans planned for one target. Each step is recorded with what the
-- backend decided before dispatch — queued as a job, or not attempted / unsupported with the
-- reason — so a scan that never ran is never shown as done. Step and assessment status are
-- derived from the jobs when read (services/vmsAssessments.ts); nothing here duplicates job state.

CREATE TABLE IF NOT EXISTS public.vms_assessments (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  asset_id      UUID REFERENCES public.vms_assets(id) ON DELETE SET NULL,
  scope_id      UUID NOT NULL REFERENCES public.vms_scopes(id),
  target        TEXT NOT NULL,                 -- the host or IP assessed
  profile       TEXT NOT NULL DEFAULT 'full' CHECK (profile IN ('full')),
  -- [{ kind, decision: queued|not_attempted|unsupported, reason, job_id, previous_job_ids[] }]
  steps         JSONB NOT NULL DEFAULT '[]',
  requested_by  TEXT NOT NULL,
  requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retried_at    TIMESTAMPTZ,
  cancelled_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS vms_assessments_org_idx ON public.vms_assessments (org_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS vms_assessments_asset_idx ON public.vms_assessments (asset_id, requested_at DESC);

-- Which assessment queued a job (NULL for scans queued on their own).
ALTER TABLE public.vms_scan_jobs ADD COLUMN IF NOT EXISTS assessment_id UUID REFERENCES public.vms_assessments(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS vms_scan_jobs_assessment_idx ON public.vms_scan_jobs (assessment_id) WHERE assessment_id IS NOT NULL;

-- Exclusions inside an authorised entry: hosts, subdomains (".example.com" = every name under
-- it), IPs or CIDRs that must never be touched. Enforced when queueing, by the worker (1.4.0+)
-- and when results arrive.
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS exclusions TEXT[] NOT NULL DEFAULT '{}';

-- What a worker announces it enforces (e.g. 'exclusions'); jobs that need a feature go only to
-- workers that announce it.
ALTER TABLE public.vms_workers ADD COLUMN IF NOT EXISTS features TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE public.vms_assessments ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'vms_assessments' AND policyname = 'vms_assessments_service') THEN
    CREATE POLICY vms_assessments_service ON public.vms_assessments FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
