-- Phase P14 — automatic assessment policies and worker tool versions. Additive and idempotent.
-- Needs P13 (vms_assessments). RLS: on, service role only.
--
-- A policy says which assets of an organisation get a Full Assessment automatically and how
-- often. Policies are created disabled; an administrator turns each one on. Every run still goes
-- through the same planning as a manual assessment (scope, exclusions, worker kinds, tools and
-- routes), so a policy never authorises anything a manual request could not do.

CREATE TABLE IF NOT EXISTS public.vms_assessment_policies (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  name             TEXT NOT NULL,
  enabled          BOOLEAN NOT NULL DEFAULT false,
  -- wazuh: Wazuh-enrolled endpoints (assessed at their recorded address); external: hosts and IPs
  -- found or registered by VMS; any: both.
  asset_source     TEXT NOT NULL DEFAULT 'external' CHECK (asset_source IN ('wazuh', 'external', 'any')),
  profile          TEXT NOT NULL DEFAULT 'full' CHECK (profile IN ('full')),
  -- An asset assessed (by any trigger) within this many hours is not assessed again by the policy;
  -- an unreachable or blocked asset is not retried before then either.
  cooldown_hours   INT NOT NULL DEFAULT 168 CHECK (cooldown_hours BETWEEN 24 AND 2160),
  max_per_run      INT NOT NULL DEFAULT 5 CHECK (max_per_run BETWEEN 1 AND 50),
  last_run_at      TIMESTAMPTZ,
  last_result      JSONB,                       -- { queued, skipped_cooldown, blocked: [{ asset, reason }] }
  created_by       TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by       TEXT,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS vms_assessment_policies_org_idx ON public.vms_assessment_policies (org_id, enabled);

-- Who or what started an assessment.
ALTER TABLE public.vms_assessments ADD COLUMN IF NOT EXISTS trigger TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE public.vms_assessments DROP CONSTRAINT IF EXISTS vms_assessments_trigger_check;
ALTER TABLE public.vms_assessments ADD CONSTRAINT vms_assessments_trigger_check CHECK (trigger IN ('manual', 'policy', 'schedule'));
ALTER TABLE public.vms_assessments ADD COLUMN IF NOT EXISTS policy_id UUID REFERENCES public.vms_assessment_policies(id) ON DELETE SET NULL;

-- Tool versions as the worker reports them ({"nmap": "7.94SVN", ...}); presence of a tool is in tools.
ALTER TABLE public.vms_workers ADD COLUMN IF NOT EXISTS tool_versions JSONB NOT NULL DEFAULT '{}';

ALTER TABLE public.vms_assessment_policies ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'vms_assessment_policies' AND policyname = 'vms_assessment_policies_service') THEN
    CREATE POLICY vms_assessment_policies_service ON public.vms_assessment_policies FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
