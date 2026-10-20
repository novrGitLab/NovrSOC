-- Phase P19 — VMS automation: Wazuh endpoint detail and scan eligibility, scan profiles, job
-- priority. Additive and idempotent; needs P4, P13 and P14. RLS unchanged (service role only).
--
-- The backend works before this runs: it writes these columns only when they exist and says
-- "not set up" otherwise. Rollback at the end.

-- ── Wazuh endpoints: what the agent reports, and whether/where the endpoint may be scanned ──────
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS os TEXT;
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS agent_status TEXT;                 -- active | disconnected | never_connected | pending
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS agent_last_keepalive TIMESTAMPTZ;  -- the agent's own keep-alive, not the sync time
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS agent_groups TEXT[] NOT NULL DEFAULT '{}';
-- { status, reason, target, scope_id, evaluated_at } — services/vmsEligibility.ts. status:
--   eligible | not_covered | private_no_route | offline | no_address | duplicate_address
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS scan_eligibility JSONB;
-- When the enabled assessment policy will next assess this asset (stamped by each policy run).
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS next_scan_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS vms_assets_agent_idx ON public.vms_assets (org_id, wazuh_agent_id) WHERE wazuh_agent_id IS NOT NULL;

-- ── Scan profiles (services/vmsProfiles.ts) ──────────────────────────────────────────────────
--   discovery: discovery + top-1000 ports · standard: + Nuclei · full: all TCP ports + Nuclei + OpenVAS
-- P13/P14 declared the profile CHECKs inline (unnamed): drop whichever CHECK on these tables
-- mentions profile, whatever Postgres named it, so no narrower one survives. Existing rows are all
-- 'full', which the new constraints accept.
DO $$
DECLARE c record;
BEGIN
  FOR c IN SELECT conname, conrelid::regclass AS tbl FROM pg_constraint
            WHERE contype = 'c'
              AND conrelid IN ('public.vms_assessments'::regclass, 'public.vms_assessment_policies'::regclass)
              AND pg_get_constraintdef(oid) ~ '\mprofile\M'
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', c.tbl, c.conname);
  END LOOP;
END $$;
ALTER TABLE public.vms_assessments ADD CONSTRAINT vms_assessments_profile_check CHECK (profile IN ('discovery', 'standard', 'full'));
ALTER TABLE public.vms_assessment_policies ADD CONSTRAINT vms_assessment_policies_profile_check CHECK (profile IN ('discovery', 'standard', 'full'));
-- 'event': a policy assessed the asset early because its scan destination changed.
ALTER TABLE public.vms_assessments DROP CONSTRAINT IF EXISTS vms_assessments_trigger_check;
ALTER TABLE public.vms_assessments ADD CONSTRAINT vms_assessments_trigger_check CHECK (trigger IN ('manual', 'policy', 'schedule', 'event'));

-- ── Job priority: higher is claimed first; equal priority stays first-in, first-out ───────────
--   verification 80 · manual 60 · event 50 · schedule 40 · policy 30 (routes/vms.ts JOB_PRIORITY)
ALTER TABLE public.vms_scan_jobs ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 50;
CREATE INDEX IF NOT EXISTS vms_scan_jobs_queue_idx ON public.vms_scan_jobs (priority DESC, requested_at) WHERE status = 'queued';

CREATE OR REPLACE FUNCTION public.vms_claim_job(p_worker TEXT, p_kinds TEXT[])
RETURNS SETOF public.vms_scan_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN QUERY
  UPDATE public.vms_scan_jobs j
     SET status = 'running', worker_id = p_worker, claimed_at = NOW(), heartbeat_at = NOW(), started_at = NOW(), attempts = j.attempts + 1
   WHERE j.id = (
     SELECT id FROM public.vms_scan_jobs
      WHERE status = 'queued' AND kind = ANY(p_kinds) AND NOT cancel_requested
      ORDER BY priority DESC, requested_at
      FOR UPDATE SKIP LOCKED
      LIMIT 1)
  RETURNING j.*;
END $$;
REVOKE ALL ON FUNCTION public.vms_claim_job(TEXT, TEXT[]) FROM PUBLIC, anon, authenticated;

-- Reload the API schema so the new columns are visible at once.
NOTIFY pgrst, 'reload schema';

-- Rollback — data-preserving; no row is changed or deleted.
--   Rolling back the CODE needs no database change: everything above is additive. The P18 backend
--   ignores the new columns, writes only profile 'full' and the P14 triggers (still allowed by the
--   wider CHECKs), and queues jobs that take the column default priority 50, so the claim order stays
--   first-in, first-out. Leave the schema as it is.
--   Only if the claim order itself must revert, restore the P4 function (no data is touched):
--     CREATE OR REPLACE FUNCTION public.vms_claim_job(p_worker TEXT, p_kinds TEXT[])
--     RETURNS SETOF public.vms_scan_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
--     BEGIN
--       RETURN QUERY
--       UPDATE public.vms_scan_jobs j
--          SET status = 'running', worker_id = p_worker, claimed_at = NOW(), heartbeat_at = NOW(), started_at = NOW(), attempts = j.attempts + 1
--        WHERE j.id = (SELECT id FROM public.vms_scan_jobs WHERE status = 'queued' AND kind = ANY(p_kinds) AND NOT cancel_requested
--                      ORDER BY requested_at FOR UPDATE SKIP LOCKED LIMIT 1)
--       RETURNING j.*;
--     END $$;
--     REVOKE ALL ON FUNCTION public.vms_claim_job(TEXT, TEXT[]) FROM PUBLIC, anon, authenticated;
--   Do NOT narrow the CHECK constraints back or DROP the new columns: assessments recorded with the
--   discovery/standard profiles or the event trigger, and the stored eligibility, are history to keep.
