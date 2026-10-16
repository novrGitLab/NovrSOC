-- Phase P12 — trustworthy scan outcomes and raw evidence. Additive and idempotent: safe to re-run.
-- Needs P4 (vms_assets, vms_scan_jobs) and P10 (vms_workers). RLS: on, service role only.
--
-- The backend works before this file runs: it stores what it can and says what is missing
-- (assessments then live only in the job summary; evidence uploads answer 503 naming this file;
-- worker networks are not recorded). Nothing here rewrites or deletes existing rows.

-- ── What the last scan learned about a host ─────────────────────────────────────────────────
-- { outcome: reachable_open | reachable_no_open | unreachable | no_route | insufficient_evidence,
--   reason, method: nmap | httpx, host_status?, host_status_reason?, port_states?, ports_scanned?,
--   job_id, worker_id }
-- "unreachable" means nothing answered THIS scanner; it never means the device is offline.
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS last_assessment JSONB;
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS last_assessed_at TIMESTAMPTZ;

-- ── Which private networks a worker can reach (VMS_WORKER_NETWORKS on the worker host) ─────
ALTER TABLE public.vms_workers ADD COLUMN IF NOT EXISTS networks TEXT[] NOT NULL DEFAULT '{}';

-- ── Raw tool output, bounded and redacted, kept 30 days ─────────────────────────────────────
-- Evidence only: deleting a row never touches assets, services, findings or the job record.
CREATE TABLE IF NOT EXISTS public.vms_job_evidence (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  job_id      UUID NOT NULL REFERENCES public.vms_scan_jobs(id) ON DELETE CASCADE,
  target      TEXT NOT NULL,
  tool        TEXT NOT NULL CHECK (tool IN ('nmap', 'httpx', 'dnsx', 'subfinder', 'nuclei', 'openvas')),
  content     TEXT NOT NULL,                  -- redacted; at most 64 KB
  truncated   BOOLEAN NOT NULL DEFAULT false, -- the worker cut the output to the limit
  sha256      TEXT NOT NULL,                  -- of the stored content
  bytes       INT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')
);
CREATE INDEX IF NOT EXISTS vms_job_evidence_job_idx ON public.vms_job_evidence (job_id, created_at);
CREATE INDEX IF NOT EXISTS vms_job_evidence_expiry_idx ON public.vms_job_evidence (expires_at);

ALTER TABLE public.vms_job_evidence ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'vms_job_evidence' AND policyname = 'vms_job_evidence_service') THEN
    CREATE POLICY vms_job_evidence_service ON public.vms_job_evidence FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- Retention. The backend also deletes expired rows itself (jobs/vmsMaintenance.ts, hourly) and
-- never serves an expired row, so pg_cron is optional.
CREATE OR REPLACE FUNCTION public.purge_vms_job_evidence()
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n BIGINT;
BEGIN
  DELETE FROM public.vms_job_evidence WHERE expires_at < NOW();
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION public.purge_vms_job_evidence() FROM PUBLIC, anon, authenticated;
-- SELECT cron.schedule('purge-vms-job-evidence', '20 * * * *', $$SELECT public.purge_vms_job_evidence()$$);
