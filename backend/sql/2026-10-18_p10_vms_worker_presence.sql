-- Phase P10 — scanner worker presence. Additive and idempotent: safe to re-run. Needs nothing else.
-- RLS: on, one service-role policy, nothing for anon/authenticated (as every backend-written table).
--
-- Why: "is a scanner worker connected?" used to be read from vms_scan_jobs.heartbeat_at, which is
-- only written while a worker runs a job. An idle worker polling an empty queue left no trace, so
-- the dashboard said "no scanner worker has connected" while one was polling every 20 seconds.
-- Now every request the backend accepts with the worker token (claim, or the worker's own
-- heartbeat) records the worker here. A worker is online when last_seen_at is recent
-- (routes/vmsWorker.ts WORKER_ONLINE_SECONDS); nothing is inferred from a process running.

CREATE TABLE IF NOT EXISTS public.vms_workers (
  worker_id         TEXT PRIMARY KEY,                  -- as configured on the worker host (VMS_WORKER_ID)
  kinds             TEXT[] NOT NULL DEFAULT '{}',      -- job kinds it asked for / announced
  version           TEXT,                              -- worker.py version string
  tools             JSONB NOT NULL DEFAULT '{}',       -- { "nmap": true, "nuclei": false, ... } as the worker reports
  first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- last authenticated request of any kind
  last_heartbeat_at TIMESTAMPTZ,                       -- last POST /heartbeat
  last_claim_at     TIMESTAMPTZ,                       -- last POST /claim
  last_job_id       UUID,                              -- last job it was given
  last_job_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS vms_workers_seen_idx ON public.vms_workers (last_seen_at DESC);

ALTER TABLE public.vms_workers ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'vms_workers' AND policyname = 'vms_workers_service') THEN
    CREATE POLICY vms_workers_service ON public.vms_workers FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- Retention: workers not seen for 90 days are removed (a renamed or retired host).
CREATE OR REPLACE FUNCTION public.purge_vms_workers(p_days INT DEFAULT 90)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n BIGINT;
BEGIN
  DELETE FROM public.vms_workers WHERE last_seen_at < NOW() - make_interval(days => p_days);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION public.purge_vms_workers(INT) FROM PUBLIC, anon, authenticated;
-- SELECT cron.schedule('purge-vms-workers', '50 4 * * *', $$SELECT public.purge_vms_workers()$$);
