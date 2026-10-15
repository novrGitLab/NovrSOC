-- Phase P7 — VMS Release 3, continuous monitoring: scan schedules, daily risk snapshots for
-- trends, change-notification state, and retention. Additive and idempotent.
-- RLS: on, service role only.

-- A schedule queues the same scan every interval, through the same scope checks as a manual scan
-- (routes/vms.ts validateScan). A schedule whose scope is revoked or expired is disabled, with the
-- reason, instead of queueing anything.
CREATE TABLE IF NOT EXISTS public.vms_scan_schedules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          TEXT NOT NULL,
  scope_id        UUID NOT NULL REFERENCES public.vms_scopes(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL CHECK (kind IN ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas')),
  targets         TEXT[] NOT NULL DEFAULT '{}',   -- empty = the whole scope entry
  ports           TEXT,
  interval_hours  INT NOT NULL CHECK (interval_hours BETWEEN 24 AND 2160),
  next_run_at     TIMESTAMPTZ NOT NULL,
  enabled         BOOLEAN NOT NULL DEFAULT true,
  last_run_at     TIMESTAMPTZ,
  last_job_id     UUID,
  last_result     TEXT,
  created_by      TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS vms_scan_schedules_due_idx ON public.vms_scan_schedules (enabled, next_run_at);
CREATE INDEX IF NOT EXISTS vms_scan_jobs_schedule_idx ON public.vms_scan_jobs (schedule_id) WHERE schedule_id IS NOT NULL;

-- One row per organisation per day, measured from vms_findings / vms_assets at snapshot time.
CREATE TABLE IF NOT EXISTS public.vms_risk_snapshots (
  org_id             TEXT NOT NULL,
  day                DATE NOT NULL,
  taken_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  open_total         INT NOT NULL DEFAULT 0,
  open_by_priority   JSONB NOT NULL DEFAULT '{}',   -- {"P1": n, "P2": n, ...}
  overdue            INT NOT NULL DEFAULT 0,
  kev_open           INT NOT NULL DEFAULT 0,
  internet_open      INT NOT NULL DEFAULT 0,        -- open findings on internet-facing assets
  assets_active      INT NOT NULL DEFAULT 0,
  assets_internet    INT NOT NULL DEFAULT 0,
  new_findings       INT NOT NULL DEFAULT 0,        -- first seen that day
  verified           INT NOT NULL DEFAULT 0,        -- verified that day
  reopened           INT NOT NULL DEFAULT 0,        -- reopened that day
  PRIMARY KEY (org_id, day)
);

-- Where change notifications got to, per organisation.
CREATE TABLE IF NOT EXISTS public.vms_notify_state (
  org_id          TEXT PRIMARY KEY,
  last_event_at   TIMESTAMPTZ,
  last_finding_at TIMESTAMPTZ,
  last_run_at     TIMESTAMPTZ,
  last_result     JSONB
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['vms_scan_schedules', 'vms_risk_snapshots', 'vms_notify_state'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;

-- Retention: asset change events and finished scan jobs after 365 days; snapshots after 730 days.
-- Findings, their evidence and history are kept (they are the remediation record).
CREATE OR REPLACE FUNCTION public.purge_vms_history(p_event_days INT DEFAULT 365, p_job_days INT DEFAULT 365, p_snapshot_days INT DEFAULT 730)
RETURNS TABLE (events_deleted INT, jobs_deleted INT, snapshots_deleted INT) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE e INT; j INT; s INT;
BEGIN
  DELETE FROM public.vms_asset_events WHERE at < NOW() - make_interval(days => p_event_days);
  GET DIAGNOSTICS e = ROW_COUNT;
  DELETE FROM public.vms_scan_jobs WHERE status IN ('succeeded', 'failed', 'cancelled') AND COALESCE(finished_at, requested_at) < NOW() - make_interval(days => p_job_days);
  GET DIAGNOSTICS j = ROW_COUNT;
  DELETE FROM public.vms_risk_snapshots WHERE day < (NOW() - make_interval(days => p_snapshot_days))::date;
  GET DIAGNOSTICS s = ROW_COUNT;
  RETURN QUERY SELECT e, j, s;
END $$;
REVOKE ALL ON FUNCTION public.purge_vms_history(INT, INT, INT) FROM PUBLIC, anon, authenticated;
-- SELECT cron.schedule('purge-vms-history', '30 4 * * *', $$SELECT * FROM public.purge_vms_history()$$);
