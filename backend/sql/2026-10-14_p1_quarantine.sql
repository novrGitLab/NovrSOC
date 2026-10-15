-- Phase P1 — alert quarantine. An alert whose agent's Wazuh groups map to no organisation (or to
-- more than one) used to be dropped, leaving only a reason row in alert_ingest_rejects. It is now
-- also kept here, without an org, so it can be replayed into `alerts` once a super_admin maps the
-- group (PUT /api/admin/wazuh-group-map replays automatically; POST .../quarantine/replay on demand).
-- Needs the R2 `alerts` table. Additive and idempotent: safe to re-run.
--
-- The rows hold alert content of unknown tenancy, so nothing but the backend (service role) can
-- read them, and the API only ever exposes per-group counts. Retention: 14 days, purged by
-- public.purge_alert_quarantine() (scheduled with the other retention jobs; see the end).

CREATE TABLE IF NOT EXISTS public.alert_quarantine (
  wazuh_alert_id   TEXT PRIMARY KEY,
  wazuh_groups     TEXT[] NOT NULL,
  reason           TEXT NOT NULL CHECK (reason IN ('unmapped_group', 'ambiguous_org')),
  alert            JSONB NOT NULL,          -- the alerts row as it would be stored, minus org_id
  received_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS alert_quarantine_groups_idx ON public.alert_quarantine USING GIN (wazuh_groups);
CREATE INDEX IF NOT EXISTS alert_quarantine_received_idx ON public.alert_quarantine (received_at);

DO $$
BEGIN
  EXECUTE 'ALTER TABLE public.alert_quarantine ENABLE ROW LEVEL SECURITY';
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'alert_quarantine' AND policyname = 'alert_quarantine_service') THEN
    EXECUTE 'CREATE POLICY alert_quarantine_service ON public.alert_quarantine FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;

-- Retention: quarantined alerts older than p_days are deleted. Not callable through the API.
CREATE OR REPLACE FUNCTION public.purge_alert_quarantine(p_days INT DEFAULT 14)
RETURNS INT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n INT;
BEGIN
  DELETE FROM public.alert_quarantine WHERE received_at < NOW() - make_interval(days => p_days);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION public.purge_alert_quarantine(INT) FROM PUBLIC, anon, authenticated;

-- Schedule (run once pg_cron is enabled):
-- SELECT cron.schedule('purge-alert-quarantine', '30 3 * * *', $$SELECT public.purge_alert_quarantine(14)$$);
