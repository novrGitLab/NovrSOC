-- Phase X2 — retention for the alert store. Additive and idempotent: safe to re-run. Defines a
-- function and does NOT run it or schedule it; the pg_cron schedule at the end is commented out.
--
--   SELECT * FROM public.purge_old_alerts();          -- defaults: alerts 90 days, rejects 14 days
--   SELECT * FROM public.purge_old_alerts(180, 30);
--
-- What it deletes:
--   • alerts with case_id IS NULL whose event_time AND received_at are both older than
--     retain_days. Requiring both means an alert backfilled or replayed today with an old
--     event_time is kept for the full period, so it can still be triaged and exported.
--     Alerts linked to a case are never deleted.
--   • alert_ingest_rejects older than reject_days (by received_at).
-- Deletes run in batches of 5,000 rows so no single statement holds locks for long.
--
-- Vendor export: an alert deleted before a vendor pulled it is never exported. Keep retain_days
-- well above any vendor's longest expected outage.
--
-- Not callable through the API: EXECUTE is revoked from PUBLIC, anon and authenticated, so only
-- the database owner (and pg_cron jobs it creates) can run it.

CREATE OR REPLACE FUNCTION public.purge_old_alerts(retain_days INTEGER DEFAULT 90, reject_days INTEGER DEFAULT 14)
RETURNS TABLE (alerts_deleted BIGINT, rejects_deleted BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
  alert_cutoff  TIMESTAMPTZ;
  reject_cutoff TIMESTAMPTZ;
  n             BIGINT;
BEGIN
  IF retain_days IS NULL OR retain_days < 1 OR reject_days IS NULL OR reject_days < 1 THEN
    RAISE EXCEPTION 'retain_days and reject_days must be at least 1 (got %, %)', retain_days, reject_days;
  END IF;
  alert_cutoff  := NOW() - make_interval(days => retain_days);
  reject_cutoff := NOW() - make_interval(days => reject_days);
  alerts_deleted := 0;
  rejects_deleted := 0;

  LOOP
    DELETE FROM public.alerts
    WHERE id IN (
      SELECT id FROM public.alerts
      WHERE case_id IS NULL AND event_time < alert_cutoff AND received_at < alert_cutoff
      LIMIT 5000
    );
    GET DIAGNOSTICS n = ROW_COUNT;
    alerts_deleted := alerts_deleted + n;
    EXIT WHEN n = 0;
  END LOOP;

  LOOP
    DELETE FROM public.alert_ingest_rejects
    WHERE id IN (SELECT id FROM public.alert_ingest_rejects WHERE received_at < reject_cutoff LIMIT 5000);
    GET DIAGNOSTICS n = ROW_COUNT;
    rejects_deleted := rejects_deleted + n;
    EXIT WHEN n = 0;
  END LOOP;

  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.purge_old_alerts(INTEGER, INTEGER) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL ON FUNCTION public.purge_old_alerts(INTEGER, INTEGER) FROM anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL ON FUNCTION public.purge_old_alerts(INTEGER, INTEGER) FROM authenticated';
  END IF;
END $$;

-- Supports the age filters above.
CREATE INDEX IF NOT EXISTS alerts_retention_idx ON public.alerts (event_time) WHERE case_id IS NULL;

-- ── Schedule (commented out — enable pg_cron in Supabase, then run once) ─────────────────────
-- Daily at 03:17 UTC:
-- SELECT cron.schedule('novrsoc-alert-retention', '17 3 * * *', $cron$SELECT public.purge_old_alerts(90, 14)$cron$);
--
-- Check it:   SELECT jobid, schedule, command FROM cron.job WHERE jobname = 'novrsoc-alert-retention';
-- Remove it:  SELECT cron.unschedule('novrsoc-alert-retention');
