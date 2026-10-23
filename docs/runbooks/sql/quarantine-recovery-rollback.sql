-- Rollback of one quarantine recovery run (quarantine-recover-by-agent.sql), from its recovery log.
-- Puts every released alert back into the quarantine exactly as it was, and removes from the alert
-- store only the alerts that run inserted (an alert that was already stored stays).
--
-- Safety:
--   • One transaction, DRY RUN by default (reports, then rolls back).
--   • Refuses if any alert of the run has since been acted on — status changed, assigned,
--     acknowledged, noted, linked to a case, or has triage history (alert_events would be deleted
--     with it, ON DELETE CASCADE). Those must be handled by a person first.
--   • A quarantine row is restored before its alert is removed, and both are confirmed.
--   • The log entries are marked rolled_back_at, so a run can't be rolled back twice.

BEGIN;
SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '10min';

CREATE TEMP TABLE rollback_params (run_id UUID NOT NULL, dry_run BOOLEAN NOT NULL) ON COMMIT DROP;
INSERT INTO rollback_params (run_id, dry_run) VALUES
  ('00000000-0000-0000-0000-000000000000', true);   -- the run id the recovery printed

DO $$
DECLARE
  v_run     UUID;
  v_dry     BOOLEAN;
  n_log     INT;
  n_touched INT;
  n_removed INT;
  has_events BOOLEAN := to_regclass('public.alert_events') IS NOT NULL;
  has_triage BOOLEAN := EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'alerts' AND column_name = 'assigned_to');
BEGIN
  SELECT run_id, dry_run INTO v_run, v_dry FROM rollback_params;
  IF to_regclass('public.alert_quarantine_recovery_log') IS NULL THEN RAISE EXCEPTION 'no recovery log table: nothing was recovered'; END IF;
  SELECT count(*) INTO n_log FROM public.alert_quarantine_recovery_log WHERE run_id = v_run AND rolled_back_at IS NULL;
  IF n_log = 0 THEN RAISE EXCEPTION 'run %: no entries to roll back (unknown run, or already rolled back)', v_run; END IF;
  PERFORM 1 FROM public.alert_quarantine_recovery_log WHERE run_id = v_run AND rolled_back_at IS NULL FOR UPDATE;

  -- Alerts of this run that someone has acted on since.
  EXECUTE format($q$
    SELECT count(*) FROM public.alerts a JOIN public.alert_quarantine_recovery_log l
      ON a.org_id = l.org_id AND a.wazuh_alert_id = l.wazuh_alert_id
    WHERE l.run_id = $1 AND l.rolled_back_at IS NULL AND l.inserted
      AND (a.case_id IS NOT NULL OR a.status IS DISTINCT FROM 'new' %s %s)$q$,
    CASE WHEN has_triage THEN 'OR a.assigned_to IS NOT NULL OR a.acknowledged_at IS NOT NULL OR a.triage_note IS NOT NULL' ELSE '' END,
    CASE WHEN has_events THEN 'OR EXISTS (SELECT 1 FROM public.alert_events e WHERE e.alert_id = a.id)' ELSE '' END)
  INTO n_touched USING v_run;
  IF n_touched > 0 THEN RAISE EXCEPTION 'run %: % recovered alert(s) have been triaged, assigned or cased since — handle them before rolling back', v_run, n_touched; END IF;

  -- 1. Restore the quarantine rows as they were.
  INSERT INTO public.alert_quarantine (wazuh_alert_id, wazuh_groups, reason, alert, received_at, last_seen_at)
  SELECT l.wazuh_alert_id,
         ARRAY(SELECT jsonb_array_elements_text(l.quarantine_row->'wazuh_groups')),
         l.quarantine_row->>'reason',
         l.quarantine_row->'alert',
         (l.quarantine_row->>'received_at')::timestamptz,
         (l.quarantine_row->>'last_seen_at')::timestamptz
  FROM public.alert_quarantine_recovery_log l
  WHERE l.run_id = v_run AND l.rolled_back_at IS NULL
  ON CONFLICT (wazuh_alert_id) DO NOTHING;
  IF (SELECT count(*) FROM public.alert_quarantine_recovery_log l JOIN public.alert_quarantine q USING (wazuh_alert_id)
      WHERE l.run_id = v_run AND l.rolled_back_at IS NULL) <> n_log THEN
    RAISE EXCEPTION 'run %: quarantine restore not confirmed', v_run;
  END IF;

  -- 2. Remove only the alerts this run inserted.
  DELETE FROM public.alerts a USING public.alert_quarantine_recovery_log l
  WHERE l.run_id = v_run AND l.rolled_back_at IS NULL AND l.inserted
    AND a.org_id = l.org_id AND a.wazuh_alert_id = l.wazuh_alert_id;
  GET DIAGNOSTICS n_removed = ROW_COUNT;

  UPDATE public.alert_quarantine_recovery_log SET rolled_back_at = now() WHERE run_id = v_run AND rolled_back_at IS NULL;

  IF v_dry THEN
    RAISE EXCEPTION 'DRY RUN OK — rolled back. Would restore % quarantine row(s) and remove % alert(s) for run %', n_log, n_removed, v_run;
  END IF;
  RAISE NOTICE 'Run %: restored % quarantine row(s), removed % alert(s)', v_run, n_log, n_removed;
END $$;

COMMIT;
