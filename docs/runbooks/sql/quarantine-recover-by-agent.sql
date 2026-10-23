-- Quarantine recovery by agent — releases named agents' quarantined alerts into ONE organisation.
-- Reviewed procedure: docs/runbooks/quarantine-recovery.md. Run the preflight first
-- (quarantine-preflight.sql) and fill in the parameters below from its output.
--
-- Safety:
--   • One transaction. Any failed check raises an exception and rolls back everything.
--   • DRY RUN by default: every check and the full insert run, then the transaction is rolled back
--     with a report. Set dry_run to false only for the approved run.
--   • Aborts on: an unknown organisation; a count per agent different from the expected one; a
--     different agent name for an id (re-enrolment); a quarantined row of that agent with another
--     reason (ambiguous_org) or with a Wazuh group mapped to any organisation; an alert id already
--     stored under ANOTHER organisation.
--   • Agent 000 (the manager): only manager-local events are recovered (location is not an IP
--     address). Syslog the manager received from another device belongs to that device's owner and
--     is left in quarantine.
--   • Only rows received at or before `cutoff` are touched, so alerts arriving during the run stay.
--   • Alerts keep their Wazuh alert id, event_time, raw payload and fields; received_at is the
--     original quarantine receipt time. Existing alerts are never overwritten.
--   • A quarantine row is deleted only after its alert is confirmed in the alert store under the
--     target organisation, and only if every selected row is confirmed.
--
-- Schema: public.alerts (sql/2026-10-09_alerts_pipeline.sql, + ingest_seq, + P24 columns, all
-- defaulted or nullable) and public.alert_quarantine (sql/2026-10-14_p1_quarantine.sql).

BEGIN;
SET LOCAL lock_timeout = '15s';
SET LOCAL statement_timeout = '10min';

-- ── Parameters (edit) ────────────────────────────────────────────────────────────────────────
CREATE TEMP TABLE recover_params (
  org_id      TEXT NOT NULL,
  agent_id    TEXT NOT NULL,
  agent_name  TEXT NOT NULL,       -- as Wazuh reports it; must match every selected row
  expected    INT  NOT NULL,       -- rows to recover for this agent, from preflight query 1/3
  cutoff      TIMESTAMPTZ NOT NULL,-- only rows received at or before this instant
  dry_run     BOOLEAN NOT NULL
) ON COMMIT DROP;

INSERT INTO recover_params (org_id, agent_id, agent_name, expected, cutoff, dry_run) VALUES
  ('cybernovr', '011', 'DESKTOP-FBC0TFT',   299, '2026-10-24T00:00:00Z', true),
  ('cybernovr', '012', 'PARTYJOLLOF',       393, '2026-10-24T00:00:00Z', true),
  ('cybernovr', '013', 'Aliyat',            304, '2026-10-24T00:00:00Z', true),
  ('cybernovr', '014', 'Mac.lan',            22, '2026-10-24T00:00:00Z', true),
  ('cybernovr', '000', 'novrsoc-security',  144, '2026-10-24T00:00:00Z', true);

-- ── Recovery log (the rollback record) ───────────────────────────────────────────────────────
-- One row per released alert: its full original quarantine row and whether this run inserted the
-- alert (false = it was already stored). quarantine-recovery-rollback.sql restores a run from it.
-- Service role only, like every backend table. Created in this transaction (a dry run leaves no table).
CREATE TABLE IF NOT EXISTS public.alert_quarantine_recovery_log (
  run_id          UUID        NOT NULL,
  wazuh_alert_id  TEXT        NOT NULL,
  org_id          TEXT        NOT NULL,
  inserted        BOOLEAN     NOT NULL,
  quarantine_row  JSONB       NOT NULL,
  recovered_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  rolled_back_at  TIMESTAMPTZ,
  PRIMARY KEY (run_id, wazuh_alert_id)
);
ALTER TABLE public.alert_quarantine_recovery_log ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'alert_quarantine_recovery_log' AND policyname = 'alert_quarantine_recovery_log_service') THEN
    CREATE POLICY alert_quarantine_recovery_log_service ON public.alert_quarantine_recovery_log FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Checks, insert, confirmation, log, delete ────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION pg_temp.is_ip(v TEXT) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  IF v IS NULL OR v !~ '^[0-9A-Fa-f.:]+$' THEN RETURN false; END IF;
  PERFORM v::inet;
  RETURN true;
EXCEPTION WHEN others THEN RETURN false;
END $$;

DO $$
DECLARE
  v_org      TEXT;
  v_dry      BOOLEAN;
  v_cutoff   TIMESTAMPTZ;
  r          RECORD;
  n_selected INT;
  n_present  INT;
  n_inserted INT;
  n_deleted  INT;
  v_run      UUID := gen_random_uuid();
BEGIN
  IF (SELECT count(DISTINCT org_id) FROM recover_params) <> 1 THEN RAISE EXCEPTION 'exactly one organisation per run'; END IF;
  IF (SELECT count(DISTINCT dry_run) FROM recover_params) <> 1 OR (SELECT count(DISTINCT cutoff) FROM recover_params) <> 1 THEN
    RAISE EXCEPTION 'dry_run and cutoff must be the same on every row';
  END IF;
  IF (SELECT count(*) FROM recover_params) <> (SELECT count(DISTINCT agent_id) FROM recover_params) THEN RAISE EXCEPTION 'an agent is listed twice'; END IF;
  SELECT org_id, dry_run, cutoff INTO v_org, v_dry, v_cutoff FROM recover_params LIMIT 1;
  IF NOT EXISTS (SELECT 1 FROM public.organisations WHERE slug = v_org) THEN RAISE EXCEPTION 'unknown organisation: %', v_org; END IF;
  IF v_cutoff > now() THEN RAISE EXCEPTION 'cutoff % is in the future', v_cutoff; END IF;

  -- The rows this run would release, locked against concurrent ingest updates.
  CREATE TEMP TABLE recover_rows ON COMMIT DROP AS
  SELECT q.wazuh_alert_id, q.wazuh_groups, q.reason, q.alert, q.received_at, p.agent_id
  FROM public.alert_quarantine q
  JOIN recover_params p ON q.alert->>'agent_id' = p.agent_id
  WHERE q.received_at <= v_cutoff
    AND NOT (p.agent_id = '000' AND pg_temp.is_ip(q.alert->>'location'));   -- manager: local events only
  PERFORM 1 FROM public.alert_quarantine q JOIN recover_rows x USING (wazuh_alert_id) FOR UPDATE OF q;

  -- Per agent: reason, identity, groups, count.
  FOR r IN SELECT p.agent_id, p.agent_name, p.expected,
                  count(x.wazuh_alert_id)                                                      AS n,
                  count(x.wazuh_alert_id) FILTER (WHERE x.reason <> 'unmapped_group')          AS other_reason,
                  count(x.wazuh_alert_id) FILTER (WHERE x.alert->>'agent_name' IS DISTINCT FROM p.agent_name) AS other_name,
                  count(x.wazuh_alert_id) FILTER (WHERE EXISTS (SELECT 1 FROM public.wazuh_group_org_map m WHERE m.wazuh_group = ANY (x.wazuh_groups))) AS mapped_group
           FROM recover_params p LEFT JOIN recover_rows x ON x.agent_id = p.agent_id
           GROUP BY p.agent_id, p.agent_name, p.expected ORDER BY p.agent_id
  LOOP
    IF r.other_reason > 0 THEN RAISE EXCEPTION 'agent %: % row(s) quarantined for a reason other than unmapped_group (ambiguous ownership)', r.agent_id, r.other_reason; END IF;
    IF r.other_name > 0 THEN RAISE EXCEPTION 'agent %: % row(s) carry a name other than % (agent id reused?)', r.agent_id, r.other_name, r.agent_name; END IF;
    IF r.mapped_group > 0 THEN RAISE EXCEPTION 'agent %: % row(s) list a Wazuh group mapped to an organisation — use the mapping replay, not this script', r.agent_id, r.mapped_group; END IF;
    IF r.n <> r.expected THEN RAISE EXCEPTION 'agent %: % row(s) selected, % expected', r.agent_id, r.n, r.expected; END IF;
  END LOOP;

  -- An alert id already stored under another organisation is a conflicting ownership: stop.
  IF EXISTS (SELECT 1 FROM recover_rows x JOIN public.alerts a ON a.wazuh_alert_id = x.wazuh_alert_id AND a.org_id <> v_org) THEN
    RAISE EXCEPTION 'conflict: % alert id(s) already stored under another organisation',
      (SELECT count(*) FROM recover_rows x JOIN public.alerts a ON a.wazuh_alert_id = x.wazuh_alert_id AND a.org_id <> v_org);
  END IF;

  SELECT count(*) INTO n_selected FROM recover_rows;
  SELECT count(*) INTO n_present FROM recover_rows x JOIN public.alerts a ON a.org_id = v_org AND a.wazuh_alert_id = x.wazuh_alert_id;

  CREATE TEMP TABLE recover_inserted (wazuh_alert_id TEXT PRIMARY KEY) ON COMMIT DROP;
  WITH ins AS (
  INSERT INTO public.alerts (org_id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip,
                             severity, mitre_ids, wazuh_groups, location, raw, raw_truncated, event_time, received_at)
  SELECT v_org,
         x.wazuh_alert_id,
         x.alert->>'rule_id',
         (x.alert->>'rule_level')::int,
         x.alert->>'rule_description',
         x.alert->>'agent_id',
         x.alert->>'agent_name',
         x.alert->>'agent_ip',
         x.alert->>'severity',
         CASE WHEN jsonb_typeof(x.alert->'mitre_ids') = 'array' THEN ARRAY(SELECT jsonb_array_elements_text(x.alert->'mitre_ids')) END,
         x.wazuh_groups,
         x.alert->>'location',
         x.alert->'raw',
         COALESCE((x.alert->>'raw_truncated')::boolean, false),
         (x.alert->>'event_time')::timestamptz,
         x.received_at
  FROM recover_rows x
  ON CONFLICT (org_id, wazuh_alert_id) DO NOTHING
  RETURNING wazuh_alert_id)
  INSERT INTO recover_inserted SELECT wazuh_alert_id FROM ins;
  SELECT count(*) INTO n_inserted FROM recover_inserted;

  -- Every selected alert must now be in the store under the target organisation.
  IF (SELECT count(*) FROM recover_rows x JOIN public.alerts a ON a.org_id = v_org AND a.wazuh_alert_id = x.wazuh_alert_id) <> n_selected THEN
    RAISE EXCEPTION 'confirmation failed: not every selected alert is stored under %', v_org;
  END IF;
  IF n_inserted + n_present <> n_selected THEN
    RAISE EXCEPTION 'count mismatch: inserted % + already present % <> selected %', n_inserted, n_present, n_selected;
  END IF;

  -- The rollback record, written before anything is removed from the quarantine.
  INSERT INTO public.alert_quarantine_recovery_log (run_id, wazuh_alert_id, org_id, inserted, quarantine_row)
  SELECT v_run, q.wazuh_alert_id, v_org, EXISTS (SELECT 1 FROM recover_inserted i WHERE i.wazuh_alert_id = q.wazuh_alert_id), to_jsonb(q)
  FROM public.alert_quarantine q JOIN recover_rows x USING (wazuh_alert_id);
  IF (SELECT count(*) FROM public.alert_quarantine_recovery_log WHERE run_id = v_run) <> n_selected THEN RAISE EXCEPTION 'recovery log incomplete'; END IF;

  DELETE FROM public.alert_quarantine q USING recover_rows x
  WHERE q.wazuh_alert_id = x.wazuh_alert_id
    AND EXISTS (SELECT 1 FROM public.alerts a WHERE a.org_id = v_org AND a.wazuh_alert_id = q.wazuh_alert_id);
  GET DIAGNOSTICS n_deleted = ROW_COUNT;
  IF n_deleted <> n_selected THEN RAISE EXCEPTION 'delete mismatch: % deleted, % selected', n_deleted, n_selected; END IF;

  IF v_dry THEN
    RAISE EXCEPTION 'DRY RUN OK — rolled back. Would release % alert(s) to % (% new, % already stored); per agent: %',
      n_selected, v_org, n_inserted, n_present,
      (SELECT string_agg(agent_id || '=' || n, ', ' ORDER BY agent_id) FROM (SELECT agent_id, count(*) n FROM recover_rows GROUP BY 1) s);
  END IF;
  RAISE NOTICE 'Released % alert(s) to % (% new, % already stored). Recovery run id: % (keep it: quarantine-recovery-rollback.sql needs it)', n_selected, v_org, n_inserted, n_present, v_run;
END $$;

COMMIT;
