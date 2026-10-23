-- Quarantine recovery preflight — READ ONLY. Run each statement in the Supabase SQL editor and
-- keep the output with the change record. Nothing here writes. See docs/runbooks/quarantine-recovery.md.

-- 1. Quarantine by agent, reason and groups: counts, receipt and event ranges.
SELECT q.alert->>'agent_id'                    AS agent_id,
       string_agg(DISTINCT q.alert->>'agent_name', ', ') AS agent_names,
       q.reason,
       q.wazuh_groups,
       count(*)                                AS alerts,
       min(q.received_at)                      AS first_received,
       max(q.received_at)                      AS last_received,
       min((q.alert->>'event_time')::timestamptz) AS first_event,
       max((q.alert->>'event_time')::timestamptz) AS last_event
FROM public.alert_quarantine q
GROUP BY 1, 3, 4
ORDER BY 5 DESC;

-- 2. Identity: one name per agent id expected. More than one means the id was reused (re-enrolment)
--    and ownership must be checked per name before recovery.
SELECT q.alert->>'agent_id' AS agent_id, q.alert->>'agent_name' AS agent_name, count(*) AS alerts,
       min(q.received_at) AS first_received, max(q.received_at) AS last_received
FROM public.alert_quarantine q
WHERE q.alert->>'agent_id' IN ('000', '011', '012', '013', '014')
GROUP BY 1, 2 ORDER BY 1, 2;

-- 3. Manager (agent 000): manager-local events vs syslog received from another device. Syslog
--    (location = a sender IP address) belongs to that device's owner and is NOT recovered by the
--    manager rule; it needs a sender mapping (P24).
SELECT CASE WHEN q.alert->>'location' ~ '^\d{1,3}(\.\d{1,3}){3}$' OR q.alert->>'location' ~ '^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*$'
            THEN 'syslog from ' || (q.alert->>'location') ELSE 'manager-local: ' || coalesce(q.alert->>'location', '(none)') END AS source,
       count(*) AS alerts
FROM public.alert_quarantine q
WHERE q.alert->>'agent_id' = '000'
GROUP BY 1 ORDER BY 2 DESC;

-- 4. Organisation candidates and the current group map.
SELECT slug, name FROM public.organisations ORDER BY slug;
SELECT wazuh_group, org_id, created_at FROM public.wazuh_group_org_map ORDER BY wazuh_group;

-- 5. Conflicts: quarantined alert ids that already exist in the alert store, and under which
--    organisation. Same organisation = already recovered (skipped); another organisation = the
--    recovery script aborts.
SELECT a.org_id, q.alert->>'agent_id' AS agent_id, count(*) AS already_stored
FROM public.alert_quarantine q
JOIN public.alerts a ON a.wazuh_alert_id = q.wazuh_alert_id
GROUP BY 1, 2 ORDER BY 1, 2;

-- 6. Have these agents ever been stored for any organisation (ownership evidence)?
SELECT agent_id, org_id, count(*) AS stored_alerts, max(received_at) AS last_received
FROM public.alerts
WHERE agent_id IN ('000', '011', '012', '013', '014')
GROUP BY 1, 2 ORDER BY 1, 2;

-- 7. Retention. purge_alert_quarantine(14) deletes rows whose received_at is older than 14 days
--    when it runs. Is it scheduled? (pg_cron: run 7a; if cron.job does not exist, it is not
--    scheduled through pg_cron.)
SELECT to_regclass('cron.job') IS NOT NULL AS pg_cron_installed,
       to_regprocedure('public.purge_alert_quarantine(integer)') IS NOT NULL AS purge_function_present;
-- 7a. Only when pg_cron_installed is true:
-- SELECT jobid, jobname, schedule, command, active FROM cron.job
--  WHERE command ILIKE '%purge_alert_quarantine%' OR command ILIKE '%purge_old_alerts%';

-- 8. Earliest deletion risk per agent if the 14-day purge runs (deletion happens on the first run
--    after this instant).
SELECT q.alert->>'agent_id' AS agent_id, min(q.received_at) AS oldest_received,
       min(q.received_at) + interval '14 days' AS eligible_for_purge_from
FROM public.alert_quarantine q
GROUP BY 1 ORDER BY 3;

-- 9. The exact `expected` values for quarantine-recover-by-agent.sql: rows per agent received at
--    or before the cutoff you will use (edit it here and there identically). Agent 000 counts only
--    manager-local events, as the recovery script does.
WITH params AS (SELECT '2026-10-24T00:00:00Z'::timestamptz AS cutoff)
SELECT q.alert->>'agent_id' AS agent_id, q.alert->>'agent_name' AS agent_name, q.reason, count(*) AS expected
FROM public.alert_quarantine q, params
WHERE q.received_at <= params.cutoff
  AND q.alert->>'agent_id' IN ('000', '011', '012', '013', '014')
  AND NOT (q.alert->>'agent_id' = '000' AND (q.alert->>'location' ~ '^\d{1,3}(\.\d{1,3}){3}$' OR q.alert->>'location' ~ '^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*$'))
GROUP BY 1, 2, 3 ORDER BY 1;
