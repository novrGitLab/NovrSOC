-- NovrSOC — replace the Slack notification step with email (Slack removed from the platform).
-- Safe to re-run. Applied to the live database via the REST API on the day it was written; kept
-- here as the record and for any other environment.

-- The step itself. Renamed in place when only the Slack row exists; if both exist, the Slack
-- row is dropped instead (step_id is UNIQUE).
UPDATE public.playbook_steps
   SET step_id = 'notify_email', name = 'Send Email Notification',
       description = 'Email the SOC team mailbox', script_name = 'notify_email.py'
 WHERE step_id = 'notify_slack'
   AND NOT EXISTS (SELECT 1 FROM public.playbook_steps WHERE step_id = 'notify_email');
DELETE FROM public.playbook_steps WHERE step_id = 'notify_slack';

-- Playbooks that referenced it.
UPDATE public.playbooks SET step_ids = array_replace(step_ids, 'notify_slack', 'notify_email')
 WHERE 'notify_slack' = ANY(step_ids);
UPDATE public.playbooks
   SET steps = replace(replace(steps::text, 'Send Slack Notification', 'Send Email Notification'), 'Notify SOC team on Slack', 'Email the SOC team mailbox')::jsonb
 WHERE steps::text LIKE '%Slack%';

-- Open tasks already created from those playbooks, so their Execute button keeps working.
UPDATE public.case_tasks
   SET step_id = 'notify_email', title = replace(title, 'Send Slack Notification', 'Send Email Notification')
 WHERE step_id = 'notify_slack';
