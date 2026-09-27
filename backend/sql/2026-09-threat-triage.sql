-- NovrSOC — analyst decisions on threats (services/threatBoard.ts). Run once; safe to re-run.
-- Threats themselves are derived live from Wazuh alerts; this only stores what an analyst
-- decided about one (contained / resolved, assignee, the case it was escalated to).
-- Until this table exists the backend keeps decisions in memory and the page says so.

CREATE TABLE IF NOT EXISTS public.threat_triage (
  threat_id    TEXT PRIMARY KEY,           -- THR-<hash of rule + source>
  org_id       TEXT NOT NULL DEFAULT 'cybernovr',
  status       TEXT,                       -- contained | resolved | NULL (no decision)
  assigned_to  TEXT,
  case_id      UUID REFERENCES public.cases(id) ON DELETE SET NULL,
  case_number  TEXT,
  updated_by   TEXT NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  note         TEXT
);

CREATE INDEX IF NOT EXISTS threat_triage_org_idx ON public.threat_triage (org_id);

ALTER TABLE public.threat_triage ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'threat_triage' AND policyname = 'threat_triage_service') THEN
    CREATE POLICY threat_triage_service ON public.threat_triage FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
