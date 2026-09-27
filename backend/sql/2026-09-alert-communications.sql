-- NovrSOC — Alert Communication log (routes/communications.ts).
-- Run once in the Supabase SQL editor. Safe to re-run.
-- Until this table exists the backend keeps the log in memory and the page says so.

CREATE TABLE IF NOT EXISTS public.alert_communications (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          TEXT NOT NULL DEFAULT 'cybernovr',
  recipient_type  TEXT NOT NULL,            -- client | analyst | all_analysts | custom
  recipients      TEXT[] NOT NULL DEFAULT '{}',
  subject         TEXT NOT NULL,
  body            TEXT NOT NULL,
  severity        TEXT NOT NULL,            -- critical | high | medium | low | informational
  case_id         UUID REFERENCES public.cases(id) ON DELETE SET NULL,
  case_number     TEXT,
  sent_by         TEXT NOT NULL,
  status          TEXT NOT NULL,            -- sent | failed
  error           TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS alert_communications_org_created_idx ON public.alert_communications (org_id, created_at DESC);

ALTER TABLE public.alert_communications ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'alert_communications' AND policyname = 'alert_communications_service') THEN
    CREATE POLICY alert_communications_service ON public.alert_communications FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
