-- NovrSOC — team presence history (services/presence.ts). Run once; safe to re-run.
-- Live online/away/offline status works without this (heartbeats are held in memory). This adds
-- history that survives a backend restart: last active time and the 7-day activity heatmap.

ALTER TABLE public.platform_users ADD COLUMN IF NOT EXISTS last_active TIMESTAMPTZ;
ALTER TABLE public.platform_users ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT false;

CREATE TABLE IF NOT EXISTS public.user_activity_days (
  email  TEXT NOT NULL,
  day    DATE NOT NULL,          -- WAT calendar day the person was active
  PRIMARY KEY (email, day)
);

ALTER TABLE public.user_activity_days ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'user_activity_days' AND policyname = 'user_activity_days_service') THEN
    CREATE POLICY user_activity_days_service ON public.user_activity_days FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
