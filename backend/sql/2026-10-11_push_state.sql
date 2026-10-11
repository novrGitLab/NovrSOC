-- Phase X3 — outbound push (jobs/stellarPush.ts): one row per push destination holding the
-- ingest_seq of the last alert it delivered, so a restart resumes where it stopped instead of
-- re-sending or skipping. Needs the R2 `alerts` table and X1's `alerts.ingest_seq`.
-- Additive and idempotent: safe to re-run. Run it BEFORE setting STELLAR_PUSH_ENABLED=true.
--
-- RLS convention: the same as every other backend-written table — RLS enabled, one policy for the
-- service role, no anon/authenticated access.

CREATE TABLE IF NOT EXISTS public.push_state (
  destination      TEXT PRIMARY KEY,               -- e.g. 'stellar'
  last_seq         BIGINT NOT NULL,                -- alerts.ingest_seq of the last delivered (or skipped) alert
  sent_count       BIGINT NOT NULL DEFAULT 0,
  skipped_count    BIGINT NOT NULL DEFAULT 0,      -- alerts the receiver rejected as invalid (400/413/422)
  last_success_at  TIMESTAMPTZ,
  last_error       TEXT,                           -- status code / short reason only, never a payload or credential
  last_error_at    TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

DO $$
BEGIN
  EXECUTE 'ALTER TABLE public.push_state ENABLE ROW LEVEL SECURITY';
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'push_state' AND policyname = 'push_state_service') THEN
    EXECUTE 'CREATE POLICY push_state_service ON public.push_state FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;
