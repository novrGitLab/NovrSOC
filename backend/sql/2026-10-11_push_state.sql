-- Phase X3 — outbound push (jobs/stellarPush.ts): one row per push destination holding the
-- ingest_seq of the last alert it delivered, so a restart resumes where it stopped instead of
-- re-sending or skipping. Needs the R2 `alerts` table and X1's `alerts.ingest_seq`.
-- Additive and idempotent: safe to re-run. Run it BEFORE setting STELLAR_PUSH_ENABLED=true.
--
-- RLS convention: the same as every other backend-written table — RLS enabled, one policy for the
-- service role, no anon/authenticated access.
CREATE TABLE IF NOT EXISTS public.push_state (
  destination TEXT PRIMARY KEY,
  -- e.g. 'stellar'
  last_seq BIGINT NOT NULL,
  -- alerts.ingest_seq of the last delivered (or skipped) alert
  sent_count BIGINT NOT NULL DEFAULT 0,
  skipped_count BIGINT NOT NULL DEFAULT 0,
  -- alerts the receiver rejected as invalid (400/413/422); each is in push_dead_letters
  retry_count BIGINT NOT NULL DEFAULT 0,
  -- transient failures (network, timeout, 429, 5xx) that were retried
  last_success_at TIMESTAMPTZ,
  last_error TEXT,
  -- status code / short reason only, never a payload or credential
  last_error_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
-- Alerts the receiver refused as invalid (400/413/422), kept so none is silently lost. The feed
-- moves past them; a super_admin can request a retry (e.g. after the receiver's parser changes),
-- and the job re-sends requested rows, marking each resolved on success. No payload is stored —
-- the alert itself stays in `alerts` (until retention removes it).
CREATE TABLE IF NOT EXISTS public.push_dead_letters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  destination TEXT NOT NULL,
  alert_id UUID NOT NULL,
  ingest_seq BIGINT NOT NULL,
  status_code INT,
  attempts INT NOT NULL DEFAULT 1,
  retry_requested BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_attempt_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS push_dead_letters_dest_alert_key ON public.push_dead_letters (destination, alert_id);
CREATE INDEX IF NOT EXISTS push_dead_letters_open_idx ON public.push_dead_letters (destination, retry_requested)
WHERE resolved_at IS NULL;
DO $$
DECLARE t text;
BEGIN FOREACH t IN ARRAY ARRAY ['push_state', 'push_dead_letters'] LOOP EXECUTE format(
  'ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',
  t
);
IF NOT EXISTS (
  SELECT 1
  FROM pg_policies
  WHERE schemaname = 'public'
    AND tablename = t
    AND policyname = t || '_service'
) THEN EXECUTE format(
  'CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')',
  t || '_service',
  t
);
END IF;
END LOOP;
END $$;