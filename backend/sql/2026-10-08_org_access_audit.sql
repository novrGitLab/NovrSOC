-- Phase S2 — record every staff request that acts on an organisation other than the caller's
-- own (lib/resolveOrg.ts, X-Org-Id header). Additive and idempotent: safe to re-run.
--
-- Until this table exists the backend still records each access in its in-process audit log
-- (lost on restart) and logs one warning; nothing fails.

CREATE TABLE IF NOT EXISTS public.org_access_audit (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor        TEXT NOT NULL,         -- token email
  role         TEXT,                  -- token role
  home_org     TEXT NOT NULL,         -- token org_id (slug)
  target_org   TEXT NOT NULL,         -- organisation acted on (slug)
  method       TEXT NOT NULL,
  route        TEXT NOT NULL,         -- request path, no query string
  accessed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS org_access_audit_target_idx ON public.org_access_audit (target_org, accessed_at DESC);
CREATE INDEX IF NOT EXISTS org_access_audit_actor_idx  ON public.org_access_audit (actor, accessed_at DESC);

-- Service role only, same as the other backend-written tables.
ALTER TABLE public.org_access_audit ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'org_access_audit' AND policyname = 'org_access_audit_service_role') THEN
    CREATE POLICY org_access_audit_service_role ON public.org_access_audit FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
