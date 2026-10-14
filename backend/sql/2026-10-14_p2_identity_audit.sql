-- Phase P2 — per-person staff sign-in and a persistent audit log.
-- Additive and idempotent: safe to re-run. Run BEFORE deploying the P2 backend; until it runs,
-- sign-in falls back to the DEV_ADMIN break-glass account only and audit entries stay in memory.
--
-- RLS convention: as every backend-written table — RLS on, one service-role policy, nothing for
-- anon/authenticated. The backend enforces roles and organisations itself.

-- ── platform_users: credentials ────────────────────────────────────────────────────────────
-- password_hash is bcrypt (cost 12). NULL = the user has no password yet and cannot sign in
-- until they use a one-time link from a super_admin.
ALTER TABLE public.platform_users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE public.platform_users ADD COLUMN IF NOT EXISTS password_set_at TIMESTAMPTZ;
ALTER TABLE public.platform_users ADD COLUMN IF NOT EXISTS failed_logins INT NOT NULL DEFAULT 0;
ALTER TABLE public.platform_users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS platform_users_email_lower_key ON public.platform_users (lower(email));

-- ── auth_links: one-time invite / password-reset links ─────────────────────────────────────
-- Only the SHA-256 of the token is stored; the token itself is shown once to the super_admin
-- who created it. A link is single use and expires.
CREATE TABLE IF NOT EXISTS public.auth_links (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES public.platform_users(id) ON DELETE CASCADE,
  token_hash   TEXT NOT NULL UNIQUE,
  purpose      TEXT NOT NULL CHECK (purpose IN ('invite', 'reset')),
  created_by   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL,
  used_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS auth_links_user_idx ON public.auth_links (user_id, created_at DESC);

-- ── audit_log: who did what, kept across restarts ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.audit_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor        TEXT NOT NULL,
  action       TEXT NOT NULL,
  resource     TEXT NOT NULL,
  resource_id  TEXT,
  org_id       TEXT,
  ip           TEXT,
  result       TEXT NOT NULL CHECK (result IN ('success', 'failed')),
  severity     TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  details      TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_at_idx ON public.audit_log (at DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON public.audit_log (lower(actor), at DESC);
CREATE INDEX IF NOT EXISTS audit_log_org_idx ON public.audit_log (org_id, at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['auth_links', 'audit_log'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;

-- Retention: audit entries are kept 400 days (a year plus a quarter, for annual reviews);
-- used or expired links 30 days. Not callable through the API.
CREATE OR REPLACE FUNCTION public.purge_audit_and_links(p_audit_days INT DEFAULT 400, p_link_days INT DEFAULT 30)
RETURNS TABLE (audit_deleted INT, links_deleted INT) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE a INT; l INT;
BEGIN
  DELETE FROM public.audit_log WHERE at < NOW() - make_interval(days => p_audit_days);
  GET DIAGNOSTICS a = ROW_COUNT;
  DELETE FROM public.auth_links WHERE COALESCE(used_at, expires_at) < NOW() - make_interval(days => p_link_days);
  GET DIAGNOSTICS l = ROW_COUNT;
  RETURN QUERY SELECT a, l;
END $$;
REVOKE ALL ON FUNCTION public.purge_audit_and_links(INT, INT) FROM PUBLIC, anon, authenticated;
-- SELECT cron.schedule('purge-audit-and-links', '45 3 * * *', $$SELECT * FROM public.purge_audit_and_links()$$);
