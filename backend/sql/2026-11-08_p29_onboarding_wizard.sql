-- Phase P29 — Release 3.1: client onboarding wizard progress and per-organisation service grants.
-- Additive and idempotent: safe to re-run. Needs P4 (vms_assets) only indirectly (nothing here
-- touches it); needs the `organisations` table (sql/2026-09-organisations-onboarding.sql).
-- RLS: on, one service-role policy each, nothing else, matching every other backend-written table.
--
-- No duplicate organisation, user or auth model: both tables key on organisations.slug (org_id)
-- exactly as every other org-scoped table in this schema does, and neither holds a credential,
-- a session, or a user identity of its own.

-- ── Wizard progress: durable, resumable draft state for one organisation's onboarding ────────
-- One row per organisation. `steps` holds each step's own form data as the wizard last saved it
-- (JSONB per step number as a string key — e.g. {"1": {...profile...}, "3": {...invites...}});
-- nothing here is a second copy of the organisation, its users, or their invitations — those stay
-- in `organisations` / `platform_users` / `auth_links`, read fresh whenever the wizard displays
-- their current status (e.g. Step 3's invitation list).
CREATE TABLE IF NOT EXISTS public.org_onboarding (
  org_id         TEXT PRIMARY KEY REFERENCES public.organisations(slug) ON DELETE CASCADE,
  status         TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active')),
  current_step   INT NOT NULL DEFAULT 1 CHECK (current_step BETWEEN 1 AND 6),
  completed_steps INT[] NOT NULL DEFAULT '{}',
  steps          JSONB NOT NULL DEFAULT '{}',
  created_by     TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by     TEXT NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  activated_by   TEXT,
  activated_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS org_onboarding_status_idx ON public.org_onboarding (status, updated_at DESC);
ALTER TABLE public.org_onboarding ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'org_onboarding' AND policyname = 'org_onboarding_service') THEN
    CREATE POLICY org_onboarding_service ON public.org_onboarding FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Per-organisation module entitlements ──────────────────────────────────────────────────────
-- An organisation with NO rows here has never been provisioned through the Release 3.1 wizard's
-- Service Provisioning step (every organisation created before this phase, and Cybernovr itself)
-- and is treated as fully enabled for every module — today's behaviour, unchanged (see
-- lib/serviceAccess.ts). Once an organisation has at least one row, access to every module is
-- explicit: missing, 'pending' or 'disabled' all deny; only 'enabled' or 'configured' allow.
CREATE TABLE IF NOT EXISTS public.org_service_grants (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL REFERENCES public.organisations(slug) ON DELETE CASCADE,
  service       TEXT NOT NULL CHECK (service IN ('vms', 'cnii_watch', 'threat_intel', 'secops_automation')),
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('enabled', 'configured', 'pending', 'disabled')),
  notes         TEXT,
  granted_by    TEXT NOT NULL,
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, service)
);
CREATE INDEX IF NOT EXISTS org_service_grants_org_idx ON public.org_service_grants (org_id);
ALTER TABLE public.org_service_grants ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'org_service_grants' AND policyname = 'org_service_grants_service') THEN
    CREATE POLICY org_service_grants_service ON public.org_service_grants FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';

-- Rollback (additive only; an organisation reverts to fully-enabled the moment its grant rows
-- are gone, and to "no saved draft" the moment its onboarding row is gone — neither action
-- touches the organisation, its users, or any other table):
--   DROP TABLE IF EXISTS public.org_service_grants;
--   DROP TABLE IF EXISTS public.org_onboarding;
