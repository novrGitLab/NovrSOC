-- Phase P21 — analysts act only on organisations they are assigned to. Additive and idempotent.
--
-- lib/resolveOrg.ts: an analyst's own organisation (token org_id) is always allowed; any other
-- organisation named in X-Org-Id needs a row here for that analyst (token sub = platform_users.id).
-- super_admin keeps access to every organisation. Until this table exists, analysts are limited to
-- their own organisation (fail closed) and the denial is audited.
--
-- Rows are written only by the backend (POST/DELETE /api/admin/org-assignments, super_admin,
-- audited). Removing a row takes effect on the next request; no token needs to be reissued.

CREATE TABLE IF NOT EXISTS public.staff_org_assignments (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      TEXT NOT NULL,          -- platform_users.id (the JWT sub)
  user_email   TEXT NOT NULL,          -- for audit readability; access is checked by user_id
  org_slug     TEXT NOT NULL REFERENCES public.organisations (slug) ON DELETE CASCADE,
  assigned_by  TEXT NOT NULL,
  assigned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  note         TEXT,
  UNIQUE (user_id, org_slug)
);
CREATE INDEX IF NOT EXISTS staff_org_assignments_org_idx ON public.staff_org_assignments (org_slug);

-- Service role only, same as the other backend-written tables.
ALTER TABLE public.staff_org_assignments ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'staff_org_assignments' AND policyname = 'staff_org_assignments_service_role') THEN
    CREATE POLICY staff_org_assignments_service_role ON public.staff_org_assignments FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';

-- Rollback (only if no assignment should survive): DROP TABLE public.staff_org_assignments;
-- Analysts then fall back to their own organisation only.
