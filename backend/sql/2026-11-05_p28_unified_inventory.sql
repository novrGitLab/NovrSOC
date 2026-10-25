-- Phase P28 — Release 2 Stage 5: unified asset inventory (Wazuh / Vulnerability / Cloud / Other).
-- Additive and idempotent: safe to re-run. vms_assets stays the one and only asset table — this
-- adds nullable cloud linkage columns and one new table for human-confirmed "same machine" links.
-- RLS: on, one service-role policy, nothing else, matching every other backend-written table.
--
-- The four inventory categories are views (predicates) over vms_assets, not separate stores:
--   Wazuh Assets         asset_type = 'endpoint' AND wazuh_agent_id IS NOT NULL
--   Vulnerability Assets  last_assessed_at IS NOT NULL OR has any vms_findings row
--   Cloud Assets          asset_type = 'cloud_resource' OR cloud_ref IS NOT NULL
--   Other Assets          none of the above
-- An asset can be in more than one category at once.

-- ── Cloud linkage (nullable; no backfill — nothing is cloud-sourced yet) ───────────────────────
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS cloud_provider TEXT CHECK (cloud_provider IN ('aws', 'azure', 'gcp', 'oci', 'other'));
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS cloud_ref TEXT;          -- ARN / resource id, as the source names it
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS cloud_account TEXT;      -- account / subscription / project id

ALTER TABLE public.vms_assets DROP CONSTRAINT IF EXISTS vms_assets_asset_type_check;
ALTER TABLE public.vms_assets ADD CONSTRAINT vms_assets_asset_type_check
  CHECK (asset_type IN ('domain', 'host', 'ip', 'endpoint', 'asn', 'cidr', 'cloud_resource'));

CREATE UNIQUE INDEX IF NOT EXISTS vms_assets_cloud_ref_key ON public.vms_assets (org_id, cloud_provider, cloud_ref) WHERE cloud_ref IS NOT NULL;

-- ── Human-confirmed relationships between two assets ("is this the same machine?") ────────────
-- Never written automatically. vmsCorrelation.ts's same_address inference stays separate and
-- derived-on-read; this table is only for a person explicitly confirming (or rejecting a
-- suggestion for) a relationship between two asset rows.
CREATE TABLE IF NOT EXISTS public.vms_asset_links (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  asset_a       UUID NOT NULL REFERENCES public.vms_assets(id) ON DELETE CASCADE,
  asset_b       UUID NOT NULL REFERENCES public.vms_assets(id) ON DELETE CASCADE,
  relation      TEXT NOT NULL CHECK (relation IN ('same_machine', 'serves', 'resolves_to')),
  basis         TEXT NOT NULL CHECK (basis IN ('confirmed', 'rejected')),
  note          TEXT,
  confirmed_by  TEXT NOT NULL,
  confirmed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (asset_a <> asset_b)
);
CREATE UNIQUE INDEX IF NOT EXISTS vms_asset_links_pair_key ON public.vms_asset_links (org_id, asset_a, asset_b, relation);
CREATE INDEX IF NOT EXISTS vms_asset_links_org_idx ON public.vms_asset_links (org_id);
ALTER TABLE public.vms_asset_links ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'vms_asset_links' AND policyname = 'vms_asset_links_service') THEN
    CREATE POLICY vms_asset_links_service ON public.vms_asset_links FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';

-- Rollback (additive only; nothing to migrate back):
--   DROP TABLE IF EXISTS public.vms_asset_links;
--   ALTER TABLE public.vms_assets DROP CONSTRAINT IF EXISTS vms_assets_asset_type_check;
--   ALTER TABLE public.vms_assets ADD CONSTRAINT vms_assets_asset_type_check CHECK (asset_type IN ('domain', 'host', 'ip', 'endpoint', 'asn', 'cidr'));
--   ALTER TABLE public.vms_assets DROP COLUMN IF EXISTS cloud_provider, DROP COLUMN IF EXISTS cloud_ref, DROP COLUMN IF EXISTS cloud_account;
