-- Phase P9 — CNII Watch on VMS and the Threat Information System.
-- Additive and idempotent: safe to re-run. Needs P4 (VMS), P5 (findings), P6 (threat information)
-- and P7 (schedules). RLS: on, service role only, as every backend-written table.
--
-- CNII Watch does not keep its own asset or findings store. An organisation is classified into a
-- CNII sector (cnii_org_profiles); its assets, findings and indicator matches are the VMS and
-- Threat Information records. What this file adds:
--   • sector classification per organisation, with its history;
--   • a passive activity: scope entries may now authorise passive monitoring only
--     (allow_discovery = false), and an 'asn' entry registers an autonomous system for passive
--     monitoring (it never authorises touching anything);
--   • a 'passive_osint' job kind, run by the backend (SpiderFoot passive modules, CT logs, RIPE
--     Stat, OpenCTI) — never by the scanner worker;
--   • vms_observations: what each passive source reported about an asset, with its confidence;
--   • evidence_class on findings, so a scanner check is never shown like a version match;
--   • OpenCTI and MISP as Threat Information feeds;
--   • retention for observations and the legacy CNII raw payloads.

-- ── Sector classification ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.cnii_org_profiles (
  org_id                 TEXT PRIMARY KEY,             -- organisations.slug
  sector_id              TEXT NOT NULL,                -- lib/cnii-sectors.ts
  subfield               TEXT,
  designation            TEXT NOT NULL DEFAULT 'candidate' CHECK (designation IN ('designated', 'candidate')),
  designation_reference  TEXT,                         -- gazette / regulator letter / contract, when designated
  notes                  TEXT,
  created_by             TEXT NOT NULL,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by             TEXT NOT NULL,
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS cnii_org_profiles_sector_idx ON public.cnii_org_profiles (sector_id);

-- Every classification change, kept (the profile row holds only the current one).
CREATE TABLE IF NOT EXISTS public.cnii_profile_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor       TEXT NOT NULL,
  from_value  JSONB,
  to_value    JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS cnii_profile_events_org_idx ON public.cnii_profile_events (org_id, at DESC);

-- ── Scope: passive-only entries and autonomous systems ─────────────────────────────────────
-- allow_discovery = true keeps today's meaning (DNS lookups and HTTP probing by the worker).
-- false = passive monitoring only: third-party sources are asked about the target, nothing
-- connects to it.
ALTER TABLE public.vms_scopes ADD COLUMN IF NOT EXISTS allow_discovery BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE public.vms_scopes DROP CONSTRAINT IF EXISTS vms_scopes_kind_check;
ALTER TABLE public.vms_scopes ADD CONSTRAINT vms_scopes_kind_check CHECK (kind IN ('domain', 'ip', 'cidr', 'asn'));
-- An autonomous system is registered for passive monitoring only.
ALTER TABLE public.vms_scopes DROP CONSTRAINT IF EXISTS vms_scopes_asn_passive_check;
ALTER TABLE public.vms_scopes ADD CONSTRAINT vms_scopes_asn_passive_check
  CHECK (kind <> 'asn' OR (NOT allow_discovery AND NOT allow_port_scan AND NOT allow_vuln_scan));

-- ── Jobs: passive collection ────────────────────────────────────────────────────────────────
ALTER TABLE public.vms_scan_jobs DROP CONSTRAINT IF EXISTS vms_scan_jobs_kind_check;
ALTER TABLE public.vms_scan_jobs ADD CONSTRAINT vms_scan_jobs_kind_check CHECK (kind IN ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas', 'passive_osint'));
ALTER TABLE public.vms_scan_schedules DROP CONSTRAINT IF EXISTS vms_scan_schedules_kind_check;
ALTER TABLE public.vms_scan_schedules ADD CONSTRAINT vms_scan_schedules_kind_check CHECK (kind IN ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas', 'passive_osint'));

-- ── Inventory ───────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.vms_assets DROP CONSTRAINT IF EXISTS vms_assets_asset_type_check;
ALTER TABLE public.vms_assets ADD CONSTRAINT vms_assets_asset_type_check CHECK (asset_type IN ('domain', 'host', 'ip', 'endpoint', 'asn', 'cidr'));
-- confirmed: the authorised scope entry itself, or seen by our own scanner inside scope.
-- probable:  reported by a passive source and inside an authorised domain (e.g. a CT-log name).
ALTER TABLE public.vms_assets ADD COLUMN IF NOT EXISTS confidence TEXT NOT NULL DEFAULT 'confirmed';
ALTER TABLE public.vms_assets DROP CONSTRAINT IF EXISTS vms_assets_confidence_check;
ALTER TABLE public.vms_assets ADD CONSTRAINT vms_assets_confidence_check CHECK (confidence IN ('confirmed', 'probable'));

-- What a passive source reported about an asset. One row per (asset, source, kind, key); a
-- repeated sighting moves last_seen and seen_count. Third-party claims (Shodan open ports, CVEs
-- guessed from versions) are observations here — never shown as our own scan results.
CREATE TABLE IF NOT EXISTS public.vms_observations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       TEXT NOT NULL,
  asset_id     UUID NOT NULL REFERENCES public.vms_assets(id) ON DELETE CASCADE,
  source       TEXT NOT NULL,                  -- spiderfoot:<module> | crtsh | ripestat | dns | opencti | legacy_cnii
  kind         TEXT NOT NULL CHECK (kind IN ('dns', 'certificate', 'service', 'registry', 'geo', 'reputation', 'vulnerability_claim', 'related_host', 'announced_prefix')),
  key          TEXT NOT NULL,                  -- what makes it distinct within (source, kind)
  value        JSONB NOT NULL DEFAULT '{}',    -- redacted, size-capped
  confidence   TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
  first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  seen_count   INT NOT NULL DEFAULT 1,
  last_job_id  UUID
);
CREATE UNIQUE INDEX IF NOT EXISTS vms_observations_key ON public.vms_observations (asset_id, source, kind, key);
CREATE INDEX IF NOT EXISTS vms_observations_org_idx ON public.vms_observations (org_id, last_seen DESC);

-- ── Findings: what kind of evidence stands behind each one ──────────────────────────────────
--   scanner_check      our scanner ran a check against the target and it fired (Nuclei, OpenVAS)
--   package_inventory  an installed package version reported by the endpoint agent (Wazuh)
--   version_match      a product/version a third party saw publicly falls in a vulnerable range —
--                      NOT confirmed; never priority above P3 until a scanner confirms it
--   exposure           a publicly reachable service or misconfiguration, not a vulnerability
--   intelligence       a third-party claim about the asset (feed, OpenCTI, MISP), unconfirmed
ALTER TABLE public.vms_findings DROP CONSTRAINT IF EXISTS vms_findings_source_class_check;
ALTER TABLE public.vms_findings ADD CONSTRAINT vms_findings_source_class_check CHECK (source_class IN ('active_scan', 'wazuh', 'passive_intel'));
ALTER TABLE public.vms_findings ADD COLUMN IF NOT EXISTS evidence_class TEXT NOT NULL DEFAULT 'scanner_check';
ALTER TABLE public.vms_findings DROP CONSTRAINT IF EXISTS vms_findings_evidence_class_check;
ALTER TABLE public.vms_findings ADD CONSTRAINT vms_findings_evidence_class_check CHECK (evidence_class IN ('scanner_check', 'package_inventory', 'version_match', 'exposure', 'intelligence'));
UPDATE public.vms_findings SET evidence_class = 'package_inventory' WHERE source_class = 'wazuh' AND evidence_class = 'scanner_check';
CREATE INDEX IF NOT EXISTS vms_findings_org_evidence_idx ON public.vms_findings (org_id, evidence_class);
-- Wazuh findings are package-inventory evidence. Set here so the Wazuh sync code needs no change.
CREATE OR REPLACE FUNCTION public.vms_findings_evidence_default() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.source_class = 'wazuh' AND NEW.evidence_class = 'scanner_check' THEN NEW.evidence_class := 'package_inventory'; END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS vms_findings_evidence_default ON public.vms_findings;
CREATE TRIGGER vms_findings_evidence_default BEFORE INSERT ON public.vms_findings
  FOR EACH ROW EXECUTE FUNCTION public.vms_findings_evidence_default();

-- ── Threat Information: OpenCTI and MISP as feeds ───────────────────────────────────────────
-- Pulled only when configured (OPENCTI_URL + OPENCTI_TOKEN; MISP_URL + MISP_API_KEY); otherwise
-- Platform Health shows them as not configured, not failing.
INSERT INTO public.ti_feeds (id, name, url, validity_days) VALUES
  ('opencti', 'OpenCTI — indicators (own instance)', 'OPENCTI_URL /graphql', 30),
  ('misp', 'MISP — to_ids attributes (own instance)', 'MISP_URL /attributes/restSearch', 30)
ON CONFLICT (id) DO NOTHING;

-- ── Legacy CNII rows (2026-10-cnii-assets.sql), until each is imported into an organisation ──
DO $$
BEGIN
  IF to_regclass('public.cnii_assets') IS NOT NULL THEN
    ALTER TABLE public.cnii_assets ADD COLUMN IF NOT EXISTS imported_org_id TEXT;
    ALTER TABLE public.cnii_assets ADD COLUMN IF NOT EXISTS imported_asset_id UUID;
    ALTER TABLE public.cnii_assets ADD COLUMN IF NOT EXISTS imported_at TIMESTAMPTZ;
    ALTER TABLE public.cnii_assets ADD COLUMN IF NOT EXISTS imported_by TEXT;
  END IF;
END $$;

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['cnii_org_profiles', 'cnii_profile_events', 'vms_observations'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;

-- Retention: observations not seen for 365 days are removed; the legacy CNII raw SpiderFoot and
-- OpenCTI payloads (which can hold e-mail addresses and phone numbers) are cleared after 30 days.
-- Profiles, their history, findings and evidence are kept.
CREATE OR REPLACE FUNCTION public.purge_cnii_history(p_observation_days INT DEFAULT 365, p_raw_days INT DEFAULT 30)
RETURNS TABLE (observations_deleted BIGINT, raw_payloads_cleared BIGINT) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE o BIGINT := 0; r BIGINT := 0;
BEGIN
  DELETE FROM public.vms_observations WHERE last_seen < NOW() - make_interval(days => p_observation_days);
  GET DIAGNOSTICS o = ROW_COUNT;
  IF to_regclass('public.cnii_assets') IS NOT NULL THEN
    UPDATE public.cnii_assets SET raw_spiderfoot = NULL, raw_opencti = NULL
     WHERE (raw_spiderfoot IS NOT NULL OR raw_opencti IS NOT NULL) AND last_seen < NOW() - make_interval(days => p_raw_days);
    GET DIAGNOSTICS r = ROW_COUNT;
  END IF;
  RETURN QUERY SELECT o, r;
END $$;
REVOKE ALL ON FUNCTION public.purge_cnii_history(INT, INT) FROM PUBLIC, anon, authenticated;
-- SELECT cron.schedule('purge-cnii-history', '45 4 * * *', $$SELECT * FROM public.purge_cnii_history()$$);
