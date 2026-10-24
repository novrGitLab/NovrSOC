-- Phase P25 — Threat Intelligence V1: sharing markings on provenance, platform timestamps for
-- exchange, MISP event reports (targeting and actor claims as the source states them), hosting
-- location of IP indicators, and TAXII 2.1 clients. Additive and idempotent; nothing is deleted.
-- Requires P6 (2026-10-15_p6_threat_info.sql) and P9 (the misp feed row).
-- RLS: on, service role only, like P6.

-- ── Platform timestamps on indicators (STIX created/modified, TAXII date_added) ─────────────
-- Existing rows: created_at is backfilled from first_seen, the earliest time the platform has.
ALTER TABLE public.ti_indicators ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
ALTER TABLE public.ti_indicators ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
UPDATE public.ti_indicators SET created_at = LEAST(first_seen, NOW()) WHERE created_at IS NULL;
UPDATE public.ti_indicators SET updated_at = GREATEST(created_at, last_seen) WHERE updated_at IS NULL;
ALTER TABLE public.ti_indicators ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE public.ti_indicators ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE public.ti_indicators ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE public.ti_indicators ALTER COLUMN updated_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS ti_indicators_created_idx ON public.ti_indicators (created_at, id);
CREATE INDEX IF NOT EXISTS ti_indicators_updated_idx ON public.ti_indicators (updated_at DESC);

-- The STIX identifier's UUID: UUIDv5 over "type:value" in the OASIS STIX namespace — the same
-- value services/tiStix.ts computes (indicator--<uuid>, or vulnerability--<uuid> for CVEs), so
-- TAXII can look an object up by its id. Generated, so it can never drift from the indicator.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;
ALTER TABLE public.ti_indicators ADD COLUMN IF NOT EXISTS stix_uuid UUID
  GENERATED ALWAYS AS (extensions.uuid_generate_v5('00abedb4-aa42-466c-9c01-fed23315a9b7'::uuid, type || ':' || value)) STORED;
CREATE INDEX IF NOT EXISTS ti_indicators_stix_uuid_idx ON public.ti_indicators (stix_uuid);

-- ── Sharing restrictions on every source record ─────────────────────────────────────────────
-- tlp: the Traffic Light Protocol marking the source applied (FIRST TLP 2.0 names).
-- distribution: MISP's own distribution level (0 your organisation only … 4 sharing group), NULL
-- for sources that have none. Public feeds are TLP:CLEAR. Existing MISP and OpenCTI rows came
-- from private instances without a recorded marking, so they are backfilled to AMBER, which
-- keeps them out of every export until a fresh MISP run records the real marking.
ALTER TABLE public.ti_indicator_sources ADD COLUMN IF NOT EXISTS tlp TEXT NOT NULL DEFAULT 'amber';
ALTER TABLE public.ti_indicator_sources ADD COLUMN IF NOT EXISTS distribution SMALLINT;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ti_indicator_sources_tlp_check') THEN
    ALTER TABLE public.ti_indicator_sources ADD CONSTRAINT ti_indicator_sources_tlp_check CHECK (tlp IN ('clear', 'green', 'amber', 'amber+strict', 'red'));
  END IF;
END $$;
UPDATE public.ti_indicator_sources SET tlp = 'clear' WHERE feed_id IN ('threatfox', 'urlhaus', 'feodo', 'cisa_kev') AND tlp = 'amber';

-- ── Feeds ───────────────────────────────────────────────────────────────────────────────────
-- OpenCTI is no longer used: its feed is switched off (its stored provenance is kept).
UPDATE public.ti_feeds SET enabled = false WHERE id = 'opencti';
INSERT INTO public.ti_feeds (id, name, url, validity_days) VALUES
  ('misp_events', 'MISP — event reports (targeting, actors, malware as tagged)', 'MISP_URL /events/restSearch', NULL)
ON CONFLICT (id) DO NOTHING;

-- ── Source reports: one row per MISP event, with what the source tagged ─────────────────────
-- Every field is the source's claim (its galaxy and taxonomy tags), never the platform's.
CREATE TABLE IF NOT EXISTS public.ti_reports (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_id            TEXT NOT NULL REFERENCES public.ti_feeds(id),
  source_ref         TEXT NOT NULL,                 -- the event uuid in that source
  title              TEXT NOT NULL,
  published_at       TIMESTAMPTZ,                   -- the source's event date
  source_updated_at  TIMESTAMPTZ,                   -- the source's last change
  tlp                TEXT NOT NULL DEFAULT 'amber' CHECK (tlp IN ('clear', 'green', 'amber', 'amber+strict', 'red')),
  distribution       SMALLINT,
  threat_level       TEXT,                          -- the source's own threat level wording
  tags               TEXT[] NOT NULL DEFAULT '{}',
  target_countries   TEXT[] NOT NULL DEFAULT '{}',  -- ISO 3166-1 alpha-2, only where the source tagged a target
  target_sectors     TEXT[] NOT NULL DEFAULT '{}',
  actors             TEXT[] NOT NULL DEFAULT '{}',  -- threat-actor galaxy names the source attached
  malware            TEXT[] NOT NULL DEFAULT '{}',
  attack_patterns    TEXT[] NOT NULL DEFAULT '{}',  -- ATT&CK technique ids the source attached
  attribute_count    INT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS ti_reports_key ON public.ti_reports (feed_id, source_ref);
CREATE INDEX IF NOT EXISTS ti_reports_published_idx ON public.ti_reports (published_at DESC);
CREATE INDEX IF NOT EXISTS ti_reports_countries_idx ON public.ti_reports USING GIN (target_countries);
CREATE INDEX IF NOT EXISTS ti_reports_actors_idx ON public.ti_reports USING GIN (actors);

-- ── Where an IP indicator is hosted ─────────────────────────────────────────────────────────
-- Hosting location only — never an attack origin or target. method says how it was found:
-- source_stated (the feed said so) or geoip (a lookup, approximate). precision is 'state' only
-- when the provider named a Nigerian state; otherwise 'country' (or 'unknown').
CREATE TABLE IF NOT EXISTS public.ti_indicator_geo (
  indicator_id  UUID PRIMARY KEY REFERENCES public.ti_indicators(id) ON DELETE CASCADE,
  country_code  TEXT,
  country       TEXT,
  region        TEXT,
  city          TEXT,
  asn           TEXT,
  as_org        TEXT,
  method        TEXT NOT NULL CHECK (method IN ('source_stated', 'geoip')),
  provider      TEXT NOT NULL,
  precision     TEXT NOT NULL CHECK (precision IN ('state', 'country', 'unknown')),
  looked_up_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ti_indicator_geo_country_idx ON public.ti_indicator_geo (country_code, region);

-- ── TAXII 2.1 clients ───────────────────────────────────────────────────────────────────────
-- HTTP Basic credentials: key_id is the username, the secret is shown once and stored as a
-- scrypt hash. A client reads only the collections listed, and never above max_tlp.
CREATE TABLE IF NOT EXISTS public.ti_taxii_clients (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  key_id        TEXT NOT NULL UNIQUE,
  secret_hash   TEXT NOT NULL,
  collections   TEXT[] NOT NULL DEFAULT '{}',
  max_tlp       TEXT NOT NULL DEFAULT 'clear' CHECK (max_tlp IN ('clear', 'green', 'amber')),
  enabled       BOOLEAN NOT NULL DEFAULT true,
  created_by    TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at  TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['ti_reports', 'ti_indicator_geo', 'ti_taxii_clients'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;
