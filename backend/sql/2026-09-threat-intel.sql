-- Threat-intelligence persistence — run once in the Supabase SQL Editor.
--
-- Live-checked against the actual database on 2026-09-07 BEFORE any of the code that uses these
-- tables was written:
--   * `public.nigeria_state_threats` ALREADY EXISTS (37 rows — every state + FCT — pre-seeded
--     with lat/lng and zeroed counters, created 2026-08-11). The Nigeria map reads it via
--     GET /api/geo/nigeria/states, and the collector now writes state aggregates back to it.
--     It is NOT recreated or altered here; nothing below touches it.
--   * The `nigeria_intel` and `global_intel` SCHEMAS DO NOT EXIST (PostgREST returns PGRST106
--     "Invalid schema" for both). Even if they were created, Supabase's PostgREST cannot read a
--     non-`public` schema until that schema is explicitly added to the project's "Exposed
--     schemas" API setting — and supabase-js's .from('nigeria_intel.advisories') does not mean
--     schema.table anyway; it looks for a table literally named "nigeria_intel.advisories" in
--     `public`. All three tables below therefore live in `public`, which is what the code queries.
--
-- Until this runs: the collector keeps advisories in a bounded in-memory buffer (they show on
-- the Nigerian Threat Feed but are lost on restart, and `advisories_persisted` in the collect
-- response is false), and the global intel job's OTX/MITRE syncs no-op with one log line each.
-- State aggregates on the Nigeria map already persist without this file, because that table
-- already exists.

-- Advisories collected from ngCERT and OTX by services/nigerianIntelCollector.ts.
CREATE TABLE IF NOT EXISTS public.nigeria_advisories (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  advisory_id  TEXT UNIQUE NOT NULL,
  source       TEXT NOT NULL,
  title        TEXT NOT NULL,
  description  TEXT,
  severity     TEXT DEFAULT 'medium',
  threat_type  TEXT,
  tags         TEXT[] DEFAULT '{}',
  source_url   TEXT,
  published_at TIMESTAMPTZ DEFAULT NOW(),
  org_id       TEXT DEFAULT 'global',
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS nigeria_advisories_published_idx ON public.nigeria_advisories (published_at DESC);

-- OTX pulses synced by jobs/globalIntelJob.ts. NOTE: OTX_API_KEY in the current environment is
-- rejected (403 on every endpoint, and it's 31 chars where a real OTX key is 64), so this table
-- stays empty until a valid key is set — creating it is harmless either way.
CREATE TABLE IF NOT EXISTS public.threat_pulses (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pulse_id         TEXT UNIQUE NOT NULL,
  name             TEXT NOT NULL,
  description      TEXT,
  author           TEXT,
  tlp              TEXT DEFAULT 'white',
  tags             TEXT[] DEFAULT '{}',
  ioc_count        INTEGER DEFAULT 0,
  malware_families JSONB DEFAULT '[]',
  attack_ids       TEXT[] DEFAULT '{}',
  published_at     TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- MITRE technique detections aggregated from Wazuh alerts. This one does NOT depend on any
-- third-party key — it reads the Wazuh indexer directly, so it populates as soon as the table
-- exists and the indexer has ATT&CK-tagged alerts in the last 24h.
CREATE TABLE IF NOT EXISTS public.mitre_detections (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  technique_id    TEXT NOT NULL,
  tactic          TEXT,
  detection_count INTEGER DEFAULT 0,
  agent_names     TEXT[] DEFAULT '{}',
  last_detected   TIMESTAMPTZ DEFAULT NOW(),
  org_id          TEXT DEFAULT 'cybernovr',
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- The job upserts on (technique_id, org_id) — that needs a matching unique constraint or the
-- upsert fails with 42P10, the same way org_setup's did.
CREATE UNIQUE INDEX IF NOT EXISTS mitre_detections_technique_org_idx ON public.mitre_detections (technique_id, org_id);

-- RLS. Re-runnable: Postgres has no "CREATE POLICY IF NOT EXISTS", so drop-then-create.
ALTER TABLE public.nigeria_advisories ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "nigeria_advisories_service_role" ON public.nigeria_advisories;
CREATE POLICY "nigeria_advisories_service_role" ON public.nigeria_advisories
  FOR ALL USING (auth.role() = 'service_role');

ALTER TABLE public.threat_pulses ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "threat_pulses_service_role" ON public.threat_pulses;
CREATE POLICY "threat_pulses_service_role" ON public.threat_pulses
  FOR ALL USING (auth.role() = 'service_role');

ALTER TABLE public.mitre_detections ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "mitre_detections_service_role" ON public.mitre_detections;
CREATE POLICY "mitre_detections_service_role" ON public.mitre_detections
  FOR ALL USING (auth.role() = 'service_role');
