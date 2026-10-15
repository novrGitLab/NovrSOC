-- Phase P6 — Threat Information System: feeds, normalised indicators with provenance, matches
-- against an organisation's records, and analyst feedback. Additive and idempotent.
-- RLS: on, service role only. Indicators are public intelligence and shared; matches and
-- feedback belong to one organisation.

CREATE TABLE IF NOT EXISTS public.ti_feeds (
  id               TEXT PRIMARY KEY,                -- threatfox | urlhaus | feodo | cisa_kev
  name             TEXT NOT NULL,
  url              TEXT NOT NULL,
  enabled          BOOLEAN NOT NULL DEFAULT true,
  validity_days    INT,                             -- how long an indicator stays active after its source last listed it; NULL = no expiry
  last_run_at      TIMESTAMPTZ,
  last_success_at  TIMESTAMPTZ,
  last_error       TEXT,
  last_counts      JSONB
);
INSERT INTO public.ti_feeds (id, name, url, validity_days) VALUES
  ('threatfox', 'ThreatFox (abuse.ch) — malware IOCs', 'https://threatfox-api.abuse.ch/api/v1/', 30),
  ('urlhaus', 'URLhaus (abuse.ch) — malware distribution URLs', 'https://urlhaus-api.abuse.ch/v1/urls/recent/', 30),
  ('feodo', 'Feodo Tracker (abuse.ch) — botnet C2 servers', 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', 30),
  ('cisa_kev', 'CISA Known Exploited Vulnerabilities', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', NULL)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.ti_feed_runs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_id      TEXT NOT NULL REFERENCES public.ti_feeds(id),
  started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at  TIMESTAMPTZ,
  status       TEXT NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
  fetched      INT NOT NULL DEFAULT 0,
  new          INT NOT NULL DEFAULT 0,
  updated      INT NOT NULL DEFAULT 0,
  duplicates   INT NOT NULL DEFAULT 0,     -- the same source record seen again in one run
  invalid      INT NOT NULL DEFAULT 0,     -- records that failed validation
  error        TEXT
);
CREATE INDEX IF NOT EXISTS ti_feed_runs_feed_idx ON public.ti_feed_runs (feed_id, started_at DESC);

CREATE TABLE IF NOT EXISTS public.ti_indicators (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type             TEXT NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve')),
  value            TEXT NOT NULL,                -- normalised (lowercase; URLs as given, trimmed)
  first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  valid_until      TIMESTAMPTZ,                  -- NULL = no expiry (e.g. KEV)
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired')),
  max_confidence   INT,                          -- highest confidence any source stated (0-100); NULL = no source stated one
  tags             TEXT[] NOT NULL DEFAULT '{}',
  malware_families TEXT[] NOT NULL DEFAULT '{}',
  threat_types     TEXT[] NOT NULL DEFAULT '{}',
  mitre_techniques TEXT[] NOT NULL DEFAULT '{}', -- only technique ids a source itself listed
  source_count     INT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS ti_indicators_type_value_key ON public.ti_indicators (type, value);
CREATE INDEX IF NOT EXISTS ti_indicators_last_seen_idx ON public.ti_indicators (last_seen DESC);

-- Provenance: every source record that listed the indicator, with what that source said.
CREATE TABLE IF NOT EXISTS public.ti_indicator_sources (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_id  UUID NOT NULL REFERENCES public.ti_indicators(id) ON DELETE CASCADE,
  feed_id       TEXT NOT NULL REFERENCES public.ti_feeds(id),
  source_ref    TEXT NOT NULL,                  -- the record id in that feed
  confidence    INT,                            -- as the source states it (0-100), NULL if it states none
  first_seen    TIMESTAMPTZ,                    -- as the source states it
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context       JSONB NOT NULL DEFAULT '{}'     -- malware, threat type, reporter, reference, tags — source-reported claims
);
CREATE UNIQUE INDEX IF NOT EXISTS ti_indicator_sources_key ON public.ti_indicator_sources (indicator_id, feed_id, source_ref);

-- An indicator seen in one of an organisation's records.
CREATE TABLE IF NOT EXISTS public.ti_matches (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            TEXT NOT NULL,
  indicator_id      UUID NOT NULL REFERENCES public.ti_indicators(id) ON DELETE CASCADE,
  entity_type       TEXT NOT NULL CHECK (entity_type IN ('alert', 'asset', 'finding', 'case')),
  entity_id         TEXT NOT NULL,
  matched_field     TEXT NOT NULL,
  matched_value     TEXT NOT NULL,
  first_matched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_matched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status            TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'reviewed', 'promoted', 'dismissed')),
  reviewed_by       TEXT,
  case_id           UUID
);
CREATE UNIQUE INDEX IF NOT EXISTS ti_matches_key ON public.ti_matches (org_id, indicator_id, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS ti_matches_org_idx ON public.ti_matches (org_id, status, last_matched_at DESC);

-- Analyst verdicts and corrections, per organisation (never overwrite what a source said).
CREATE TABLE IF NOT EXISTS public.ti_feedback (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  indicator_id  UUID NOT NULL REFERENCES public.ti_indicators(id) ON DELETE CASCADE,
  verdict       TEXT NOT NULL CHECK (verdict IN ('confirmed_malicious', 'suspicious', 'benign', 'false_positive')),
  note          TEXT,
  actor         TEXT NOT NULL,
  at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ti_feedback_indicator_idx ON public.ti_feedback (org_id, indicator_id, at DESC);

-- Correlation position per organisation.
CREATE TABLE IF NOT EXISTS public.ti_correlation_state (
  org_id          TEXT PRIMARY KEY,
  last_alert_seen TIMESTAMPTZ,
  last_run_at     TIMESTAMPTZ,
  last_result     JSONB
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['ti_feeds', 'ti_feed_runs', 'ti_indicators', 'ti_indicator_sources', 'ti_matches', 'ti_feedback', 'ti_correlation_state'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;

-- Retention: expired indicators with no matches are removed after 180 days; feed runs after 90 days.
CREATE OR REPLACE FUNCTION public.purge_threat_info(p_indicator_days INT DEFAULT 180, p_run_days INT DEFAULT 90)
RETURNS TABLE (indicators_deleted INT, runs_deleted INT) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE i INT; r INT;
BEGIN
  DELETE FROM public.ti_indicators ti WHERE ti.status = 'expired' AND ti.last_seen < NOW() - make_interval(days => p_indicator_days)
    AND NOT EXISTS (SELECT 1 FROM public.ti_matches m WHERE m.indicator_id = ti.id);
  GET DIAGNOSTICS i = ROW_COUNT;
  DELETE FROM public.ti_feed_runs WHERE started_at < NOW() - make_interval(days => p_run_days);
  GET DIAGNOSTICS r = ROW_COUNT;
  RETURN QUERY SELECT i, r;
END $$;
REVOKE ALL ON FUNCTION public.purge_threat_info(INT, INT) FROM PUBLIC, anon, authenticated;
-- SELECT cron.schedule('purge-threat-info', '15 4 * * *', $$SELECT * FROM public.purge_threat_info()$$);
