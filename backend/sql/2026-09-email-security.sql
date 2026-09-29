-- NovrSOC — Email Security module (DMARC SaaS, Intellicode Phish ID, Messaging Suite).
-- Run once in the Supabase SQL editor; safe to re-run. Until this exists the Email Security
-- pages say "not set up" rather than showing anything.
--
-- Every table carries org_id (tenant isolation — the API always filters on the caller's org).
-- No secrets are stored here: Microsoft 365 uses the app's client credentials from the backend
-- environment plus the tenant id recorded on consent; Google Workspace uses a service-account
-- key from the environment plus the delegated admin address. Message bodies are never stored.

BEGIN;  -- all or nothing

-- Preflight: CREATE TABLE IF NOT EXISTS silently skips a same-named table with a different
-- shape. Refuse to continue if any of these names is already taken by something else.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['email_domains','email_dns_checks','dmarc_aggregate_reports','dmarc_records','email_sending_sources',
                           'brand_profiles','phishing_domains','phishing_observations','messaging_connections',
                           'email_events','email_indicators','email_alerts']
  LOOP
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = t)
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = t AND column_name = 'org_id' AND data_type = 'text') THEN
      RAISE EXCEPTION 'public.% already exists with a different structure — not modifying it. Rename or remove it first.', t;
    END IF;
  END LOOP;
END $$;

-- ── DMARC SaaS ──────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.email_domains (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          TEXT NOT NULL,
  domain          TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',       -- pending | healthy | warning | critical | error
  dmarc_policy    TEXT,                                  -- none | quarantine | reject (as published)
  spf_status      TEXT,                                  -- pass | warn | fail | missing | error
  dkim_status     TEXT,                                  -- pass | warn | fail | not_found | error
  dmarc_status    TEXT,
  dkim_selectors  TEXT[] NOT NULL DEFAULT '{}',          -- selectors to check besides the common list
  health_score    INT,
  sending_sources INT NOT NULL DEFAULT 0,
  last_checked    TIMESTAMPTZ,
  last_error      TEXT,
  created_by      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, domain)
);

-- One row per DNS inspection (history of SPF / DKIM / DMARC as published).
CREATE TABLE IF NOT EXISTS public.email_dns_checks (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  domain_id   UUID REFERENCES public.email_domains(id) ON DELETE CASCADE,
  domain      TEXT NOT NULL,
  result      JSONB NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email_dns_checks_domain_idx ON public.email_dns_checks (org_id, domain, created_at DESC);

-- One row per aggregate (RUA) report received.
-- Named dmarc_aggregate_reports because an unrelated, empty legacy table public.dmarc_reports
-- (uuid org_id FK to organisations, one row per source IP) already exists in this database and
-- nothing uses it. This script deliberately leaves that table alone rather than dropping it.
CREATE TABLE IF NOT EXISTS public.dmarc_aggregate_reports (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  domain           TEXT NOT NULL,
  report_id        TEXT NOT NULL,
  reporter         TEXT NOT NULL,          -- reporting organisation (google.com, Outlook.com, …)
  reporter_email   TEXT,
  date_begin       TIMESTAMPTZ NOT NULL,
  date_end         TIMESTAMPTZ NOT NULL,
  policy_published JSONB,
  record_count     INT NOT NULL DEFAULT 0,
  message_count    BIGINT NOT NULL DEFAULT 0,
  pass_count       BIGINT NOT NULL DEFAULT 0,
  received_via     TEXT NOT NULL,          -- upload | mailgun
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, reporter, report_id)
);
CREATE INDEX IF NOT EXISTS dmarc_aggregate_reports_domain_idx ON public.dmarc_aggregate_reports (org_id, domain, date_begin DESC);

-- One row per <record> in a report (source IP × identifiers × results).
CREATE TABLE IF NOT EXISTS public.dmarc_records (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         TEXT NOT NULL,
  report_id      UUID NOT NULL REFERENCES public.dmarc_aggregate_reports(id) ON DELETE CASCADE,
  domain         TEXT NOT NULL,
  source_ip      TEXT NOT NULL,
  message_count  BIGINT NOT NULL,
  disposition    TEXT,
  header_from    TEXT,
  envelope_from  TEXT,
  spf_result     TEXT,
  spf_domain     TEXT,
  spf_aligned    BOOLEAN,
  dkim_result    TEXT,
  dkim_domain    TEXT,
  dkim_aligned   BOOLEAN,
  dmarc_pass     BOOLEAN NOT NULL,
  date_begin     TIMESTAMPTZ NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dmarc_records_domain_idx ON public.dmarc_records (org_id, domain, date_begin DESC);
CREATE INDEX IF NOT EXISTS dmarc_records_ip_idx ON public.dmarc_records (org_id, source_ip);

CREATE TABLE IF NOT EXISTS public.email_sending_sources (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                TEXT NOT NULL,
  domain                TEXT NOT NULL,
  source_ip             TEXT NOT NULL,
  provider              TEXT,                 -- from reverse DNS, when it names a known sender
  ptr                   TEXT,
  classification        TEXT NOT NULL DEFAULT 'unknown',   -- known | unknown | suspicious
  classification_reason TEXT,
  classified_by         TEXT NOT NULL DEFAULT 'system',    -- system | <analyst email>
  message_count         BIGINT NOT NULL DEFAULT 0,
  spf_pass              BIGINT NOT NULL DEFAULT 0,
  dkim_pass             BIGINT NOT NULL DEFAULT 0,
  dmarc_pass            BIGINT NOT NULL DEFAULT 0,
  first_seen            TIMESTAMPTZ NOT NULL,
  last_seen             TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, domain, source_ip)
);
CREATE INDEX IF NOT EXISTS email_sending_sources_ip_idx ON public.email_sending_sources (org_id, source_ip);

-- ── Intellicode Phish ID ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.brand_profiles (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             TEXT NOT NULL UNIQUE,
  organization_name  TEXT NOT NULL,
  primary_domains    TEXT[] NOT NULL DEFAULT '{}',
  additional_domains TEXT[] NOT NULL DEFAULT '{}',
  keywords           TEXT[] NOT NULL DEFAULT '{}',
  legitimate_domains TEXT[] NOT NULL DEFAULT '{}',
  legitimate_urls    TEXT[] NOT NULL DEFAULT '{}',
  logo_url           TEXT,
  last_discovery     TIMESTAMPTZ,
  updated_by         TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.phishing_domains (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          TEXT NOT NULL,
  domain          TEXT NOT NULL,
  brand_domain    TEXT,                     -- which protected domain it resembles
  techniques      TEXT[] NOT NULL DEFAULT '{}',
  similarity      NUMERIC,
  discovered_via  TEXT NOT NULL,            -- permutation | certificate_transparency | manual | email
  status          TEXT NOT NULL DEFAULT 'discovered',
      -- discovered | under_investigation | suspicious | confirmed_phishing | false_positive | resolved
  risk            TEXT NOT NULL DEFAULT 'informational',  -- informational | low | medium | high | critical
  risk_score      INT NOT NULL DEFAULT 0,
  risk_signals    JSONB NOT NULL DEFAULT '[]',
  intel           JSONB,                    -- registration, DNS, IPs, ASN, certificates
  website         JSONB,                    -- last safe inspection
  resolves        BOOLEAN,
  assigned_to     TEXT,
  alert_id        UUID,
  opencti_id      TEXT,
  first_observed  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_observed   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_enriched   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, domain)
);
CREATE INDEX IF NOT EXISTS phishing_domains_status_idx ON public.phishing_domains (org_id, status, risk);

-- Timeline + analyst notes for a phishing domain.
CREATE TABLE IF NOT EXISTS public.phishing_observations (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             TEXT NOT NULL,
  phishing_domain_id UUID NOT NULL REFERENCES public.phishing_domains(id) ON DELETE CASCADE,
  kind               TEXT NOT NULL,         -- discovered | enriched | inspected | status | note | email | opencti
  summary            TEXT NOT NULL,
  data               JSONB,
  actor              TEXT NOT NULL DEFAULT 'system',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS phishing_observations_domain_idx ON public.phishing_observations (phishing_domain_id, created_at DESC);

-- ── Messaging Suite ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.messaging_connections (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             TEXT NOT NULL,
  provider           TEXT NOT NULL,         -- microsoft365 | google_workspace | gateway
  status             TEXT NOT NULL,         -- connected | not_connected | auth_error | permission_error | sync_error
  tenant_id          TEXT,
  tenant_name        TEXT,
  admin_email        TEXT,
  scopes             TEXT[] NOT NULL DEFAULT '{}',
  sync_cursor        TEXT,
  last_sync          TIMESTAMPTZ,
  last_success_sync  TIMESTAMPTZ,
  last_event_at      TIMESTAMPTZ,
  last_error         TEXT,
  connected_by       TEXT,
  connected_at       TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, provider)
);

CREATE TABLE IF NOT EXISTS public.email_events (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id               TEXT NOT NULL,
  provider             TEXT NOT NULL,
  provider_event_id    TEXT NOT NULL,
  message_id           TEXT,
  sender               TEXT,
  sender_domain        TEXT,
  recipient            TEXT,
  subject              TEXT,               -- only when the provider supplies it
  received_at          TIMESTAMPTZ NOT NULL,
  source_ip            TEXT,
  spf                  TEXT,
  dkim                 TEXT,
  dmarc                TEXT,
  urls                 JSONB NOT NULL DEFAULT '[]',
  attachments          JSONB NOT NULL DEFAULT '[]',
  ti_matches           JSONB NOT NULL DEFAULT '[]',
  categories           TEXT[] NOT NULL DEFAULT '{}',
  detection            TEXT NOT NULL,      -- clean | phishing | malware | spam | spoofing | bec | malicious_url | suspicious_attachment | impersonation | auth_failure
  severity             TEXT NOT NULL,      -- informational | low | medium | high | critical
  action               TEXT NOT NULL,      -- allow | flag | quarantine | block
  action_by            TEXT NOT NULL,      -- the system that took the action (never 'novrsoc' unless it did)
  mailbox              TEXT,
  tenant               TEXT,
  analysis             JSONB,              -- URL / attachment analysis results
  alert_id             UUID,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, provider, provider_event_id)
);
CREATE INDEX IF NOT EXISTS email_events_received_idx ON public.email_events (org_id, received_at DESC);
CREATE INDEX IF NOT EXISTS email_events_sender_idx ON public.email_events (org_id, sender);
CREATE INDEX IF NOT EXISTS email_events_recipient_idx ON public.email_events (org_id, recipient);
CREATE INDEX IF NOT EXISTS email_events_sev_idx ON public.email_events (org_id, severity, detection);
CREATE INDEX IF NOT EXISTS email_events_provider_idx ON public.email_events (org_id, provider);
CREATE INDEX IF NOT EXISTS email_events_ip_idx ON public.email_events (org_id, source_ip);

-- ── Shared: indicators + alerts ─────────────────────────────────────────────────────────

-- Every domain / URL / IP / hash / address seen by any of the three modules, with references
-- back to where it was seen. This is what correlation joins on.
CREATE TABLE IF NOT EXISTS public.email_indicators (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  type        TEXT NOT NULL,     -- domain | url | ip | sha256 | email
  value       TEXT NOT NULL,
  refs        JSONB NOT NULL DEFAULT '[]',   -- [{ module, kind, id }]
  first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, type, value)
);
CREATE INDEX IF NOT EXISTS email_indicators_value_idx ON public.email_indicators (org_id, value);

CREATE TABLE IF NOT EXISTS public.email_alerts (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,
  correlation_key  TEXT NOT NULL,     -- one alert per incident; repeat observations attach here
  severity         TEXT NOT NULL,
  source_module    TEXT NOT NULL,     -- dmarc | phishid | messaging (module that opened it)
  modules          TEXT[] NOT NULL DEFAULT '{}',   -- every module that has contributed evidence
  detection_type   TEXT NOT NULL,
  entity           TEXT NOT NULL,
  title            TEXT NOT NULL,
  description      TEXT,
  evidence         JSONB NOT NULL DEFAULT '[]',
  timeline         JSONB NOT NULL DEFAULT '[]',
  indicators       JSONB NOT NULL DEFAULT '[]',
  related_events   JSONB NOT NULL DEFAULT '[]',
  occurrences      INT NOT NULL DEFAULT 1,
  status           TEXT NOT NULL DEFAULT 'new',   -- new | investigating | resolved | false_positive | suppressed
  assigned_to      TEXT,
  case_id          UUID,
  case_number      TEXT,
  first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, correlation_key)
);
CREATE INDEX IF NOT EXISTS email_alerts_status_idx ON public.email_alerts (org_id, status, severity, last_seen DESC);

-- ── Row-level security: service role only (the backend), same as the rest of the schema ──

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['email_domains','email_dns_checks','dmarc_aggregate_reports','dmarc_records','email_sending_sources',
                           'brand_profiles','phishing_domains','phishing_observations','messaging_connections',
                           'email_events','email_indicators','email_alerts']
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;

COMMIT;
