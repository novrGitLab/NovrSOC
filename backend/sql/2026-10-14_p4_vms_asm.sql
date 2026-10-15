-- Phase P4 — VMS Release 1: authorised scope, scan jobs and the attack-surface inventory.
-- Additive and idempotent: safe to re-run. RLS: on, one service-role policy, nothing else.
--
-- Safety model: nothing is scanned unless it is inside an ACTIVE, unexpired scope entry that a
-- soc_manager / super_admin approved with an authorisation reference (contract, letter of
-- authorisation, ticket). The backend checks scope when a job is queued, the worker checks it
-- again before running a tool, and the backend checks every result it accepts.

-- ── Authorised scope ────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.vms_scopes (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                   TEXT NOT NULL,
  kind                     TEXT NOT NULL CHECK (kind IN ('domain', 'ip', 'cidr')),
  value                    TEXT NOT NULL,               -- example.com | 203.0.113.10 | 203.0.113.0/28
  include_subdomains       BOOLEAN NOT NULL DEFAULT true,   -- domain only
  allow_port_scan          BOOLEAN NOT NULL DEFAULT false,  -- active port/service scanning allowed
  allow_vuln_scan          BOOLEAN NOT NULL DEFAULT false,  -- Release 2 (Nuclei / OpenVAS) allowed
  authorization_reference  TEXT NOT NULL,                   -- the document that authorises testing
  notes                    TEXT,
  status                   TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  approved_by              TEXT NOT NULL,
  approved_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at               TIMESTAMPTZ NOT NULL,
  revoked_by               TEXT,
  revoked_at               TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS vms_scopes_org_idx ON public.vms_scopes (org_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS vms_scopes_active_key ON public.vms_scopes (org_id, kind, lower(value)) WHERE status = 'active';

-- ── Scan jobs (the queue the worker pulls from) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.vms_scan_jobs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         TEXT NOT NULL,
  scope_id       UUID NOT NULL REFERENCES public.vms_scopes(id),
  kind           TEXT NOT NULL CHECK (kind IN ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas')),
  targets        JSONB NOT NULL,                -- validated against scope when queued
  options        JSONB NOT NULL DEFAULT '{}',
  status         TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  requested_by   TEXT NOT NULL,
  requested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  schedule_id    UUID,                          -- set when a schedule queued it (Release 3)
  purpose        TEXT NOT NULL DEFAULT 'assessment' CHECK (purpose IN ('assessment', 'verification')),
  worker_id      TEXT,
  claimed_at     TIMESTAMPTZ,
  heartbeat_at   TIMESTAMPTZ,
  started_at     TIMESTAMPTZ,
  finished_at    TIMESTAMPTZ,
  progress       JSONB NOT NULL DEFAULT '{}',   -- { phase, done, total, message } as the worker reports it
  attempts       INT NOT NULL DEFAULT 0,
  error          TEXT,
  summary        JSONB,
  cancel_requested BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS vms_scan_jobs_queue_idx ON public.vms_scan_jobs (status, requested_at);
CREATE INDEX IF NOT EXISTS vms_scan_jobs_org_idx ON public.vms_scan_jobs (org_id, requested_at DESC);

-- ── Inventory ───────────────────────────────────────────────────────────────────────────────
-- One row per hostname or IP address an organisation exposes (or a Wazuh endpoint, linked by
-- wazuh_agent_id). Attributes are what scanners observed; owner/criticality are set by people.
CREATE TABLE IF NOT EXISTS public.vms_assets (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            TEXT NOT NULL,
  asset_type        TEXT NOT NULL CHECK (asset_type IN ('domain', 'host', 'ip', 'endpoint')),
  value             TEXT NOT NULL,              -- hostname or IP (lowercase)
  hostnames         TEXT[] NOT NULL DEFAULT '{}',
  ips               TEXT[] NOT NULL DEFAULT '{}',
  dns               JSONB NOT NULL DEFAULT '{}',     -- { a:[], aaaa:[], cname:[] }
  http              JSONB,                            -- { url, status, title, webserver, cdn }
  exposure          TEXT NOT NULL DEFAULT 'unknown' CHECK (exposure IN ('internet', 'internal', 'unknown')),
  alive             BOOLEAN,
  owner             TEXT,
  criticality       TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
  wazuh_agent_id    TEXT,
  discovery_sources TEXT[] NOT NULL DEFAULT '{}',
  first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'gone')),
  scope_id          UUID REFERENCES public.vms_scopes(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS vms_assets_org_value_key ON public.vms_assets (org_id, asset_type, value);
CREATE INDEX IF NOT EXISTS vms_assets_org_seen_idx ON public.vms_assets (org_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS public.vms_services (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  asset_id    UUID NOT NULL REFERENCES public.vms_assets(id) ON DELETE CASCADE,
  port        INT NOT NULL CHECK (port BETWEEN 0 AND 65535),
  protocol    TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
  state       TEXT NOT NULL DEFAULT 'open',
  service     TEXT,
  product     TEXT,
  version     TEXT,
  cpe         TEXT[],
  source      TEXT NOT NULL,
  first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'gone'))
);
CREATE UNIQUE INDEX IF NOT EXISTS vms_services_key ON public.vms_services (asset_id, port, protocol);

CREATE TABLE IF NOT EXISTS public.vms_technologies (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  asset_id    UUID NOT NULL REFERENCES public.vms_assets(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,                 -- lowercase, as normalised by the backend
  version     TEXT NOT NULL DEFAULT '',      -- '' when the version is unknown
  source      TEXT NOT NULL,
  first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS vms_technologies_key ON public.vms_technologies (asset_id, name, version);

-- What changed, when: new assets/services/technologies, changed attributes, things gone.
CREATE TABLE IF NOT EXISTS public.vms_asset_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  asset_id    UUID REFERENCES public.vms_assets(id) ON DELETE CASCADE,
  job_id      UUID REFERENCES public.vms_scan_jobs(id) ON DELETE SET NULL,
  at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event       TEXT NOT NULL CHECK (event IN ('asset_new', 'asset_changed', 'asset_gone', 'service_new', 'service_changed', 'service_gone', 'technology_new')),
  details     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS vms_asset_events_org_idx ON public.vms_asset_events (org_id, at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['vms_scopes', 'vms_scan_jobs', 'vms_assets', 'vms_services', 'vms_technologies', 'vms_asset_events'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;

-- The worker claims one job atomically, so two workers never run the same job.
CREATE OR REPLACE FUNCTION public.vms_claim_job(p_worker TEXT, p_kinds TEXT[])
RETURNS SETOF public.vms_scan_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN QUERY
  UPDATE public.vms_scan_jobs j
     SET status = 'running', worker_id = p_worker, claimed_at = NOW(), heartbeat_at = NOW(), started_at = NOW(), attempts = j.attempts + 1
   WHERE j.id = (
     SELECT id FROM public.vms_scan_jobs
      WHERE status = 'queued' AND kind = ANY(p_kinds) AND NOT cancel_requested
      ORDER BY requested_at
      FOR UPDATE SKIP LOCKED
      LIMIT 1)
  RETURNING j.*;
END $$;
REVOKE ALL ON FUNCTION public.vms_claim_job(TEXT, TEXT[]) FROM PUBLIC, anon, authenticated;
