-- Phase R2 — durable, org-scoped alert store fed by POST /api/ingest/alerts.
-- Additive and idempotent: safe to re-run. Run it in the Supabase SQL editor BEFORE deploying the
-- backend that writes to these tables.
--
-- RLS convention: the same as every other backend-written table here (cases, threat_triage,
-- alert_communications, …) — RLS enabled, one policy granting the service role everything, and
-- no policy for anon/authenticated, so the tables are reachable only through the backend (which
-- uses the service-role key and enforces org scoping itself).

-- Guard: an earlier draft of this project assumed an `alerts` table. If one with a different shape
-- already exists, CREATE TABLE IF NOT EXISTS would silently keep it and the backend would fail.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alerts')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'alerts' AND column_name = 'wazuh_alert_id') THEN
    RAISE EXCEPTION 'public.alerts already exists with a different shape (no wazuh_alert_id column) — inspect it before running this file';
  END IF;
END $$;

-- ── alerts ───────────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.alerts (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           TEXT NOT NULL,                 -- from wazuh_group_org_map, never from the payload
  wazuh_alert_id   TEXT NOT NULL,
  rule_id          TEXT,
  rule_level       INT,
  rule_description TEXT,
  agent_id         TEXT,
  agent_name       TEXT,
  agent_ip         TEXT,
  severity         TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),  -- computed from rule_level (lib/severity.ts)
  mitre_ids        TEXT[],
  wazuh_groups     TEXT[],                        -- the agent's Wazuh groups used to resolve org_id
  location         TEXT,
  raw              JSONB,                         -- the original alert, at most 32 KB (see raw_truncated)
  raw_truncated    BOOLEAN NOT NULL DEFAULT false,
  event_time       TIMESTAMPTZ NOT NULL,          -- Wazuh's alert timestamp
  received_at      TIMESTAMPTZ DEFAULT NOW(),
  status           TEXT DEFAULT 'new' CHECK (status IN ('new', 'triaged', 'escalated', 'closed', 'false_positive')),
  case_id          UUID NULL
);

-- Added after the first draft of this file; harmless when the table was just created above.
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS raw_truncated BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS alerts_org_wazuh_alert_id_key ON public.alerts (org_id, wazuh_alert_id);
CREATE INDEX IF NOT EXISTS alerts_org_event_time_idx ON public.alerts (org_id, event_time DESC);
CREATE INDEX IF NOT EXISTS alerts_org_severity_status_idx ON public.alerts (org_id, severity, status);
-- Keyset pagination orders by (event_time, id); the stale-data check reads the newest received_at.
CREATE INDEX IF NOT EXISTS alerts_org_received_at_idx ON public.alerts (org_id, received_at DESC);

-- ── wazuh_group_org_map ──────────────────────────────────────────────────────────────────────
-- Which organisation owns the agents in each Wazuh agent group. Managed at
-- /api/admin/wazuh-group-map (super_admin). An alert whose agent is in no mapped group, or in
-- groups that map to more than one org, is rejected — never guessed.
CREATE TABLE IF NOT EXISTS public.wazuh_group_org_map (
  wazuh_group  TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,                     -- organisations.slug
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Example only — do not run as-is; use the admin page or adapt the values:
-- INSERT INTO public.wazuh_group_org_map (wazuh_group, org_id) VALUES ('acme-servers', 'acme')
--   ON CONFLICT (wazuh_group) DO NOTHING;

-- ── alert_ingest_rejects ─────────────────────────────────────────────────────────────────────
-- Alerts the ingest endpoint refused, and why. No payload is kept.
CREATE TABLE IF NOT EXISTS public.alert_ingest_rejects (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  received_at     TIMESTAMPTZ DEFAULT NOW(),
  reason          TEXT,                           -- unmapped_group | ambiguous_org | invalid: <field>
  wazuh_alert_id  TEXT,
  wazuh_groups    TEXT[]
);
CREATE INDEX IF NOT EXISTS alert_ingest_rejects_received_idx ON public.alert_ingest_rejects (received_at DESC);

-- ── RLS ──────────────────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['alerts', 'wazuh_group_org_map', 'alert_ingest_rejects'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;
