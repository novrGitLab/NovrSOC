-- Phase X1 — vendor export API (GET /api/export/v1/events). Additive and idempotent: safe to
-- re-run. Run it BEFORE deploying the backend that reads these tables; the endpoint itself stays
-- off until EXPORT_API_ENABLED=true.
--
-- RLS convention: the same as every other backend-written table (cases, alerts, threat_triage, …):
-- RLS enabled, one policy granting the service role everything, no anon/authenticated policy —
-- reachable only through the backend.

-- ── export_clients ───────────────────────────────────────────────────────────────────────────
-- One row per external consumer. Only the SHA-256 of the client's token is stored; the plaintext
-- is shown once, when the client is created or rotated (POST /api/admin/export-clients…).
CREATE TABLE IF NOT EXISTS public.export_clients (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name               TEXT,
  token_hash         TEXT NOT NULL UNIQUE,                     -- hex SHA-256 of the bearer token
  org_ids            TEXT[] NOT NULL CHECK (cardinality(org_ids) > 0),        -- organisations.slug
  allowed_cidrs      TEXT[] NOT NULL CHECK (cardinality(allowed_cidrs) > 0),
  enabled            BOOLEAN DEFAULT true,
  redaction_profile  TEXT DEFAULT 'standard',
  created_at         TIMESTAMPTZ DEFAULT NOW(),
  rotated_at         TIMESTAMPTZ,
  last_used_at       TIMESTAMPTZ
);

-- ── export_access_log ────────────────────────────────────────────────────────────────────────
-- Every call by an identifiable client, accepted or refused. No payloads, no tokens.
CREATE TABLE IF NOT EXISTS public.export_access_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id    UUID,                                  -- export_clients.id (kept if the client is deleted)
  at           TIMESTAMPTZ DEFAULT NOW(),
  source_ip    TEXT,
  org_ids      TEXT[],                                -- the org scope of this call
  row_count    INT,
  cursor_from  TEXT,
  cursor_to    TEXT,
  status_code  INT
);
CREATE INDEX IF NOT EXISTS export_access_log_client_at_idx ON public.export_access_log (client_id, at DESC);

-- The export reads alerts in (event_time, id) order within the client's orgs.
CREATE INDEX IF NOT EXISTS alerts_org_event_time_id_idx ON public.alerts (org_id, event_time, id);

-- ── RLS ──────────────────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['export_clients', 'export_access_log'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;
