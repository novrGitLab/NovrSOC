-- Phase P31 — NovrSOC Collector V1: a per-organisation log-collection appliance (Vector) that
-- enrolls with this backend, authenticates with a per-collector secret (never a shared token),
-- and forwards collected log events through a new, dedicated ingestion gateway.
--
-- Additive and idempotent: safe to re-run. RLS: on, one service-role policy each, matching every
-- other backend-written table (see P4's vms_scopes, P30's report_schedules for the pattern).
--
-- Deliberately separate from the `alerts` table (sql/2026-10-09_alerts_pipeline.sql), not a
-- second copy of it: `alerts` rows are Wazuh-generated alerts (a rule fired, at a Wazuh severity
-- level) forwarded by infra/soar/soar.py. A raw syslog line a collector forwards has had no
-- detection logic applied to it at all — storing it as an "alert" with an invented severity would
-- be exactly the fabricated detection claim the Collector V1 brief explicitly forbids ("do not
-- claim full endpoint detection and response from agentless log collection"). collector_log_events
-- stores it honestly, as a log, not an alert, and nothing here writes into the Wazuh manager or
-- the `alerts` table — ingestion identity and routing for collectors stays entirely separate from
-- Wazuh's own alert-generation logic (see docs/collector-v1/WAZUH_COMPATIBILITY.md).

-- ── Collectors: one enrolled appliance, bound to exactly one organisation ─────────────────────
CREATE TABLE IF NOT EXISTS public.collectors (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                  TEXT NOT NULL REFERENCES public.organisations(slug) ON DELETE CASCADE,
  name                    TEXT NOT NULL,
  status                  TEXT NOT NULL DEFAULT 'enrolling' CHECK (status IN ('enrolling', 'connected', 'disconnected', 'revoked')),
  -- The enrollment/auth secret itself is NEVER stored — only its SHA-256 hash, compared with
  -- timingSafeEqual (lib/collectorAuth.ts), the same pattern routes/ingest.ts already uses for
  -- ALERT_INGEST_TOKEN. token_prefix (first 8 hex chars) is shown in the UI so staff can confirm
  -- which physical collector a secret belongs to without ever displaying the secret again.
  token_hash              TEXT NOT NULL,
  token_prefix            TEXT NOT NULL,
  enrollment_expires_at   TIMESTAMPTZ,              -- null once activated; a collector that never completes its first heartbeat before this expires cannot authenticate
  activated_at            TIMESTAMPTZ,
  revoked_at              TIMESTAMPTZ,
  revoked_by              TEXT,
  config_version          INT NOT NULL DEFAULT 1,   -- bumped on every config-affecting change (rotate, revoke); a collector logs this on reload so staff can confirm it picked up a change
  vector_version           TEXT,
  last_heartbeat_at       TIMESTAMPTZ,
  last_ip                 TEXT,
  last_events_received    BIGINT NOT NULL DEFAULT 0,
  last_events_forwarded   BIGINT NOT NULL DEFAULT 0,
  last_delivery_failures  BIGINT NOT NULL DEFAULT 0,
  last_buffer_pct         NUMERIC,
  created_by              TEXT NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS collectors_org_idx ON public.collectors (org_id);
ALTER TABLE public.collectors ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'collectors' AND policyname = 'collectors_service') THEN
    CREATE POLICY collectors_service ON public.collectors FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Sources: the log sources a collector is actually receiving from right now ────────────────
CREATE TABLE IF NOT EXISTS public.collector_sources (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  collector_id    UUID NOT NULL REFERENCES public.collectors(id) ON DELETE CASCADE,
  source_key      TEXT NOT NULL,   -- the Vector source id, e.g. "syslog_tcp_514"
  kind            TEXT NOT NULL CHECK (kind IN ('syslog_tcp', 'syslog_udp', 'syslog_tls', 'wef_bridge', 'file', 'other')),
  label           TEXT,
  events_total    BIGINT NOT NULL DEFAULT 0,
  last_event_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (collector_id, source_key)
);
ALTER TABLE public.collector_sources ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'collector_sources' AND policyname = 'collector_sources_service') THEN
    CREATE POLICY collector_sources_service ON public.collector_sources FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Heartbeats: a time series of what each collector reported, for the throughput chart and ──
-- staleness detection. Retained 30 days (purge function below) — this is operational telemetry,
-- not an audit trail (collector_log_events and audit_log cover that separately).
CREATE TABLE IF NOT EXISTS public.collector_heartbeats (
  id                  BIGSERIAL PRIMARY KEY,
  collector_id        UUID NOT NULL REFERENCES public.collectors(id) ON DELETE CASCADE,
  at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  events_received     BIGINT NOT NULL DEFAULT 0,
  events_forwarded    BIGINT NOT NULL DEFAULT 0,
  delivery_failures   BIGINT NOT NULL DEFAULT 0,
  buffer_pct          NUMERIC
);
CREATE INDEX IF NOT EXISTS collector_heartbeats_collector_idx ON public.collector_heartbeats (collector_id, at DESC);
ALTER TABLE public.collector_heartbeats ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'collector_heartbeats' AND policyname = 'collector_heartbeats_service') THEN
    CREATE POLICY collector_heartbeats_service ON public.collector_heartbeats FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Log events: the actual collected logs, tenant-scoped, deliberately NOT alerts ────────────
-- dedup_key is computed by the gateway (sha256 of collector_id + source_key + the raw line) so a
-- buffered-and-retried batch after a network outage can be replayed safely: the unique index
-- below makes a duplicate send a no-op, the same idempotency pattern routes/ingest.ts already
-- proves for Wazuh alerts (alerts_org_wazuh_alert_id_key).
CREATE TABLE IF NOT EXISTS public.collector_log_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          TEXT NOT NULL REFERENCES public.organisations(slug) ON DELETE CASCADE,
  collector_id    UUID NOT NULL REFERENCES public.collectors(id) ON DELETE CASCADE,
  source_key      TEXT NOT NULL,
  host            TEXT,             -- the originating device's own hostname/IP, as it reported itself (source identity preservation)
  received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_time      TIMESTAMPTZ,      -- as the device reported it; may differ from received_at after an outage-buffered replay
  message         TEXT NOT NULL,    -- capped at 32 KB by the gateway before insert, same cap and reasoning as routes/ingest.ts's capRaw()
  truncated       BOOLEAN NOT NULL DEFAULT FALSE,
  dedup_key       TEXT NOT NULL,
  UNIQUE (collector_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS collector_log_events_org_idx ON public.collector_log_events (org_id, received_at DESC);
ALTER TABLE public.collector_log_events ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'collector_log_events' AND policyname = 'collector_log_events_service') THEN
    CREATE POLICY collector_log_events_service ON public.collector_log_events FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Retention ──────────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.purge_collector_history(retain_days INTEGER DEFAULT 30)
RETURNS TABLE(heartbeats_deleted BIGINT, events_deleted BIGINT) LANGUAGE plpgsql AS $$
DECLARE h BIGINT; e BIGINT;
BEGIN
  DELETE FROM public.collector_heartbeats WHERE at < NOW() - (retain_days || ' days')::INTERVAL;
  GET DIAGNOSTICS h = ROW_COUNT;
  DELETE FROM public.collector_log_events WHERE received_at < NOW() - (retain_days || ' days')::INTERVAL;
  GET DIAGNOSTICS e = ROW_COUNT;
  RETURN QUERY SELECT h, e;
END $$;

-- ── Rollback ───────────────────────────────────────────────────────────────────────────────────
--   DROP FUNCTION IF EXISTS public.purge_collector_history(INTEGER);
--   DROP TABLE IF EXISTS public.collector_log_events;
--   DROP TABLE IF EXISTS public.collector_heartbeats;
--   DROP TABLE IF EXISTS public.collector_sources;
--   DROP TABLE IF EXISTS public.collectors;
-- None of the previous code reads these tables, so the rollback is safe at any time.
