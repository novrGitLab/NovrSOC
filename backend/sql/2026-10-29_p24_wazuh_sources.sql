-- Phase P24 — agentless Wazuh sources (OPNsense syslog) and network fields on stored alerts.
-- Additive and idempotent: safe to re-run. Needs the R2 `alerts` table and the P1 quarantine.
-- Run it in the Supabase SQL editor BEFORE deploying the backend that uses it. The backend keeps
-- working without it (no source mappings, no network columns), but OPNsense alerts stay
-- quarantined until it runs.
--
-- 1. wazuh_source_org_map — which organisation owns a syslog sender. Syslog the Wazuh manager
--    receives itself (OPNsense over WireGuard to UDP 514) is attributed to agent 000, the manager,
--    which has no agent group, so the group map can never assign it. Its `location` is the sender's
--    address; this table maps that address to an organisation. Managed at
--    /api/admin/wazuh-group-map/sources (super_admin), which accepts IP addresses only (never a
--    log file path, which every agent shares) and audits every change. Only agent-000 alerts are
--    ever matched by location (routes/ingest.ts, lib/orgScope.ts).
--
--    Trust: the sender address is only as trustworthy as the path it arrives on. Over WireGuard
--    with one peer per AllowedIPs it is authenticated; never map an address that reaches UDP 514
--    from the open internet.
--
-- 2. Network columns on alerts, extracted at ingest from the alert itself (lib/alertNetwork.ts):
--    src/dst IP and port, protocol, firewall action / direction / interface, the Wazuh decoder and
--    the syslog host. Nullable; nothing is inferred. backfill_alert_network() fills them for alerts
--    stored before this ran (call it yourself; it is not run here).
--
-- 3. alert_quarantine.reason gains 'unmapped_source' (an agent-000 alert whose sender isn't mapped).

-- ── 1. wazuh_source_org_map ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.wazuh_source_org_map (
  location     TEXT PRIMARY KEY,                  -- the sender address exactly as Wazuh records it in `location`
  org_id       TEXT NOT NULL,                     -- organisations.slug
  device_name  TEXT,                              -- e.g. 'opnsense-fw' — a label, not used for matching
  device_type  TEXT NOT NULL DEFAULT 'firewall' CHECK (device_type IN ('firewall', 'ids', 'syslog', 'other')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS wazuh_source_org_map_org_idx ON public.wazuh_source_org_map (org_id);

-- Example only — do not run as-is; use the admin page (Settings → Wazuh Groups → Syslog sources):
-- INSERT INTO public.wazuh_source_org_map (location, org_id, device_name) VALUES ('10.0.0.4', '<org slug>', 'opnsense-fw')
--   ON CONFLICT (location) DO NOTHING;

-- ── 2. Network columns on alerts ─────────────────────────────────────────────────────────────
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS src_ip          TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS src_port        INT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS dst_ip          TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS dst_port        INT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS protocol        TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS net_action      TEXT;   -- pass / block / reject (lowercased as the decoder reports it)
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS net_direction   TEXT;   -- in / out
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS net_interface   TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS decoder_name    TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS device_hostname TEXT;

-- The Alerts page filters by these within one organisation, newest first.
CREATE INDEX IF NOT EXISTS alerts_org_net_action_idx ON public.alerts (org_id, net_action, event_time DESC) WHERE net_action IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_org_src_ip_idx ON public.alerts (org_id, src_ip) WHERE src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_org_dst_ip_idx ON public.alerts (org_id, dst_ip) WHERE dst_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_org_location_idx ON public.alerts (org_id, location);

-- ── 3. Quarantine reason ─────────────────────────────────────────────────────────────────────
DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint
  WHERE conrelid = 'public.alert_quarantine'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%reason%';
  IF c IS NOT NULL THEN EXECUTE format('ALTER TABLE public.alert_quarantine DROP CONSTRAINT %I', c); END IF;
  ALTER TABLE public.alert_quarantine ADD CONSTRAINT alert_quarantine_reason_check
    CHECK (reason IN ('unmapped_group', 'ambiguous_org', 'unmapped_source'));
END $$;

-- ── RLS (same convention as every backend-written table) ─────────────────────────────────────
DO $$
BEGIN
  EXECUTE 'ALTER TABLE public.wazuh_source_org_map ENABLE ROW LEVEL SECURITY';
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'wazuh_source_org_map' AND policyname = 'wazuh_source_org_map_service') THEN
    EXECUTE 'CREATE POLICY wazuh_source_org_map_service ON public.wazuh_source_org_map FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;

-- ── Backfill (defined, not run) ──────────────────────────────────────────────────────────────
-- Mirrors lib/alertNetwork.ts for alerts stored before this migration: values that are not a
-- valid address / port / short token stay NULL. Truncated raw (raw_truncated) has no fields to
-- read. Walks the table once in id order, batch_size rows per statement, so no statement holds
-- locks for long; only rows whose network columns are all NULL are touched, so a re-run is cheap.
--
--   SELECT public.backfill_alert_network();        -- returns the number of rows updated
CREATE OR REPLACE FUNCTION public.p24_ip(v TEXT) RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  IF v IS NULL OR btrim(v) = '' OR length(v) > 45 THEN RETURN NULL; END IF;
  RETURN host(btrim(v)::inet);
EXCEPTION WHEN others THEN RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.p24_port(v TEXT) RETURNS INT LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN btrim(v) ~ '^\d{1,5}$' AND btrim(v)::int <= 65535 THEN btrim(v)::int END
$$;

CREATE OR REPLACE FUNCTION public.p24_token(v TEXT, max_len INT, lower_case BOOLEAN) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN btrim(v) ~ '^[A-Za-z0-9._:/@-]+$' AND length(btrim(v)) <= max_len
              THEN CASE WHEN lower_case THEN lower(btrim(v)) ELSE btrim(v) END END
$$;

CREATE OR REPLACE FUNCTION public.backfill_alert_network(batch_size INT DEFAULT 5000)
RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE
  last_id UUID := '00000000-0000-0000-0000-000000000000';
  ids     UUID[];
  n       BIGINT := 0;
  done    BIGINT;
BEGIN
  IF batch_size IS NULL OR batch_size < 1 THEN RAISE EXCEPTION 'batch_size must be at least 1'; END IF;
  LOOP
    SELECT array_agg(id ORDER BY id) INTO ids FROM (
      SELECT id FROM public.alerts
      WHERE id > last_id AND raw_truncated = false AND raw IS NOT NULL
        AND src_ip IS NULL AND dst_ip IS NULL AND net_action IS NULL AND decoder_name IS NULL
      ORDER BY id LIMIT batch_size
    ) s;
    EXIT WHEN ids IS NULL;
    last_id := ids[array_length(ids, 1)];

    UPDATE public.alerts a SET
      src_ip          = COALESCE(public.p24_ip(a.raw->'data'->>'srcip'), public.p24_ip(a.raw->'data'->'win'->'eventdata'->>'sourceIp')),
      src_port        = COALESCE(public.p24_port(a.raw->'data'->>'srcport'), public.p24_port(a.raw->'data'->'win'->'eventdata'->>'sourcePort')),
      dst_ip          = COALESCE(public.p24_ip(a.raw->'data'->>'dstip'), public.p24_ip(a.raw->'data'->'win'->'eventdata'->>'destinationIp')),
      dst_port        = COALESCE(public.p24_port(a.raw->'data'->>'dstport'), public.p24_port(a.raw->'data'->'win'->'eventdata'->>'destinationPort')),
      protocol        = COALESCE(public.p24_token(a.raw->'data'->>'protocol', 32, true), public.p24_token(a.raw->'data'->'win'->'eventdata'->>'protocol', 32, true),
                                 public.p24_token(a.raw->'data'->>'proto', 32, true), public.p24_token(a.raw->'data'->>'protoname', 32, true)),
      net_action      = public.p24_token(a.raw->'data'->>'action', 32, true),
      net_direction   = COALESCE(public.p24_token(a.raw->'data'->>'direction', 16, true), public.p24_token(a.raw->'data'->>'dir', 16, true)),
      net_interface   = COALESCE(public.p24_token(a.raw->'data'->>'interface', 64, false), public.p24_token(a.raw->'data'->>'iface', 64, false),
                                 public.p24_token(a.raw->'data'->>'ifname', 64, false), public.p24_token(a.raw->'data'->>'real_interface', 64, false)),
      decoder_name    = public.p24_token(a.raw->'decoder'->>'name', 128, false),
      device_hostname = public.p24_token(a.raw->'predecoder'->>'hostname', 255, false)
    WHERE a.id = ANY(ids);
    GET DIAGNOSTICS done = ROW_COUNT;
    n := n + done;
  END LOOP;
  RETURN n;
END $$;

REVOKE ALL ON FUNCTION public.backfill_alert_network(INT) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN EXECUTE 'REVOKE ALL ON FUNCTION public.backfill_alert_network(INT) FROM anon'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN EXECUTE 'REVOKE ALL ON FUNCTION public.backfill_alert_network(INT) FROM authenticated'; END IF;
END $$;
