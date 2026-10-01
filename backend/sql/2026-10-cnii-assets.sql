-- NovrSOC — CNII Watch asset inventory (routes/cnii.ts). Run once; safe to re-run.
-- One row per monitored IP. Scan data comes from SpiderFoot + OpenCTI; `vulns` holds the CVEs
-- the scan found (SpiderFoot/Shodan), since most CNII assets are external hosts with no Wazuh
-- agent to report vulnerabilities for them.

CREATE TABLE IF NOT EXISTS public.cnii_assets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip              TEXT NOT NULL UNIQUE,
  hostname        TEXT,
  owner           TEXT,
  org             TEXT,
  asn             TEXT,
  country         TEXT DEFAULT 'NG',
  sector_id       TEXT NOT NULL,
  subfield        TEXT,
  domains         TEXT[] DEFAULT '{}',
  subdomains      TEXT[] DEFAULT '{}',
  open_ports      INTEGER[] DEFAULT '{}',
  alert_count     INTEGER DEFAULT 0,
  vuln_count      INTEGER DEFAULT 0,
  risk_score      INTEGER DEFAULT 0,
  scan_status     TEXT DEFAULT 'pending',
  last_seen       TIMESTAMPTZ DEFAULT now(),
  added_at        TIMESTAMPTZ DEFAULT now(),
  vulns           JSONB DEFAULT '[]'::jsonb,   -- [{cve, cvss, severity, service?}] from the last scan
  raw_spiderfoot  JSONB,
  raw_opencti     JSONB
);

ALTER TABLE public.cnii_assets ADD COLUMN IF NOT EXISTS vulns JSONB DEFAULT '[]'::jsonb;
CREATE INDEX IF NOT EXISTS cnii_assets_sector_idx ON public.cnii_assets (sector_id);

-- Backend-only table: RLS on, and only the service role may read or write.
ALTER TABLE public.cnii_assets ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'cnii_assets' AND policyname = 'cnii_assets_service') THEN
    CREATE POLICY cnii_assets_service ON public.cnii_assets FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;
