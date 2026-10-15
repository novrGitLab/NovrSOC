-- Phase P5 — VMS Release 2: findings, evidence, CVE intelligence, remediation and verification.
-- Additive and idempotent: safe to re-run. Needs the P4 VMS tables. RLS: on, service role only.

-- ── CVE intelligence (shared, not per organisation: public data) ───────────────────────────
CREATE TABLE IF NOT EXISTS public.cve_intel (
  cve_id               TEXT PRIMARY KEY,               -- CVE-YYYY-NNNN
  description          TEXT,
  cvss_score           NUMERIC(3,1),
  cvss_vector          TEXT,
  cvss_version         TEXT,
  cwe_ids              TEXT[],
  published_at         TIMESTAMPTZ,
  nvd_last_modified    TIMESTAMPTZ,
  references_urls      TEXT[],
  epss_score           NUMERIC(6,5),                   -- probability 0..1, from FIRST
  epss_percentile      NUMERIC(6,5),
  epss_date            DATE,
  kev                  BOOLEAN NOT NULL DEFAULT false, -- in the CISA KEV catalogue
  kev_date_added       DATE,
  kev_due_date         DATE,
  kev_required_action  TEXT,
  kev_ransomware       TEXT,                           -- 'Known' | 'Unknown' as CISA states it
  nvd_fetched_at       TIMESTAMPTZ,
  epss_fetched_at      TIMESTAMPTZ,
  kev_checked_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS cve_intel_kev_idx ON public.cve_intel (kev) WHERE kev;

-- ── Findings ────────────────────────────────────────────────────────────────────────────────
-- One finding per (organisation, dedupe_key): the same issue on the same asset and port, however
-- many scanners or scans report it. Each sighting is kept in vms_finding_evidence.
CREATE TABLE IF NOT EXISTS public.vms_findings (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id              TEXT NOT NULL,
  dedupe_key          TEXT NOT NULL,
  asset_id            UUID REFERENCES public.vms_assets(id) ON DELETE SET NULL,
  asset_value         TEXT NOT NULL,                  -- hostname / IP / agent name, kept if the asset is removed
  port                INT,
  protocol            TEXT,
  source_class        TEXT NOT NULL CHECK (source_class IN ('active_scan', 'wazuh')),
  detected_by         TEXT[] NOT NULL DEFAULT '{}',   -- nuclei | openvas | wazuh
  rule_id             TEXT NOT NULL,                  -- nuclei template id | OpenVAS NVT OID | Wazuh: CVE id
  title               TEXT NOT NULL,
  description         TEXT,
  finding_type        TEXT NOT NULL DEFAULT 'vulnerability' CHECK (finding_type IN ('vulnerability', 'misconfiguration', 'exposure', 'information')),
  cve_ids             TEXT[] NOT NULL DEFAULT '{}',
  scanner_severity    TEXT NOT NULL CHECK (scanner_severity IN ('critical', 'high', 'medium', 'low', 'info')),
  scanner_cvss        NUMERIC(3,1),
  remediation         TEXT,                            -- as the scanner states it
  references_urls     TEXT[] NOT NULL DEFAULT '{}',
  risk_score          INT,                             -- 0..100, lib/riskScore.ts
  priority            TEXT CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
  risk_factors        JSONB NOT NULL DEFAULT '{}',     -- every input and how much it contributed
  status              TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'verified', 'reopened', 'risk_accepted', 'false_positive')),
  owner               TEXT,
  due_at              TIMESTAMPTZ,
  due_manual          BOOLEAN NOT NULL DEFAULT false,  -- true once a person set due_at; policy no longer moves it
  first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_job_id         UUID,
  fixed_marked_at     TIMESTAMPTZ,
  verification_job_id UUID,
  verified_at         TIMESTAMPTZ,
  closed_at           TIMESTAMPTZ,
  case_id             UUID,
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS vms_findings_dedupe_key ON public.vms_findings (org_id, dedupe_key);
CREATE INDEX IF NOT EXISTS vms_findings_org_status_idx ON public.vms_findings (org_id, status, priority);
CREATE INDEX IF NOT EXISTS vms_findings_asset_idx ON public.vms_findings (asset_id);
CREATE INDEX IF NOT EXISTS vms_findings_cves_idx ON public.vms_findings USING GIN (cve_ids);

CREATE TABLE IF NOT EXISTS public.vms_finding_evidence (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       TEXT NOT NULL,
  finding_id   UUID NOT NULL REFERENCES public.vms_findings(id) ON DELETE CASCADE,
  source       TEXT NOT NULL,                  -- nuclei | openvas | wazuh
  job_id       UUID,
  observed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  matched_at   TEXT,                           -- URL, host:port or package
  evidence     JSONB NOT NULL DEFAULT '{}'     -- redacted, size-capped
);
CREATE INDEX IF NOT EXISTS vms_finding_evidence_finding_idx ON public.vms_finding_evidence (finding_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS public.vms_finding_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      TEXT NOT NULL,
  finding_id  UUID NOT NULL REFERENCES public.vms_findings(id) ON DELETE CASCADE,
  at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,                  -- detected | status | owner | due | note | reopened | verified | verification_queued | case_link | risk
  from_value  TEXT,
  to_value    TEXT,
  details     TEXT
);
CREATE INDEX IF NOT EXISTS vms_finding_events_finding_idx ON public.vms_finding_events (finding_id, at);

-- Remediation work items (people's tasks, optionally drafted from an AI plan they accepted).
CREATE TABLE IF NOT EXISTS public.vms_remediation_tasks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  finding_id    UUID NOT NULL REFERENCES public.vms_findings(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,
  details       TEXT,
  owner         TEXT,
  due_at        TIMESTAMPTZ,
  status        TEXT NOT NULL DEFAULT 'todo' CHECK (status IN ('todo', 'doing', 'done', 'cancelled')),
  ai_artifact_id UUID,
  created_by    TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS vms_remediation_tasks_finding_idx ON public.vms_remediation_tasks (finding_id);
CREATE INDEX IF NOT EXISTS vms_remediation_tasks_org_idx ON public.vms_remediation_tasks (org_id, status, due_at);

-- Wazuh endpoint vulnerability sync position per organisation.
CREATE TABLE IF NOT EXISTS public.vms_wazuh_sync (
  org_id          TEXT PRIMARY KEY,
  last_synced_at  TIMESTAMPTZ,
  last_result     JSONB
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cve_intel', 'vms_findings', 'vms_finding_evidence', 'vms_finding_events', 'vms_remediation_tasks', 'vms_wazuh_sync'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;
