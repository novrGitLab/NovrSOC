-- Phase P16 — OSV enrichment for tracked CVEs. Additive and idempotent: safe to re-run.
-- Needs P5 (cve_intel). Nullable columns only; no existing row changes value; RLS unchanged.
--
-- OSV (https://osv.dev) is asked, per tracked CVE, for its record (GET /v1/vulns/<CVE id>): which
-- OSV ids name the same vulnerability (e.g. GHSA-…, distribution advisories) and, per affected
-- package, the versions that fix it. Fetched by the CVE intelligence job (services/cveIntel.ts).
-- Without this file the job skips OSV and says so; nothing else changes.
--
-- Rollback: the backend ignores these columns when they are absent. To remove them:
--   ALTER TABLE public.cve_intel DROP COLUMN IF EXISTS osv_ids, DROP COLUMN IF EXISTS osv_summary,
--     DROP COLUMN IF EXISTS osv_affected, DROP COLUMN IF EXISTS osv_status, DROP COLUMN IF EXISTS osv_fetched_at;

ALTER TABLE public.cve_intel ADD COLUMN IF NOT EXISTS osv_ids        TEXT[];        -- the OSV record id, its aliases and related ids
ALTER TABLE public.cve_intel ADD COLUMN IF NOT EXISTS osv_summary    TEXT;
-- [{ ecosystem, name, repo, fixed: [versions], last_affected: [versions] }] as OSV states them
ALTER TABLE public.cve_intel ADD COLUMN IF NOT EXISTS osv_affected   JSONB;
-- found: OSV has a record; not_found: OSV answered that it has none (HTTP 404). Errors leave the
-- row unchanged so the next run retries; a lookup that failed is never stored as "not found".
ALTER TABLE public.cve_intel ADD COLUMN IF NOT EXISTS osv_status     TEXT;
ALTER TABLE public.cve_intel DROP CONSTRAINT IF EXISTS cve_intel_osv_status_check;
ALTER TABLE public.cve_intel ADD CONSTRAINT cve_intel_osv_status_check CHECK (osv_status IS NULL OR osv_status IN ('found', 'not_found'));
ALTER TABLE public.cve_intel ADD COLUMN IF NOT EXISTS osv_fetched_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS cve_intel_osv_fetched_idx ON public.cve_intel (osv_fetched_at NULLS FIRST);
