-- Phase P30 — Release 3.3E: unified client reporting and scheduled delivery.
-- Additive and idempotent: safe to re-run. RLS: on, one service-role policy each, matching every
-- other backend-written table (see P4's vms_scopes, P29's org_onboarding for the pattern).
--
-- This does NOT duplicate VMS/CNII/Threat Intelligence report generation — those stay exactly
-- where they are (services/vmsContinuous.ts periodReport(), routes/cnii.ts's client-scoped
-- /profile, services/threatInfo.ts relevantIntel()). What's new here is purely the scheduling,
-- recipient and delivery layer connecting them: a schedule says WHEN and for WHOM a report type
-- should run; a job is one actual run; an artifact is its generated PDF/CSV; a delivery is one
-- attempt to email it to one recipient.
--
-- Distributed scheduling safety (R3.3E Stage 2's explicit requirement — "do not rely only on an
-- in-process busy Set"): every existing backend/src/jobs/*.ts job uses only an in-process Set,
-- which is safe only by convention (exactly one Render instance has NOVRSOC_DISABLE_JOBS=false).
-- report_claim_job() below is deliberately modelled on sql/2026-10-14_p4_vms_asm.sql's
-- vms_claim_job() — the one place this codebase already solves multi-replica claiming correctly,
-- with a real `FOR UPDATE SKIP LOCKED` instead of an in-process guard. Schedule due-ness itself
-- is claimed with a plain compare-and-swap UPDATE from application code (lib/reportScheduling.ts),
-- which is equally safe under Postgres's read-committed isolation: a second replica's UPDATE
-- re-evaluates its WHERE clause against the first replica's already-committed row and simply
-- matches nothing, rather than racing it.

-- ── Schedules: when and in what format a report type runs for an organisation ────────────────
-- A schedule existing is NOT enough to send email on its own — report_recipients (below) must
-- also have at least one enabled row for the same organisation, checked in application code
-- before a schedule is ever allowed to go live. One row per (org, report_type): an organisation
-- cannot have two competing weekly/monthly configurations for the same report.
CREATE TABLE IF NOT EXISTS public.report_schedules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          TEXT NOT NULL REFERENCES public.organisations(slug) ON DELETE CASCADE,
  report_type     TEXT NOT NULL CHECK (report_type IN ('vms', 'cnii', 'threat_intel', 'executive_summary')),
  format          TEXT NOT NULL DEFAULT 'executive' CHECK (format IN ('executive', 'technical')),
  cadence         TEXT NOT NULL CHECK (cadence IN ('weekly', 'monthly')),
  day_of_week     INT CHECK (day_of_week BETWEEN 0 AND 6),    -- weekly only; 0 = Sunday
  day_of_month    INT CHECK (day_of_month BETWEEN 1 AND 28),  -- monthly only; capped at 28 so it exists every month
  hour_local      INT NOT NULL DEFAULT 8 CHECK (hour_local BETWEEN 0 AND 23),
  timezone        TEXT NOT NULL DEFAULT 'Africa/Lagos',
  enabled         BOOLEAN NOT NULL DEFAULT false,              -- off until a staff member explicitly turns it on
  next_run_at     TIMESTAMPTZ NOT NULL,
  last_success_at TIMESTAMPTZ,
  last_failure_at TIMESTAMPTZ,
  last_error      TEXT,
  created_by      TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by      TEXT NOT NULL,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, report_type)
);
CREATE INDEX IF NOT EXISTS report_schedules_due_idx ON public.report_schedules (next_run_at) WHERE enabled;
ALTER TABLE public.report_schedules ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'report_schedules' AND policyname = 'report_schedules_service') THEN
    CREATE POLICY report_schedules_service ON public.report_schedules FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Recipients: who a report may go to, and how that address is trusted ──────────────────────
-- kind = 'portal_user' means email must match an active platform_users row for this org (checked
-- in application code at write time, not enforced by a foreign key, since platform_users is keyed
-- by id, not email, and emails there can change). kind = 'external_email' is any other address —
-- these require external_authorised_by/at to be set before any sensitive report is actually sent
-- to them (Stage 3: "Require appropriate authorisation and confirmation before sensitive external
-- delivery" — enforced in lib/reportRecipients.ts, not by this schema alone).
CREATE TABLE IF NOT EXISTS public.report_recipients (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                  TEXT NOT NULL REFERENCES public.organisations(slug) ON DELETE CASCADE,
  kind                    TEXT NOT NULL CHECK (kind IN ('portal_user', 'external_email')),
  email                   TEXT NOT NULL,
  display_name            TEXT,
  report_types            TEXT[] NOT NULL DEFAULT '{}',  -- empty = every type scheduled for this org
  enabled                 BOOLEAN NOT NULL DEFAULT true,
  external_authorised_by  TEXT,
  external_authorised_at  TIMESTAMPTZ,
  added_by                TEXT NOT NULL,
  added_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by              TEXT,
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, kind, email)
);
CREATE INDEX IF NOT EXISTS report_recipients_org_idx ON public.report_recipients (org_id) WHERE enabled;
ALTER TABLE public.report_recipients ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'report_recipients' AND policyname = 'report_recipients_service') THEN
    CREATE POLICY report_recipients_service ON public.report_recipients FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Jobs: one actual report run (scheduled or "generate now") ────────────────────────────────
CREATE TABLE IF NOT EXISTS public.report_jobs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          TEXT NOT NULL REFERENCES public.organisations(slug) ON DELETE CASCADE,
  report_type     TEXT NOT NULL CHECK (report_type IN ('vms', 'cnii', 'threat_intel', 'executive_summary')),
  format          TEXT NOT NULL DEFAULT 'executive' CHECK (format IN ('executive', 'technical')),
  period_days     INT NOT NULL DEFAULT 30,
  schedule_id     UUID REFERENCES public.report_schedules(id) ON DELETE SET NULL,
  trigger         TEXT NOT NULL DEFAULT 'scheduled' CHECK (trigger IN ('scheduled', 'manual')),
  requested_by    TEXT,  -- null for scheduler-originated runs
  status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed')),
  worker_id       TEXT,
  attempts        INT NOT NULL DEFAULT 0,
  last_error      TEXT,
  requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  claimed_at      TIMESTAMPTZ,
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS report_jobs_queue_idx ON public.report_jobs (status, requested_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS report_jobs_org_idx ON public.report_jobs (org_id, requested_at DESC);
ALTER TABLE public.report_jobs ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'report_jobs' AND policyname = 'report_jobs_service') THEN
    CREATE POLICY report_jobs_service ON public.report_jobs FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- Distributed claim, mirroring vms_claim_job() exactly (sql/2026-10-14_p4_vms_asm.sql) — the one
-- place in this codebase that already does multi-replica job claiming correctly.
CREATE OR REPLACE FUNCTION public.report_claim_job(p_worker TEXT)
RETURNS SETOF public.report_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN QUERY
  UPDATE public.report_jobs j
     SET status = 'running', worker_id = p_worker, claimed_at = NOW(), started_at = NOW(), attempts = j.attempts + 1
   WHERE j.id = (
     SELECT id FROM public.report_jobs
      WHERE status = 'queued'
      ORDER BY requested_at
      FOR UPDATE SKIP LOCKED
      LIMIT 1)
  RETURNING j.*;
END $$;
REVOKE ALL ON FUNCTION public.report_claim_job(TEXT) FROM PUBLIC, anon, authenticated;

-- ── Artifacts: the generated file for one job ─────────────────────────────────────────────────
-- Stored as bytes in Postgres, not an object-storage bucket: this repository has no existing
-- Supabase Storage / S3 usage anywhere (verified before choosing this), and report PDFs/CSVs are
-- small (typically well under a few MB). This also trivially satisfies "no public storage URLs" —
-- there is no object URL at all, only an authenticated backend route that streams these bytes
-- after its own permission and org check (routes/reports.ts).
CREATE TABLE IF NOT EXISTS public.report_artifacts (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_job_id   UUID NOT NULL REFERENCES public.report_jobs(id) ON DELETE CASCADE,
  format          TEXT NOT NULL CHECK (format IN ('pdf', 'csv')),
  filename        TEXT NOT NULL,
  content_type    TEXT NOT NULL,
  bytes           BYTEA NOT NULL,
  size_bytes      INT NOT NULL,
  sha256          TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS report_artifacts_job_idx ON public.report_artifacts (report_job_id);
CREATE INDEX IF NOT EXISTS report_artifacts_expiry_idx ON public.report_artifacts (expires_at);
ALTER TABLE public.report_artifacts ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'report_artifacts' AND policyname = 'report_artifacts_service') THEN
    CREATE POLICY report_artifacts_service ON public.report_artifacts FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Deliveries: one attempt to email one artifact to one recipient ───────────────────────────
-- recipient_email is kept even if the report_recipients row is later removed or disabled, so
-- delivery history stays a true audit trail rather than losing its subject when a recipient is
-- deleted.
CREATE TABLE IF NOT EXISTS public.report_deliveries (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_job_id        UUID NOT NULL REFERENCES public.report_jobs(id) ON DELETE CASCADE,
  recipient_id         UUID REFERENCES public.report_recipients(id) ON DELETE SET NULL,
  recipient_email      TEXT NOT NULL,
  status               TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'delivered', 'bounced', 'failed')),
  provider             TEXT,
  provider_message_id  TEXT,
  error                TEXT,
  attempts             INT NOT NULL DEFAULT 0,
  last_attempt_at      TIMESTAMPTZ,
  delivered_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS report_deliveries_job_idx ON public.report_deliveries (report_job_id);
ALTER TABLE public.report_deliveries ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'report_deliveries' AND policyname = 'report_deliveries_service') THEN
    CREATE POLICY report_deliveries_service ON public.report_deliveries FOR ALL USING (auth.role() = 'service_role');
  END IF;
END $$;

-- ── Retention ──────────────────────────────────────────────────────────────────────────────
-- Two separate purges, like VMS's purge_vms_history: artifact BYTES expire sooner (the content
-- itself) than the job/delivery AUDIT TRAIL (who ran what, when, delivered to whom) — a job row
-- with no artifact left still proves a report was generated and sent.
CREATE OR REPLACE FUNCTION public.purge_expired_report_artifacts()
RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE n BIGINT;
BEGIN
  DELETE FROM public.report_artifacts WHERE expires_at < NOW();
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION public.purge_expired_report_artifacts() FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.purge_report_job_history(retain_days INTEGER DEFAULT 180)
RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE n BIGINT; cutoff TIMESTAMPTZ;
BEGIN
  IF retain_days IS NULL OR retain_days < 7 THEN
    RAISE EXCEPTION 'retain_days must be at least 7 (got %)', retain_days;
  END IF;
  cutoff := NOW() - make_interval(days => retain_days);
  DELETE FROM public.report_jobs WHERE requested_at < cutoff;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION public.purge_report_job_history(INTEGER) FROM PUBLIC, anon, authenticated;

NOTIFY pgrst, 'reload schema';

-- Rollback (additive only; nothing here is referenced by any table that predates this migration):
--   DROP FUNCTION IF EXISTS public.purge_report_job_history(INTEGER);
--   DROP FUNCTION IF EXISTS public.purge_expired_report_artifacts();
--   DROP FUNCTION IF EXISTS public.report_claim_job(TEXT);
--   DROP TABLE IF EXISTS public.report_deliveries;
--   DROP TABLE IF EXISTS public.report_artifacts;
--   DROP TABLE IF EXISTS public.report_jobs;
--   DROP TABLE IF EXISTS public.report_recipients;
--   DROP TABLE IF EXISTS public.report_schedules;
