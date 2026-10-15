-- Phase P3 — SecOps triage, response approvals and AI records.
-- Additive and idempotent: safe to re-run. Needs the R2 `alerts` and the cases tables.
-- RLS convention: RLS on, one service-role policy, nothing for anon/authenticated.

-- ── Alert triage fields ─────────────────────────────────────────────────────────────────────
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS assigned_to TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS acknowledged_by TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS triage_note TEXT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS alerts_org_assigned_idx ON public.alerts (org_id, assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_case_idx ON public.alerts (case_id) WHERE case_id IS NOT NULL;

-- Every triage change on an alert (status, assignment, acknowledgement, note, case link).
CREATE TABLE IF NOT EXISTS public.alert_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id    UUID NOT NULL REFERENCES public.alerts(id) ON DELETE CASCADE,
  org_id      TEXT NOT NULL,
  at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,               -- status | assign | acknowledge | note | case_link
  from_value  TEXT,
  to_value    TEXT,
  details     TEXT
);
CREATE INDEX IF NOT EXISTS alert_events_alert_idx ON public.alert_events (alert_id, at);

-- ── Case deadlines ──────────────────────────────────────────────────────────────────────────
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS due_at TIMESTAMPTZ;

-- ── Response approvals ──────────────────────────────────────────────────────────────────────
-- Consequential response actions (block an IP, isolate a host) are requested, then approved by
-- a soc_manager or super_admin before they run. The stored result is what the remote system
-- actually returned.
CREATE TABLE IF NOT EXISTS public.response_approvals (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  action        TEXT NOT NULL CHECK (action IN ('block_ip', 'isolate_agent')),
  target        TEXT NOT NULL,              -- IP address or Wazuh agent id
  target_label  TEXT,                       -- agent name, for display
  reason        TEXT NOT NULL,
  case_id       UUID REFERENCES public.cases(id) ON DELETE SET NULL,
  task_id       UUID,
  threat_id     TEXT,
  source        TEXT NOT NULL,              -- case | playbook | threat
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed', 'skipped', 'cancelled')),
  requested_by  TEXT NOT NULL,
  requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_by    TEXT,
  decided_at    TIMESTAMPTZ,
  decision_note TEXT,
  result        TEXT,
  executed_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS response_approvals_org_status_idx ON public.response_approvals (org_id, status, requested_at DESC);
-- At most one open request per action and target in an organisation.
CREATE UNIQUE INDEX IF NOT EXISTS response_approvals_open_key ON public.response_approvals (org_id, action, target) WHERE status = 'pending';

-- ── AI ──────────────────────────────────────────────────────────────────────────────────────
-- Metadata for every model call: no prompt or response text is stored here.
CREATE TABLE IF NOT EXISTS public.ai_requests (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  org_id         TEXT,
  actor          TEXT,
  purpose        TEXT NOT NULL,
  model          TEXT,
  served_by      TEXT,                     -- the model that answered (differs after a fallback)
  source_refs    JSONB NOT NULL DEFAULT '[]',
  status         TEXT NOT NULL CHECK (status IN ('ok', 'refused', 'invalid_output', 'unavailable', 'error')),
  input_tokens   INT,
  output_tokens  INT,
  latency_ms     INT,
  error          TEXT
);
CREATE INDEX IF NOT EXISTS ai_requests_org_at_idx ON public.ai_requests (org_id, at DESC);

-- AI outputs people act on (summaries, plans, reports), with the records they were built from.
-- An artifact is advice: nothing in the platform changes state because one exists.
CREATE TABLE IF NOT EXISTS public.ai_artifacts (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        TEXT NOT NULL,
  purpose       TEXT NOT NULL,
  subject_type  TEXT NOT NULL,             -- alert | case | finding | asset | indicator | report
  subject_id    TEXT NOT NULL,
  source_refs   JSONB NOT NULL DEFAULT '[]',
  content       JSONB NOT NULL,
  model         TEXT NOT NULL,
  created_by    TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status        TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'accepted', 'rejected')),
  feedback      TEXT,
  feedback_by   TEXT,
  feedback_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ai_artifacts_subject_idx ON public.ai_artifacts (org_id, subject_type, subject_id, created_at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['alert_events', 'response_approvals', 'ai_requests', 'ai_artifacts'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_service') THEN
      EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL USING (auth.role() = ''service_role'')', t || '_service', t);
    END IF;
  END LOOP;
END $$;
