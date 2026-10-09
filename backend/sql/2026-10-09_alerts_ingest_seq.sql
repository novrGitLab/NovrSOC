-- Phase X1 follow-up — a monotonic ingest order for the vendor export. Additive and idempotent:
-- safe to re-run. Run it AFTER 2026-10-09_alerts_pipeline.sql and BEFORE deploying the backend
-- whose export pages by ingest_seq.
--
-- Why: the export used to page by (event_time, id). Alerts are stored after the fact (forwarder
-- backfill, replay after an outage, the overlap window), so an alert with an old event_time could
-- be inserted after a vendor's cursor had already passed that time, and it was never exported.
-- ingest_seq numbers rows in the order they were stored, so "everything after my cursor" includes
-- late arrivals.
--
-- One transaction, with alerts locked against writes for its duration, so no insert can take a
-- sequence value while existing rows are being numbered. Existing rows are numbered in
-- (received_at, id) order, after any rows that already have a number. The sequence is only ever
-- moved forward, so a value is never issued twice (a re-issued value could land behind a vendor's
-- cursor and be skipped).

BEGIN;

LOCK TABLE public.alerts IN SHARE ROW EXCLUSIVE MODE;

CREATE SEQUENCE IF NOT EXISTS public.alerts_ingest_seq_seq AS BIGINT;
ALTER TABLE public.alerts ADD COLUMN IF NOT EXISTS ingest_seq BIGINT;

-- Backfill: rows without a number, in (received_at, id) order, after the highest existing number.
WITH base AS (
  SELECT COALESCE(MAX(ingest_seq), 0) AS b FROM public.alerts
), ordered AS (
  SELECT id, row_number() OVER (ORDER BY received_at NULLS FIRST, id) AS rn
  FROM public.alerts WHERE ingest_seq IS NULL
)
UPDATE public.alerts a
SET ingest_seq = base.b + ordered.rn
FROM ordered, base
WHERE a.id = ordered.id;

-- Move the sequence past every number in use — never backwards.
DO $$
DECLARE
  hi BIGINT;
  cur BIGINT;
  called BOOLEAN;
BEGIN
  SELECT MAX(ingest_seq) INTO hi FROM public.alerts;
  SELECT last_value, is_called INTO cur, called FROM public.alerts_ingest_seq_seq;
  IF hi IS NOT NULL AND (hi > cur OR (hi = cur AND NOT called)) THEN
    PERFORM setval('public.alerts_ingest_seq_seq', hi, true);
  END IF;
END $$;

ALTER TABLE public.alerts ALTER COLUMN ingest_seq SET DEFAULT nextval('public.alerts_ingest_seq_seq');
ALTER SEQUENCE public.alerts_ingest_seq_seq OWNED BY public.alerts.ingest_seq;
ALTER TABLE public.alerts ALTER COLUMN ingest_seq SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS alerts_ingest_seq_key ON public.alerts (ingest_seq);
-- The export reads WHERE org_id IN (...) AND ingest_seq > cursor ORDER BY ingest_seq.
CREATE INDEX IF NOT EXISTS alerts_org_ingest_seq_idx ON public.alerts (org_id, ingest_seq);

COMMIT;
