-- Phase P26 — IOC lookup cache per organisation (ioc_enrichments).
--
-- Before: one shared row per IOC value (primary key ioc_value). /api/cti/feed, /api/cti/stats,
-- /api/intelligence/stix and /api/search read every row, so any signed-in user saw which values
-- other organisations had looked up or escalated, with their scores. After: one row per
-- (organisation, value); every read is filtered by the requester's organisation.
--
-- Additive and idempotent: safe to run twice. No row is deleted.
--   • org_id is added if missing (some environments already have it from the hunt escalation path).
--   • A surrogate primary key `id` replaces the ioc_value primary key, and (org_id, ioc_value)
--     becomes unique — the conflict target the backend now upserts on.
--   • Existing rows keep org_id as it is. Rows without one (written by the old shared lookup cache)
--     are attributed to nobody, so no organisation sees them (fail closed). If every such row is
--     known to belong to one organisation, attribute them explicitly with the optional statement
--     at the end — never guess.
-- Requires: the ioc_enrichments table (backend/novrsoc_supabase_schema.sql). No other dependency.

ALTER TABLE public.ioc_enrichments ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE public.ioc_enrichments ADD COLUMN IF NOT EXISTS id UUID NOT NULL DEFAULT gen_random_uuid();

DO $$
DECLARE pk_name text; pk_cols text;
BEGIN
  SELECT c.conname, string_agg(a.attname, ',' ORDER BY a.attnum)
    INTO pk_name, pk_cols
    FROM pg_constraint c
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
   WHERE c.conrelid = 'public.ioc_enrichments'::regclass AND c.contype = 'p'
   GROUP BY c.conname;
  -- The old primary key on ioc_value alone makes a second organisation's row impossible.
  IF pk_name IS NOT NULL AND pk_cols = 'ioc_value' THEN
    EXECUTE format('ALTER TABLE public.ioc_enrichments DROP CONSTRAINT %I', pk_name);
    pk_name := NULL;
  END IF;
  IF pk_name IS NULL THEN
    ALTER TABLE public.ioc_enrichments ADD CONSTRAINT ioc_enrichments_pkey PRIMARY KEY (id);
  END IF;
END $$;

-- Any other unique constraint or index on ioc_value alone would block per-organisation rows too.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT c.conname FROM pg_constraint c
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
     WHERE c.conrelid = 'public.ioc_enrichments'::regclass AND c.contype = 'u'
     GROUP BY c.conname HAVING string_agg(a.attname, ',') = 'ioc_value'
  LOOP
    EXECUTE format('ALTER TABLE public.ioc_enrichments DROP CONSTRAINT %I', r.conname);
  END LOOP;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ioc_enrichments_org_value_key ON public.ioc_enrichments (org_id, ioc_value);
CREATE INDEX IF NOT EXISTS ioc_enrichments_org_seen_idx ON public.ioc_enrichments (org_id, last_seen DESC);

-- Optional, only when it is known that every unattributed row belongs to one organisation
-- (replace the slug; check first with: select count(*) from ioc_enrichments where org_id is null;):
--   UPDATE public.ioc_enrichments SET org_id = 'cybernovr' WHERE org_id IS NULL
--     AND NOT EXISTS (SELECT 1 FROM public.ioc_enrichments x WHERE x.org_id = 'cybernovr' AND x.ioc_value = ioc_enrichments.ioc_value);
