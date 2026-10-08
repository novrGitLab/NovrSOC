-- Phase S2 — case de-duplication per organisation. Idempotent: safe to re-run.
--
-- ROLLOUT ORDER: run this file FIRST, then deploy the backend that scopes createCase()'s
-- lookup by org_id. (New code against the old key: a second org escalating the same IOC hits the
-- old unique (source, source_id), and its case creation fails instead of opening a new case.)
--
-- Before: cases had UNIQUE(source, source_id) (sql/2026-09-cases-soar.sql:56, declared inline,
-- so Postgres named it cases_source_source_id_key). Two organisations hunting or escalating the
-- same IOC collided on it, and the second org was handed the first org's case.
-- After: unique per (org_id, source, source_id). The SOAR engine (infra/soar/soar.py) writes with
-- a plain insert and treats a unique violation as "already cased"; it keeps working because it
-- always writes the same org_id.

-- 1. The new per-org key, created before the old one is dropped so there is never a window
--    without one. Rows already unique on (source, source_id) are unique on this too.
CREATE UNIQUE INDEX IF NOT EXISTS cases_org_source_source_id_key
  ON public.cases (org_id, source, source_id);

-- 2. Drop the old key by its default name…
ALTER TABLE public.cases DROP CONSTRAINT IF EXISTS cases_source_source_id_key;

-- 3. …and any other unique constraint or unique index on exactly (source, source_id), in case
--    the live database named it differently.
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT con.conname
    FROM pg_constraint con
    JOIN pg_class t ON t.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'public' AND t.relname = 'cases' AND con.contype = 'u'
      AND (SELECT array_agg(a.attname::text ORDER BY a.attname)
           FROM unnest(con.conkey) k JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k)
          = ARRAY['source', 'source_id']
  LOOP
    EXECUTE format('ALTER TABLE public.cases DROP CONSTRAINT %I', r.conname);
    RAISE NOTICE 'dropped unique constraint %', r.conname;
  END LOOP;

  FOR r IN
    SELECT i.relname AS indexname
    FROM pg_index x
    JOIN pg_class i ON i.oid = x.indexrelid
    JOIN pg_class t ON t.oid = x.indrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'public' AND t.relname = 'cases' AND x.indisunique AND NOT x.indisprimary
      AND NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = x.indexrelid)
      AND (SELECT array_agg(a.attname::text ORDER BY a.attname)
           FROM unnest(x.indkey) k JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k)
          = ARRAY['source', 'source_id']
  LOOP
    EXECUTE format('DROP INDEX public.%I', r.indexname);
    RAISE NOTICE 'dropped unique index %', r.indexname;
  END LOOP;
END $$;

-- 4. Report rows without an organisation. org_id is NOT NULL DEFAULT 'cybernovr' in the
--    original schema, so this should be 0; if it isn't, those rows are not covered by the new
--    key (NULLs never conflict) and need an owner assigned by hand.
DO $$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM public.cases WHERE org_id IS NULL;
  RAISE NOTICE 'cases with NULL org_id: %', n;
END $$;

SELECT count(*) AS cases_with_null_org_id FROM public.cases WHERE org_id IS NULL;
