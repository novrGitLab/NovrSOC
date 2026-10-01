-- NovrSOC — email_logs: one row per (organisation, message, recipient).
-- SEPARATE migration from 2026-09-email-security.sql. Run once in the Supabase SQL editor; safe
-- to re-run. Deletes no rows.
--
-- Why: the mail gateway reports one verdict per recipient (the payload carries a single
-- to_address), but the table was unique on message_id alone, so a message sent to three people
-- kept only the last recipient's row — and the same Message-ID at two customers overwrote across
-- tenants. The event identity is (org_id, message_id, to_address).
--
-- Order matters: the new unique index is created FIRST, then any unique constraint/index on
-- message_id alone is dropped, so there is never a moment without de-duplication. Every existing
-- row is already unique on message_id, hence also unique on the wider key — no data conflicts.
--
-- The backend works before and after this migration (it falls back to the old conflict key
-- when the new index does not exist yet), so deploy order does not matter.

BEGIN;

DO $$
BEGIN
  IF to_regclass('public.email_logs') IS NULL THEN
    RAISE EXCEPTION 'public.email_logs does not exist — nothing to migrate.';
  END IF;
END $$;

-- 1. The correct identity.
CREATE UNIQUE INDEX IF NOT EXISTS email_logs_org_message_recipient_key
  ON public.email_logs (org_id, message_id, to_address);

-- 2. Drop whatever made message_id alone unique — a constraint or a bare unique index, whatever
--    its name. Only single-column unique objects on message_id are touched.
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT c.conname
    FROM pg_constraint c
    WHERE c.conrelid = 'public.email_logs'::regclass
      AND c.contype = 'u'
      AND array_length(c.conkey, 1) = 1
      AND c.conkey[1] = (SELECT attnum FROM pg_attribute WHERE attrelid = 'public.email_logs'::regclass AND attname = 'message_id')
  LOOP
    EXECUTE format('ALTER TABLE public.email_logs DROP CONSTRAINT %I', r.conname);
    RAISE NOTICE 'dropped unique constraint % on email_logs(message_id)', r.conname;
  END LOOP;

  FOR r IN
    SELECT ic.relname AS indexname
    FROM pg_index i
    JOIN pg_class ic ON ic.oid = i.indexrelid
    WHERE i.indrelid = 'public.email_logs'::regclass
      AND i.indisunique AND NOT i.indisprimary
      AND i.indnatts = 1
      AND i.indkey[0] = (SELECT attnum FROM pg_attribute WHERE attrelid = 'public.email_logs'::regclass AND attname = 'message_id')
      AND NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = i.indexrelid)
  LOOP
    EXECUTE format('DROP INDEX public.%I', r.indexname);
    RAISE NOTICE 'dropped unique index % on email_logs(message_id)', r.indexname;
  END LOOP;
END $$;

-- 3. Keep message_id fast to look up (no longer unique).
CREATE INDEX IF NOT EXISTS email_logs_message_id_idx ON public.email_logs (message_id);
CREATE INDEX IF NOT EXISTS email_logs_org_received_idx ON public.email_logs (org_id, received_at DESC);

COMMIT;
