// One-off migration runner for the dedicated dev/test Supabase project used to capture real
// NovrSOC UI for the conference video. Lives entirely in video-production/ — not committed into
// backend/. Applies backend/novrsoc_supabase_schema.sql, then backend/sql/*.sql, then
// backend/src/db/rls-policies.sql, against the Postgres connection string in PG_CONN_STRING.
//
// The sql/*.sql files aren't a strict dependency-ordered chain (e.g. an "alert-communications"
// migration references a `cases` table that a later-sorted "cases-soar" migration creates) — so
// this runs repeated passes, retrying only files that haven't succeeded yet, until a full pass
// makes no further progress (fixpoint) or everything has applied.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';

const BACKEND = 'C:\\Users\\USER\\NovrSOC\\backend';
const connectionString = process.env.PG_CONN_STRING;
if (!connectionString) {
  console.error('Set PG_CONN_STRING env var first.');
  process.exit(1);
}

const HERE = 'C:\\Users\\USER\\NovrSOC\\video-production\\scripts';

// Skipped deliberately:
// - 2026-09-organisations-onboarding.sql: its INSERT hardcodes the real production org's UUID
//   and a named real staff member (rayne@cybernovr.com) as super_admin. The ALTER/index parts it
//   would otherwise contribute are already covered by bootstrap-missing-tables.sql above (using
//   the real column names its own header comment documents), and our own synthetic org/admin are
//   seeded separately by seed.mjs — so nothing of this file is actually needed, and the part that
//   IS needed is reproduced without the real person's data.
const SKIP = new Set(['2026-09-organisations-onboarding.sql']);

const files = [
  join(HERE, 'bootstrap-missing-tables.sql'),
  join(BACKEND, 'novrsoc_supabase_schema.sql'),
  ...readdirSync(join(BACKEND, 'sql'))
    .filter((f) => f.endsWith('.sql') && !SKIP.has(f))
    .sort()
    .map((f) => join(BACKEND, 'sql', f)),
  join(BACKEND, 'src', 'db', 'rls-policies.sql'),
];

const client = new pg.Client({ connectionString, ssl: { rejectUnauthorized: false } });

async function main() {
  await client.connect();
  console.log(`Connected. Applying ${files.length} SQL files (multi-pass).`);

  const pending = new Set(files);
  const ok = [];
  let lastError = new Map();
  let pass = 0;

  while (pending.size > 0) {
    pass++;
    let progressed = false;
    for (const f of [...pending]) {
      const sql = readFileSync(f, 'utf8');
      try {
        await client.query(sql);
        ok.push(f);
        pending.delete(f);
        progressed = true;
        console.log(`OK    [pass ${pass}] ${f}`);
      } catch (err) {
        // "already exists" on a bare re-run (e.g. a policy this script created on an earlier,
        // partially-successful pass) means the file's effect is already in place — not a real
        // failure.
        if (/already exists/i.test(err.message)) {
          ok.push(f);
          pending.delete(f);
          progressed = true;
          console.log(`OK*   [pass ${pass}] ${f} (already applied: ${err.message})`);
        } else {
          lastError.set(f, err.message);
        }
        try {
          await client.query('ROLLBACK');
        } catch {
          /* no transaction was open — fine */
        }
      }
    }
    if (!progressed) break;
  }

  console.log(`\n${ok.length}/${files.length} files applied (after ${pass} pass(es)).`);
  if (pending.size) {
    console.log('\nStill failing:');
    for (const f of pending) console.log(`  ${f}\n    ${lastError.get(f)}`);
  }
  await client.end();
  process.exit(pending.size ? 2 : 0);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
