// Imported immediately after dotenv/config (and the TLS guard) in index.ts, before any module
// that can reach the database. A development, test or staging process pointed at a production —
// or undeclared — Supabase database refuses to start: local API requests must never read or
// write production data. See databaseStartupCheck() in runtimeEnv.ts for the rules.
import { databaseStartupCheck } from './runtimeEnv';

const check = databaseStartupCheck();
if (!check.ok) {
    console.error('');
    console.error('[env] ======================================================================');
    console.error(`[env] REFUSING TO START: ${check.reason}.`);
    console.error('[env] Outside production this backend only runs against a development or test database.');
    console.error('[env] Point SUPABASE_URL / SUPABASE_SERVICE_KEY at a separate Supabase project and set');
    console.error('[env] SUPABASE_ENV=development (or test). See backend/.env.example.');
    console.error('[env] ======================================================================');
    console.error('');
    process.exit(1);
}
