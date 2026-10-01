// Where is this backend running, and is it allowed to run scheduled jobs that WRITE?
//
// Background: the local .env is a copy of production's (same Supabase project, service key and
// even NODE_ENV=production), so a developer starting the backend used to run every production
// job — case escalation email, threat-intel writes, MISP pushes — against the production
// database. This module decides, without any hardcoded database URL:
//
//   App environment
//     NOVRSOC_ENV (production | staging | development | test) always wins.
//     On Railway (RAILWAY_ENVIRONMENT_NAME / RAILWAY_PROJECT_ID present): production when the
//       Railway environment is named "production", otherwise staging.
//     Anywhere else: development. NODE_ENV is deliberately ignored off Railway, because a copied
//       production .env carries NODE_ENV=production.
//
//   Database environment
//     SUPABASE_ENV (production | staging | development | test) declares what SUPABASE_URL is.
//     Undeclared means "assume production" — fail safe.
//     NOVRSOC_PRODUCTION_SUPABASE_URLS (comma-separated, optional) lists known production
//     projects; a URL on that list is production whatever SUPABASE_ENV says.
//
//   Mutating scheduled jobs run when the app is production, or when the database is explicitly a
//   development/test database that is not on the production list. Everything else: disabled,
//   with a loud warning. Request handling is not affected.

export type AppEnv = 'production' | 'staging' | 'development' | 'test';
export type DbEnv = AppEnv | 'undeclared';

const ENVS: AppEnv[] = ['production', 'staging', 'development', 'test'];
const asEnv = (v: string | undefined): AppEnv | null => {
    const x = (v ?? '').trim().toLowerCase();
    return (ENVS as string[]).includes(x) ? (x as AppEnv) : null;
};
const normUrl = (u: string) => u.trim().toLowerCase().replace(/\/+$/, '');

export function appEnvironment(env: NodeJS.ProcessEnv = process.env): { env: AppEnv; reason: string } {
    const explicit = asEnv(env.NOVRSOC_ENV);
    if (explicit) return { env: explicit, reason: `NOVRSOC_ENV=${explicit}` };
    const railwayEnv = env.RAILWAY_ENVIRONMENT_NAME ?? env.RAILWAY_ENVIRONMENT;
    if (railwayEnv || env.RAILWAY_PROJECT_ID) {
        return railwayEnv?.toLowerCase() === 'production'
            ? { env: 'production', reason: 'Railway environment "production"' }
            : { env: 'staging', reason: `Railway environment "${railwayEnv ?? 'unknown'}"` };
    }
    return { env: 'development', reason: 'not running on Railway and NOVRSOC_ENV is not set' };
}

export function databaseEnvironment(env: NodeJS.ProcessEnv = process.env): { env: DbEnv; reason: string } {
    const url = env.SUPABASE_URL ? normUrl(env.SUPABASE_URL) : '';
    const prodList = (env.NOVRSOC_PRODUCTION_SUPABASE_URLS ?? '').split(',').map(normUrl).filter(Boolean);
    if (url && prodList.includes(url)) return { env: 'production', reason: 'SUPABASE_URL is listed in NOVRSOC_PRODUCTION_SUPABASE_URLS' };
    const declared = asEnv(env.SUPABASE_ENV);
    if (declared) return { env: declared, reason: `SUPABASE_ENV=${declared}` };
    return { env: 'undeclared', reason: 'SUPABASE_ENV is not set, so the database is treated as production' };
}

export interface JobPolicy { allowed: boolean; app: AppEnv; db: DbEnv; reason: string }

export function scheduledJobPolicy(env: NodeJS.ProcessEnv = process.env): JobPolicy {
    const app = appEnvironment(env);
    const db = databaseEnvironment(env);
    if (env.NOVRSOC_DISABLE_JOBS === 'true') return { allowed: false, app: app.env, db: db.env, reason: 'NOVRSOC_DISABLE_JOBS=true' };
    if (app.env === 'production') return { allowed: true, app: app.env, db: db.env, reason: `production (${app.reason})` };
    if (db.env === 'development' || db.env === 'test') {
        return { allowed: true, app: app.env, db: db.env, reason: `${app.env} app on a declared ${db.env} database (${db.reason})` };
    }
    return {
        allowed: false, app: app.env, db: db.env,
        reason: `${app.env} app (${app.reason}) on a ${db.env === 'undeclared' ? 'possibly production' : db.env} database (${db.reason})`,
    };
}

/** Logs the decision once at startup; returns whether mutating jobs may start. */
export function announceJobPolicy(): boolean {
    const p = scheduledJobPolicy();
    if (p.allowed) {
        console.log(`[env] Scheduled jobs ENABLED — ${p.reason}`);
    } else {
        console.warn('');
        console.warn('[env] ================================================================');
        console.warn(`[env] Scheduled jobs that write data are DISABLED — ${p.reason}.`);
        console.warn('[env] This protects the production database from a local/staging run.');
        console.warn('[env] To run them against a development database: set SUPABASE_URL to that');
        console.warn('[env] database and SUPABASE_ENV=development. Production is unaffected.');
        if (p.db !== 'development' && p.db !== 'test') console.warn('[env] WARNING: API requests from this instance still read and write this database.');
        console.warn('[env] ================================================================');
        console.warn('');
    }
    return p.allowed;
}
