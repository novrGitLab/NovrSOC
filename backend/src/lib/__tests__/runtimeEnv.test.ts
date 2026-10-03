// Environment guard for scheduled jobs (lib/runtimeEnv.ts). Pure functions over a fake env —
// nothing here touches any database.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import { join } from 'path';
import { scheduledJobPolicy, appEnvironment, databaseEnvironment, databaseStartupCheck } from '../runtimeEnv';

const PROD_DB = 'https://prodproject.supabase.co';
const TEST_DB = 'https://testproject.supabase.co';
const railwayProd = { RAILWAY_ENVIRONMENT_NAME: 'production', RAILWAY_PROJECT_ID: 'p1' };

test('development + production DB → jobs disabled', () => {
    // Exactly the local situation found: a copied production .env, not on Railway.
    const p = scheduledJobPolicy({ SUPABASE_URL: PROD_DB, NODE_ENV: 'production' });
    assert.equal(p.app, 'development');
    assert.equal(p.db, 'undeclared');
    assert.equal(p.allowed, false);
    // …also when the production URL is listed, even if someone mislabels it as a test DB.
    const listed = scheduledJobPolicy({ SUPABASE_URL: PROD_DB, SUPABASE_ENV: 'test', NOVRSOC_PRODUCTION_SUPABASE_URLS: `${PROD_DB}/` });
    assert.equal(listed.db, 'production');
    assert.equal(listed.allowed, false);
});

test('development + test DB → jobs allowed', () => {
    const p = scheduledJobPolicy({ SUPABASE_URL: TEST_DB, SUPABASE_ENV: 'test', NOVRSOC_PRODUCTION_SUPABASE_URLS: PROD_DB });
    assert.equal(p.app, 'development');
    assert.equal(p.allowed, true);
    assert.equal(scheduledJobPolicy({ SUPABASE_URL: TEST_DB, SUPABASE_ENV: 'development' }).allowed, true);
});

test('production + production DB → jobs allowed', () => {
    const p = scheduledJobPolicy({ ...railwayProd, SUPABASE_URL: PROD_DB, NODE_ENV: 'production' });
    assert.equal(p.app, 'production');
    assert.equal(p.allowed, true);
    // Production is unaffected by the new variables being absent or present.
    assert.equal(scheduledJobPolicy({ ...railwayProd, SUPABASE_URL: PROD_DB, NOVRSOC_PRODUCTION_SUPABASE_URLS: PROD_DB }).allowed, true);
    assert.equal(scheduledJobPolicy({ NOVRSOC_ENV: 'production', SUPABASE_URL: PROD_DB }).allowed, true);
});

test('staging on Railway with an undeclared database → disabled', () => {
    const p = scheduledJobPolicy({ RAILWAY_ENVIRONMENT_NAME: 'staging', SUPABASE_URL: PROD_DB });
    assert.equal(p.app, 'staging');
    assert.equal(p.allowed, false);
});

test('NODE_ENV=production off Railway does not make the app production', () => {
    assert.equal(appEnvironment({ NODE_ENV: 'production' }).env, 'development');
    assert.equal(appEnvironment({ NOVRSOC_ENV: 'PRODUCTION' }).env, 'production');
    assert.equal(appEnvironment({ NOVRSOC_ENV: 'nonsense' }).env, 'development');
});

test('undeclared or unknown SUPABASE_ENV is treated as production-risk', () => {
    assert.equal(databaseEnvironment({ SUPABASE_URL: TEST_DB }).env, 'undeclared');
    assert.equal(databaseEnvironment({ SUPABASE_URL: TEST_DB, SUPABASE_ENV: 'dev-ish' }).env, 'undeclared');
    assert.equal(scheduledJobPolicy({ SUPABASE_URL: TEST_DB, SUPABASE_ENV: 'dev-ish' }).allowed, false);
});

test('NOVRSOC_DISABLE_JOBS switches jobs off anywhere', () => {
    assert.equal(scheduledJobPolicy({ ...railwayProd, NOVRSOC_DISABLE_JOBS: 'true' }).allowed, false);
});

// ── Startup refusal (API access, not just jobs) ──

const DEV_DB = 'https://devproject.supabase.co';

test('startup rule: dev+prod refused; dev+dev, test+test, prod+prod allowed', () => {
    assert.equal(databaseStartupCheck({ SUPABASE_URL: PROD_DB }).ok, false, 'dev + undeclared (copied production .env)');
    assert.equal(databaseStartupCheck({ SUPABASE_URL: PROD_DB, SUPABASE_ENV: 'production' }).ok, false, 'dev + declared production');
    assert.equal(databaseStartupCheck({ SUPABASE_URL: PROD_DB, SUPABASE_ENV: 'development', NOVRSOC_PRODUCTION_SUPABASE_URLS: PROD_DB }).ok, false, 'dev + production URL mislabelled');
    assert.equal(databaseStartupCheck({ SUPABASE_URL: DEV_DB, SUPABASE_ENV: 'development' }).ok, true, 'dev + dev');
    assert.equal(databaseStartupCheck({ NOVRSOC_ENV: 'test', SUPABASE_URL: TEST_DB, SUPABASE_ENV: 'test' }).ok, true, 'test + test');
    assert.equal(databaseStartupCheck({ ...railwayProd, SUPABASE_URL: PROD_DB }).ok, true, 'prod + prod');
    assert.equal(databaseStartupCheck({ RAILWAY_ENVIRONMENT_NAME: 'staging', SUPABASE_URL: PROD_DB }).ok, false, 'staging + undeclared');
    assert.equal(databaseStartupCheck({}).ok, true, 'no database configured');
});

// Runs the real guard module in a child process. It makes no database call — it only reads env.
function startGuard(env: Record<string, string>) {
    const r = spawnSync(process.execPath, ['--import', 'tsx', join(__dirname, '..', 'envGuard.ts')], {
        env: { PATH: process.env.PATH ?? '', SystemRoot: process.env.SystemRoot ?? '', ...env }, encoding: 'utf8', timeout: 60_000,
    });
    return { code: r.status, stderr: r.stderr };
}

test('development + production database → the application refuses to start', () => {
    const r = startGuard({ SUPABASE_URL: PROD_DB, SUPABASE_SERVICE_KEY: 'not-a-real-key', NODE_ENV: 'production' });
    assert.equal(r.code, 1);
    assert.match(r.stderr, /REFUSING TO START/);
    assert.doesNotMatch(r.stderr, /not-a-real-key/, 'never prints the key');
});

test('development + development database → starts', () => {
    assert.equal(startGuard({ SUPABASE_URL: DEV_DB, SUPABASE_ENV: 'development' }).code, 0);
});

test('test + test database → starts', () => {
    assert.equal(startGuard({ NOVRSOC_ENV: 'test', SUPABASE_URL: TEST_DB, SUPABASE_ENV: 'test' }).code, 0);
});

test('production + production database → starts', () => {
    assert.equal(startGuard({ RAILWAY_ENVIRONMENT_NAME: 'production', RAILWAY_PROJECT_ID: 'p', SUPABASE_URL: PROD_DB }).code, 0);
});
