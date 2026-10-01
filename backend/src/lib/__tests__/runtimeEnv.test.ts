// Environment guard for scheduled jobs (lib/runtimeEnv.ts). Pure functions over a fake env —
// nothing here touches any database.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scheduledJobPolicy, appEnvironment, databaseEnvironment } from '../runtimeEnv';

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
