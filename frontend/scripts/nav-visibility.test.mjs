// Unit tests for src/config/nav.ts's toNavGroups() status filter (2026 redesign, Stage 6).
// A BROKEN/PLANNED item is hidden from everyone but super_admin, who still sees it with a badge
// — the audit's recommendation (§4.5) so a customer or analyst is never sent to a page where
// every API call is refused. Transpiles the real nav.ts (as check-nav-routes.mjs does), so this
// runs against the app's actual ADMIN_NAV/CLIENT_NAV data, not a fixture.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'nav-visibility-test');
mkdirSync(cacheDir, { recursive: true });

function transpile(name) {
    const source = join(root, 'src', 'config', `${name}.ts`);
    const out = ts.transpileModule(readFileSync(source, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, verbatimModuleSyntax: false },
        fileName: source,
    });
    const file = join(cacheDir, `${name}.mjs`);
    writeFileSync(file, out.outputText.replace(/from '\.\/vmsSections'/g, "from './vmsSections.mjs'"));
    return file;
}
transpile('vmsSections');
const { ADMIN_NAV, CLIENT_NAV, toNavGroups } = await import(pathToFileURL(transpile('nav')).href);

const findItem = (groups, label) => groups.flatMap((g) => g.items).find((i) => i.label === label);

test('a BROKEN client item is absent for the client portal\'s only role (portal_user)', () => {
    const groups = toNavGroups(CLIENT_NAV, 'portal_user');
    assert.equal(findItem(groups, 'Domain Suite'), undefined, 'BROKEN item is hidden');
    assert.ok(findItem(groups, 'Overview'), 'a WORKING item (client VMS) stays visible');
});

test('a section left with no items once its only entry is hidden is dropped entirely, not rendered empty', () => {
    const groups = toNavGroups(CLIENT_NAV, 'portal_user');
    assert.equal(groups.find((g) => g.section === 'Account'), undefined, 'Account held only the BROKEN billing item');
});

test('super_admin sees a BROKEN item, carrying a badge naming its status', () => {
    const groups = toNavGroups(CLIENT_NAV, 'super_admin');
    const item = findItem(groups, 'Domain Suite');
    assert.ok(item, 'super_admin can still reach it, e.g. to verify a fix');
    assert.equal(item.badge, 'BROKEN');
});

test('a WORKING item never carries a badge, for any role', () => {
    const groups = toNavGroups(CLIENT_NAV, 'super_admin');
    assert.equal(findItem(groups, 'Overview').badge, undefined);
});

test('the admin nav applies the same rule: a BROKEN compliance item is hidden from a manager, badged for super_admin', () => {
    const forManager = toNavGroups(ADMIN_NAV, 'soc_manager');
    assert.equal(findItem(forManager, 'CBN Framework'), undefined);
    const forAdmin = toNavGroups(ADMIN_NAV, 'super_admin');
    assert.equal(findItem(forAdmin, 'CBN Framework')?.badge, 'BROKEN');
});
