// Unit tests for src/lib/breadcrumbs.ts's pure matching logic (2026 redesign, Stage 1 header).
// breadcrumbFromSections() takes its nav data as parameters, so it is tested here with small
// fixture data rather than transpiling config/nav.ts and config/vmsSections.ts (which pull in
// lucide-react icon modules) just to exercise matching — breadcrumbFor() (the real call site,
// using the app's actual nav data) is covered indirectly by check:nav and the build.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'breadcrumbs-test');
mkdirSync(cacheDir, { recursive: true });

async function load(source, name) {
    const out = ts.transpileModule(readFileSync(source, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
        fileName: source,
    });
    const file = join(cacheDir, `${name}.mjs`);
    writeFileSync(file, out.outputText);
    return import(pathToFileURL(file).href);
}

// breadcrumbs.ts itself imports config/nav.ts and config/vmsSections.ts at the top (for
// breadcrumbFor()) via the `@/` alias, which this lightweight loader can't resolve — but
// breadcrumbFromSections, the function under test, never calls them. Stub both specifiers out
// to empty modules before transpiling so the import lines don't need to resolve for real.
const src = readFileSync(join(root, 'src', 'lib', 'breadcrumbs.ts'), 'utf8')
    .replace("from '@/config/nav'", "from './stub-nav.mjs'")
    .replace("from '@/config/vmsSections'", "from './stub-vms.mjs'");
writeFileSync(join(cacheDir, 'stub-nav.mjs'), 'export const ADMIN_NAV = []; export const CLIENT_NAV = [];\n');
writeFileSync(join(cacheDir, 'stub-vms.mjs'), 'export const VMS_SECTIONS = [];\n');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, 'src', 'lib', 'breadcrumbs.ts') });
writeFileSync(join(cacheDir, 'breadcrumbs.mjs'), out.outputText);
const { breadcrumbFromSections, humanizeLastSegment } = await import(pathToFileURL(join(cacheDir, 'breadcrumbs.mjs')).href);

const NAV = [
    { section: 'SecOps', groupLabel: 'Security Operations', items: [
        { href: '/admin/secops/cases', label: 'Cases' },
        { href: '/admin/secops/alerts', label: 'Alerts', match: ['/admin/secops/alerts'] },
    ] },
    { section: 'Brand', items: [
        { href: '/admin/brand/domain', label: 'Domain Intelligence' },
    ] },
];
const VMS = [
    { href: '/admin/vms', label: 'VMS Overview', pages: [{ href: '/admin/vms', label: 'VMS Dashboard' }] },
    { href: '/admin/vms/assets', label: 'Asset Management', pages: [
        { href: '/admin/vms/assets', label: 'Asset Inventory' },
        { href: '/admin/vms/import', label: 'Asset Import' },
    ] },
];

test('an exact nav href gives the section group label and the item label', () => {
    assert.deepEqual(breadcrumbFromSections('/admin/secops/cases', NAV, VMS), { section: 'Security Operations', page: 'Cases' });
});

test('a section with no groupLabel falls back to its own section name', () => {
    assert.deepEqual(breadcrumbFromSections('/admin/brand/domain', NAV, VMS), { section: 'Brand', page: 'Domain Intelligence' });
});

test('a dynamic sub-route matches its nav item\'s longest `match` prefix, not a shorter one', () => {
    assert.deepEqual(breadcrumbFromSections('/admin/secops/alerts/123', NAV, VMS), { section: 'Security Operations', page: 'Alerts' });
});

test('VMS pages resolve through vmsSections.ts, under a fixed "VMS" section label', () => {
    assert.deepEqual(breadcrumbFromSections('/admin/vms/assets', NAV, VMS), { section: 'VMS', page: 'Asset Inventory' });
    assert.deepEqual(breadcrumbFromSections('/admin/vms/import', NAV, VMS), { section: 'VMS', page: 'Asset Import' });
});

test('a VMS sub-page not listed by exact href falls back to its section\'s own label', () => {
    assert.deepEqual(breadcrumbFromSections('/admin/vms/assets/some-uuid', NAV, VMS), { section: 'VMS', page: 'Asset Management' });
});

test('/.../dashboard is always "Overview / Dashboard" even with no nav match', () => {
    assert.deepEqual(breadcrumbFromSections('/admin/dashboard', [], []), { section: 'Overview', page: 'Dashboard' });
});

test('nothing matches: humanized last URL segment, with no section', () => {
    assert.deepEqual(breadcrumbFromSections('/admin/some-unlisted-page', NAV, VMS), { section: '', page: 'Some Unlisted Page' });
});

test('humanizeLastSegment title-cases hyphenated words', () => {
    assert.equal(humanizeLastSegment('/admin/threat/live-ioc'), 'Live Ioc');
    assert.equal(humanizeLastSegment('/'), '');
});
