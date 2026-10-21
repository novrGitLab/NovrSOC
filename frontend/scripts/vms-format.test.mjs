// Unit tests for the VMS redesign's pure helpers: CSV export (src/lib/vmsFormat.ts) neutralises
// spreadsheet formulas and quotes every cell; the section map (src/config/vmsSections.ts) gives
// every VMS route its section and page, with Scanner Operations marked for managers.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'vms-format-test');
mkdirSync(cacheDir, { recursive: true });
async function load(rel, name) {
    const src = join(root, 'src', rel);
    const out = ts.transpileModule(readFileSync(src, 'utf8'), { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: src });
    writeFileSync(join(cacheDir, `${name}.mjs`), out.outputText);
    return import(pathToFileURL(join(cacheDir, `${name}.mjs`)).href);
}
const f = await load('lib/vmsFormat.ts', 'vmsFormat');
const s = await load('config/vmsSections.ts', 'vmsSections');

test('CSV: every cell quoted, quotes doubled, formulas neutralised, arrays joined', () => {
    const csv = f.toCsv(
        [{ a: '=HYPERLINK("x")', b: 'say "hi"', c: ['CVE-1', 'CVE-2'], d: null }, { a: '+1', b: '-2', c: '@SUM(A1)', d: 3 }],
        [{ key: 'a', header: 'A' }, { key: 'b', header: 'B' }, { key: 'c', header: 'C' }, { key: 'd', header: 'D' }],
    );
    const lines = csv.split('\r\n');
    assert.equal(lines[0], '"A","B","C","D"');
    assert.equal(lines[1], '"\'=HYPERLINK(""x"")","say ""hi""","CVE-1; CVE-2",""');
    assert.equal(lines[2], '"\'+1","\'-2","\'@SUM(A1)","3"');
});

test('relative time is computed against the given clock', () => {
    const now = Date.parse('2026-10-21T12:00:00Z');
    assert.equal(f.relTime('2026-10-21T11:30:00Z', now), '30 mins ago');
    assert.equal(f.relTime('2026-10-23T12:00:00Z', now), 'in 2 days');
    assert.equal(f.relTime(null, now), '—');
    assert.equal(f.fmtDay('2026-10-05'), '05 Oct');
});

test('VMS sections: eight, each route maps to its section and page; operations is manager-only', () => {
    assert.equal(s.VMS_SECTIONS.length, 8);
    assert.deepEqual(s.VMS_SECTIONS.filter((x) => x.managerOnly).map((x) => x.id), ['operations']);
    const at = (p) => { const r = s.vmsLocate(p); return r && `${r.section.id}:${r.page.href}`; };
    assert.equal(at('/admin/vms'), 'overview:/admin/vms');
    assert.equal(at('/admin/vms/assets/1234'), 'assets:/admin/vms/assets');
    assert.equal(at('/admin/vms/scans/history'), 'detection:/admin/vms/scans/history');
    assert.equal(at('/admin/vms/scans'), 'detection:/admin/vms/scans');
    assert.equal(at('/admin/vms/remediation/ai'), 'remediation:/admin/vms/remediation/ai');
    assert.equal(at('/admin/vms/operations/workers'), 'operations:/admin/vms/operations/workers');
    assert.equal(at('/admin/secops'), null);
});
