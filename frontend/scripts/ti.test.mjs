// Unit tests for the Threat Intelligence pages (phase P25): the Nigeria map's state outlines match
// the states the backend can name (services/tiGeo.ts), so no hosted indicator with a known state is
// left off the map and none is placed on a state that does not exist; freshness wording; markings.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'ti-test');
mkdirSync(cacheDir, { recursive: true });
async function load(rel, name) {
    const src = join(root, 'src', ...rel.split('/'));
    const out = ts.transpileModule(readFileSync(src, 'utf8'), { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: src });
    writeFileSync(join(cacheDir, `${name}.mjs`), out.outputText);
    return import(pathToFileURL(join(cacheDir, `${name}.mjs`)).href);
}
const paths = await load('components/features/ti/nigeriaPaths.ts', 'nigeriaPaths');
const ti = await load('lib/ti.ts', 'ti');

test('map: 37 state outlines, one per state, named as the backend names them', () => {
    const names = paths.NIGERIA_STATE_PATHS.map((p) => (p.name === 'Nassarawa' ? 'Nasarawa' : p.name));
    assert.equal(names.length, 37);
    assert.equal(new Set(names).size, 37);
    const backend = readFileSync(join(root, '..', 'backend', 'src', 'services', 'tiGeo.ts'), 'utf8');
    const list = /NIGERIA_STATES = \[([\s\S]*?)\] as const/.exec(backend)[1].match(/'([^']+)'/g).map((s) => s.slice(1, -1));
    assert.deepEqual([...names].sort(), [...list].sort());
    for (const p of paths.NIGERIA_STATE_PATHS) assert.match(p.d, /^M[\d.\s,lLmMzZcChHvV-]+$/);
    assert.equal(paths.NIGERIA_VIEWBOX, '0 0 1000 812');
});

test('freshness wording and markings', () => {
    const now = Date.parse('2026-10-30T12:00:00Z');
    assert.equal(ti.ago(null, now), 'never');
    assert.equal(ti.ago('2026-10-30T11:59:30Z', now), 'just now');
    assert.equal(ti.ago('2026-10-30T11:00:00Z', now), '60 min ago');
    assert.equal(ti.ago('2026-10-30T06:00:00Z', now), '6 h ago');
    assert.equal(ti.ago('2026-10-27T12:00:00Z', now), '3 d ago');
    assert.deepEqual(Object.keys(ti.TLP_LABEL), ['clear', 'green', 'amber', 'amber+strict', 'red']);
    assert.equal(ti.FEED_NAME.opencti, 'Legacy Threat Feed (retired)');
});
