// Unit tests for src/lib/severity.ts, plus a parity check against backend/src/lib/severity.ts.
//
//   npm test
//
// Both files are transpiled with the project's TypeScript (no extra test dependencies).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'severity-test');
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

const frontend = await load(join(root, 'src', 'lib', 'severity.ts'), 'frontend');
const backendSource = join(root, '..', 'backend', 'src', 'lib', 'severity.ts');

test('severityFromLevel: boundary values', () => {
    const cases = [[6, 'low'], [7, 'medium'], [9, 'medium'], [10, 'high'], [12, 'high'], [13, 'critical']];
    for (const [level, expected] of cases) assert.equal(frontend.severityFromLevel(level), expected, `level ${level}`);
});

test('levelTextClass follows severity', () => {
    assert.equal(frontend.levelTextClass(6), 'text-blue');
    assert.equal(frontend.levelTextClass(7), 'text-amber');
    assert.equal(frontend.levelTextClass(12), 'text-amber');
    assert.equal(frontend.levelTextClass(13), 'text-red');
});

test('frontend thresholds match the backend module', { skip: !existsSync(backendSource) && 'backend/src/lib/severity.ts not present' }, async () => {
    const backend = await load(backendSource, 'backend');
    assert.deepEqual(frontend.SEVERITY_MIN_LEVEL, backend.SEVERITY_MIN_LEVEL);
    for (let level = 0; level <= 20; level++) {
        assert.equal(frontend.severityFromLevel(level), backend.severityFromLevel(level), `level ${level}`);
    }
});

test('severityFromScore / verdictFromScore: boundaries 90 / 70 / 30', () => {
    const sev = [[29, 'low'], [30, 'medium'], [69, 'medium'], [70, 'high'], [89, 'high'], [90, 'critical']];
    for (const [score, expected] of sev) assert.equal(frontend.severityFromScore(score), expected, `score ${score}`);
    const ver = [[29, 'clean'], [30, 'suspicious'], [69, 'suspicious'], [70, 'malicious']];
    for (const [score, expected] of ver) assert.equal(frontend.verdictFromScore(score), expected, `score ${score}`);
});

test('severityFromCvss: boundaries 9.0 / 7.0 / 4.0', () => {
    const cases = [[3.9, 'low'], [4, 'medium'], [6.9, 'medium'], [7, 'high'], [8.9, 'high'], [9, 'critical']];
    for (const [score, expected] of cases) assert.equal(frontend.severityFromCvss(score), expected, `cvss ${score}`);
});

test('score and CVSS bands match the backend module', { skip: !existsSync(backendSource) && 'backend/src/lib/severity.ts not present' }, async () => {
    const backend = await load(backendSource, 'backend-scores');
    assert.deepEqual(frontend.SCORE_MIN, backend.SCORE_MIN);
    for (let score = 0; score <= 100; score++) {
        assert.equal(frontend.severityFromScore(score), backend.severityFromScore(score), `score ${score}`);
        assert.equal(frontend.verdictFromScore(score), backend.verdictFromScore(score), `score ${score}`);
    }
    for (let tenths = 0; tenths <= 100; tenths++) {
        assert.equal(frontend.severityFromCvss(tenths / 10), backend.severityFromCvss(tenths / 10), `cvss ${tenths / 10}`);
    }
});
