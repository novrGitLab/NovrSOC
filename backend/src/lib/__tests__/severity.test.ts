import { test } from 'node:test';
import assert from 'node:assert/strict';
import { severityFromLevel, SEVERITY_MIN_LEVEL, severityFromScore, verdictFromScore, severityFromCvss, SCORE_MIN } from '../severity';
import { severityFromConfidence } from '../opencti';

test('severityFromLevel: boundary values', () => {
    const cases: [number, string][] = [
        [6, 'low'],
        [7, 'medium'],
        [9, 'medium'],
        [10, 'high'],
        [12, 'high'],
        [13, 'critical'],
    ];
    for (const [level, expected] of cases) assert.equal(severityFromLevel(level), expected, `level ${level}`);
});

test('severityFromLevel: extremes', () => {
    assert.equal(severityFromLevel(0), 'low');
    assert.equal(severityFromLevel(15), 'critical');
});

test('SEVERITY_MIN_LEVEL agrees with severityFromLevel', () => {
    assert.equal(severityFromLevel(SEVERITY_MIN_LEVEL.critical), 'critical');
    assert.equal(severityFromLevel(SEVERITY_MIN_LEVEL.critical - 1), 'high');
    assert.equal(severityFromLevel(SEVERITY_MIN_LEVEL.high), 'high');
    assert.equal(severityFromLevel(SEVERITY_MIN_LEVEL.high - 1), 'medium');
    assert.equal(severityFromLevel(SEVERITY_MIN_LEVEL.medium), 'medium');
    assert.equal(severityFromLevel(SEVERITY_MIN_LEVEL.medium - 1), 'low');
});

test('severityFromScore: boundaries 90 / 70 / 30', () => {
    const cases: [number, string][] = [[0, 'low'], [29, 'low'], [30, 'medium'], [69, 'medium'], [70, 'high'], [89, 'high'], [90, 'critical'], [100, 'critical']];
    for (const [score, expected] of cases) assert.equal(severityFromScore(score), expected, `score ${score}`);
    assert.deepEqual(SCORE_MIN, { critical: 90, high: 70, medium: 30, low: 0 });
});

test('verdictFromScore: malicious is exactly high-or-critical, suspicious exactly medium', () => {
    for (let score = 0; score <= 100; score++) {
        const sev = severityFromScore(score);
        const expected = sev === 'critical' || sev === 'high' ? 'malicious' : sev === 'medium' ? 'suspicious' : 'clean';
        assert.equal(verdictFromScore(score), expected, `score ${score}`);
    }
    assert.equal(verdictFromScore(29), 'clean');
    assert.equal(verdictFromScore(30), 'suspicious');
    assert.equal(verdictFromScore(70), 'malicious');
});

test('severityFromCvss: CVSS v3 bands 9.0 / 7.0 / 4.0', () => {
    const cases: [number, string][] = [[3.9, 'low'], [4, 'medium'], [6.9, 'medium'], [7, 'high'], [8.9, 'high'], [9, 'critical'], [10, 'critical']];
    for (const [score, expected] of cases) assert.equal(severityFromCvss(score), expected, `cvss ${score}`);
});

test('OpenCTI confidence goes through the shared score bands', () => {
    for (const c of [0, 29, 30, 69, 70, 89, 90]) assert.equal(severityFromConfidence(c), severityFromScore(c), `confidence ${c}`);
});
