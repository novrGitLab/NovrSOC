import { test } from 'node:test';
import assert from 'node:assert/strict';
import { severityFromLevel, SEVERITY_MIN_LEVEL } from '../severity';

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
