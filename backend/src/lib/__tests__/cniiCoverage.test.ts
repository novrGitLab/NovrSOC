import { test } from 'node:test';
import assert from 'node:assert/strict';
import { coverageState, tallyCoverage, emptyCoverageTally } from '../cniiCoverage';

const NOW = Date.parse('2026-06-15T00:00:00Z');
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();

test('no active scope is not_connected, regardless of any past collection', () => {
    assert.equal(coverageState({ active_scopes: 0, last_collection: { at: daysAgo(1), status: 'succeeded' } }, NOW), 'not_connected');
});

test('scoped but never collected is configured_not_receiving', () => {
    assert.equal(coverageState({ active_scopes: 1, last_collection: null }, NOW), 'configured_not_receiving');
});

test('the last collection attempt failed: configured_not_receiving, even if an earlier one may have succeeded', () => {
    assert.equal(coverageState({ active_scopes: 1, last_collection: { at: daysAgo(1), status: 'failed' } }, NOW), 'configured_not_receiving');
});

test('within the 8-day threshold is connected_fresh', () => {
    assert.equal(coverageState({ active_scopes: 1, last_collection: { at: daysAgo(7.9), status: 'succeeded' } }, NOW), 'connected_fresh');
});

test('past the 8-day threshold is connected_stale, not silently healthy', () => {
    assert.equal(coverageState({ active_scopes: 1, last_collection: { at: daysAgo(8.1), status: 'succeeded' } }, NOW), 'connected_stale');
});

test('exactly at the threshold is still fresh (strictly greater-than is stale)', () => {
    assert.equal(coverageState({ active_scopes: 1, last_collection: { at: daysAgo(8), status: 'succeeded' } }, NOW), 'connected_fresh');
});

test('an unparseable timestamp is unknown, never fresh — the critical "unknown is not healthy" rule', () => {
    assert.equal(coverageState({ active_scopes: 1, last_collection: { at: 'not-a-date', status: 'succeeded' } }, NOW), 'unknown');
});

test('a malformed scope count is unknown rather than a guess', () => {
    assert.equal(coverageState({ active_scopes: Number.NaN, last_collection: null }, NOW), 'unknown');
    assert.equal(coverageState({ active_scopes: -1, last_collection: null }, NOW), 'unknown');
});

test('tallyCoverage counts each state and states its percentage\'s denominator explicitly', () => {
    const t = tallyCoverage(['connected_fresh', 'connected_fresh', 'connected_stale', 'not_connected', 'unknown']);
    assert.deepEqual(t.by_state, { ...emptyCoverageTally(), connected_fresh: 2, connected_stale: 1, not_connected: 1, unknown: 1 });
    assert.equal(t.total, 5);
    assert.equal(t.connected_pct, 60, '3 of 5 (fresh + stale) are connected');
});

test('tallyCoverage on an empty set: 0 total, a null percentage rather than a fabricated 0%', () => {
    const t = tallyCoverage([]);
    assert.equal(t.total, 0);
    assert.equal(t.connected_pct, null);
});
