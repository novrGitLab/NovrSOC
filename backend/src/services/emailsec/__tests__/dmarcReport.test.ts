import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'zlib';
import { SAMPLE_REPORT, REPORT_BEGIN, zipOf } from './fixtures';
import { parseDmarcReport, unpackReport, parseXml } from '../dmarcReport';

test('parses an aggregate report into normalised records', () => {
    const r = parseDmarcReport(SAMPLE_REPORT);
    assert.equal(r.reporter, 'google.com');
    assert.equal(r.report_id, '1234567890');
    assert.equal(r.domain, 'example.com');
    assert.equal(r.date_begin, new Date(REPORT_BEGIN * 1000).toISOString());
    assert.equal(r.policy_published.p, 'none');
    assert.equal(r.records.length, 2);
    assert.equal(r.message_count, 134);
    assert.equal(r.pass_count, 120);
    const bad = r.records[1];
    assert.equal(bad.source_ip, '203.0.113.9');
    assert.equal(bad.dmarc_pass, false);
    assert.equal(bad.spf_domain, 'bad.example');
    assert.equal(bad.envelope_from, 'bad.example');
    assert.equal(r.records[0].dkim_domain, 'example.com');
});

test('unpacks gzip and zip attachments', () => {
    assert.equal(parseDmarcReport(unpackReport(gzipSync(SAMPLE_REPORT))).records.length, 2);
    assert.equal(parseDmarcReport(unpackReport(zipOf('google.com!example.com!1!2.xml', SAMPLE_REPORT))).records.length, 2);
    assert.equal(parseDmarcReport(unpackReport(Buffer.from(SAMPLE_REPORT))).records.length, 2);
});

test('namespaced (DMARCbis) reports parse', () => {
    const ns = SAMPLE_REPORT.replace('<feedback>', '<dmarc:feedback xmlns:dmarc="urn:ietf:params:xml:ns:dmarc-2.0">').replace('</feedback>', '</dmarc:feedback>');
    assert.equal(parseDmarcReport(ns).records.length, 2);
});

test('refuses DOCTYPE / entity declarations (XXE, billion laughs)', () => {
    assert.throws(() => parseDmarcReport(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>${SAMPLE_REPORT.replace(/^<\?xml[^>]*\?>/, '')}`), /DOCTYPE/);
});

test('rejects non-reports with a readable reason', () => {
    assert.throws(() => unpackReport(Buffer.from('hello')), /Not a DMARC report/);
    assert.throws(() => parseDmarcReport('<foo></foo>'), /no <feedback>/);
    assert.throws(() => parseXml('<a><b></a>'), /Malformed/);
    assert.throws(() => parseDmarcReport('<feedback><report_metadata></report_metadata></feedback>'), /missing org_name/);
});

test('decodes XML entities in text', () => {
    const x = parseXml('<a>Tom &amp; Jerry &#65;</a>');
    assert.equal(x.children[0].text, 'Tom & Jerry A');
});
