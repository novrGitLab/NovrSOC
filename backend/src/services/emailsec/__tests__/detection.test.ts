import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessPhishingRisk } from '../phishRisk';
import { resemblance } from '../similarity';
import { eventSeverity, fromGateway, fromMicrosoftAlert, fromGmailActivity, primaryDetection } from '../eventModel';
import { classifySource, providerForPtr } from '../dmarcService';
import type { WebsiteEvidence } from '../siteInspect';

const site = (over: Partial<WebsiteEvidence> = {}): WebsiteEvidence => ({
    inspected_at: '', url: 'https://x/', reachable: true, error: null, blocked: false, final_url: 'https://x/', status: 200, redirects: [], cross_domain_redirect: false,
    tls: null, title: null, meta: {}, forms: [], login_indicators: [], brand_mentions: [], external_scripts: 0, iframes: 0, content_type: 'text/html', truncated: false, ...over,
});

// ── Phish ID risk ──

test('similarity alone is never more than low risk', () => {
    const r = assessPhishingRisk({ resemblance: resemblance('company-login.com', 'company.com'), domain_age_days: 900, resolves: true, website: site(), ti_hits: [], brand_terms: ['company'] });
    assert.equal(r.risk, 'low');
    assert.ok(r.signals.length > 0 && r.signals.every((s) => s.label && s.points > 0));
});

test('look-alike + credential capture + brand + new registration is critical, with reasons', () => {
    const r = assessPhishingRisk({
        resemblance: resemblance('company-login.com', 'company.com'), domain_age_days: 3, resolves: true,
        website: site({ forms: [{ action: 'https://evil/p', method: 'post', external: true, password_fields: 1, email_fields: 1, hidden_fields: 0 }], login_indicators: ['password field'], brand_mentions: ['company'] }),
        ti_hits: [], brand_terms: ['company'],
    });
    assert.equal(r.risk, 'critical');
    const ids = r.signals.map((s) => s.id);
    for (const id of ['brand_keyword', 'young_domain', 'login_form', 'brand_on_page', 'external_form', 'credential_harvest']) assert.ok(ids.includes(id), id);
    assert.match(r.summary, /Critical risk/);
});

test('a threat-intelligence listing is at least high', () => {
    const r = assessPhishingRisk({ resemblance: null, domain_age_days: null, resolves: true, website: null, ti_hits: ['OpenPhish: listed'], brand_terms: [] });
    assert.equal(r.risk, 'high');
});

test('no signals is informational', () => {
    assert.equal(assessPhishingRisk({ resemblance: null, domain_age_days: 2000, resolves: false, website: null, ti_hits: [], brand_terms: [] }).risk, 'informational');
});

// ── Event severity + normalisation ──

test('severity: delivered threats rank higher than stopped ones; TI bumps', () => {
    assert.equal(eventSeverity(['phishing'], 'quarantine', 0), 'high');
    assert.equal(eventSeverity(['phishing'], 'allow', 0), 'critical');
    assert.equal(eventSeverity(['spam'], 'allow', 0), 'informational');
    assert.equal(eventSeverity(['auth_failure'], 'flag', 0), 'medium');
    assert.equal(eventSeverity(['suspicious_attachment'], 'block', 1), 'high');
    assert.equal(eventSeverity(['clean'], 'allow', 0), 'informational');
    assert.equal(primaryDetection(['spam', 'malware']), 'malware');
});

test('gateway verdicts are recorded as flagged, never as blocked, unless the gateway says so', () => {
    const e = fromGateway({ message_id: '<a@x>', org_id: 'o', from_address: 'Bad <bad@evil.example>', to_address: 'user@company.com', verdict: 'phishing', dmarc_result: 'fail', received_at: '2026-09-28T10:00:00Z' });
    assert.equal(e.detection, 'phishing');
    assert.ok(e.categories.includes('auth_failure'));
    assert.equal(e.action, 'flag');
    assert.equal(e.action_by, 'none');
    assert.equal(e.sender_domain, 'evil.example');
    const blocked = fromGateway({ message_id: '<b@x>', org_id: 'o', from_address: 'a@b.c', to_address: 'u@c.com', verdict: 'malware', action: 'reject' });
    assert.equal(blocked.action, 'block');
    assert.equal(blocked.action_by, 'NovrSOC mail gateway');
    assert.equal(fromGateway({ message_id: '<c@x>', org_id: 'o', from_address: 'a@b.c', to_address: 'u@c.com', verdict: 'clean' }).detection, 'clean');
});

test('Microsoft 365 Defender alert evidence normalises per message', () => {
    const events = fromMicrosoftAlert({
        id: 'da1', category: 'InitialAccess', createdDateTime: '2026-09-28T09:00:00Z', tenantId: 't1',
        evidence: [
            { '@odata.type': '#microsoft.graph.security.analyzedMessageEvidence', networkMessageId: 'n1', internetMessageId: '<m1@evil>', senderIp: '203.0.113.5',
                p1Sender: { emailAddress: 'ceo@evil.example' }, recipientEmailAddress: 'User@Company.com', subject: 'Invoice', receivedDateTime: '2026-09-28T08:59:00Z',
                threats: ['Phish'], deliveryAction: 'Blocked', deliveryLocation: 'Quarantine', urls: ['https://company-login.example/x'],
                authenticationDetails: { dmarc: 'Fail', senderPolicyFramework: 'Fail', dkim: 'None' } },
            { '@odata.type': '#microsoft.graph.security.userEvidence' },
        ],
    });
    assert.equal(events.length, 1);
    const e = events[0];
    assert.equal(e.provider_event_id, 'da1:n1');
    assert.equal(e.detection, 'phishing');
    assert.equal(e.action, 'quarantine');
    assert.match(e.action_by, /Microsoft 365/);
    assert.equal(e.recipient, 'user@company.com');
    assert.equal(e.urls[0].domain, 'company-login.example');
    assert.equal(e.dmarc, 'fail');
});

test('Google Workspace Gmail log event normalises', () => {
    const e = fromGmailActivity({
        id: { time: '2026-09-28T07:00:00Z', uniqueQualifier: 'g1', customerId: 'C01' },
        events: [{ name: 'delivery', parameters: [{ name: 'message_info', messageValue: { parameter: [
            { name: 'rfc2822_message_id', value: '<g@evil>' }, { name: 'subject', value: 'Reset' },
            { name: 'source', messageValue: { parameter: [{ name: 'from_header_address', value: 'x@evil.example' }] } },
            { name: 'destination', messageValue: { parameter: [{ name: 'address', value: 'u@company.com' }] } },
            { name: 'spam_info', messageValue: { parameter: [{ name: 'classification', value: 'PHISHY' }, { name: 'disposition', value: 'QUARANTINE' }] } },
            { name: 'connection_info', messageValue: { parameter: [{ name: 'client_ip', value: '198.51.100.7' }, { name: 'dmarc_pass', boolValue: false }, { name: 'spf_pass', boolValue: false }] } },
            { name: 'link_domain', multiValue: ['company-login.example'] },
        ] } }] }],
    });
    assert.ok(e);
    assert.equal(e!.detection, 'phishing');
    assert.equal(e!.action, 'quarantine');
    assert.equal(e!.source_ip, '198.51.100.7');
    assert.equal(e!.dmarc, 'fail');
    assert.equal(e!.urls[0].domain, 'company-login.example');
});

// ── DMARC source classification ──

test('sending sources: known / suspicious / unknown with reasons', () => {
    assert.equal(classifySource({ message_count: 100, dmarc_pass: 99, provider: 'Google' }).classification, 'known');
    const sus = classifySource({ message_count: 20, dmarc_pass: 0, provider: null });
    assert.equal(sus.classification, 'suspicious');
    assert.match(sus.reason, /All 20 messages failed/);
    // Failing but from a real provider (forwarding) — not called malicious.
    assert.equal(classifySource({ message_count: 50, dmarc_pass: 0, provider: 'Microsoft 365' }).classification, 'unknown');
    // Too few messages to judge.
    assert.equal(classifySource({ message_count: 2, dmarc_pass: 0, provider: null }).classification, 'unknown');
    assert.equal(providerForPtr('mail-sor-f41.google.com.'), 'Google');
    assert.equal(providerForPtr('a1-2.smtp-out.amazonses.com'), 'Amazon SES');
    assert.equal(providerForPtr('host.random.example'), null);
});

test('Microsoft 365 documented delivery values map to the provider\'s action', () => {
    const mk = (deliveryAction: string, deliveryLocation: string) => fromMicrosoftAlert({ id: 'x', category: 'Phish', evidence: [{ '@odata.type': '#microsoft.graph.security.analyzedMessageEvidence', networkMessageId: 'n', threats: ['Phish'], deliveryAction, deliveryLocation }] })[0];
    assert.equal(mk('blocked', 'failed').action, 'block');
    assert.equal(mk('delivered', 'dropped').action, 'block');
    assert.equal(mk('delivered', 'quarantine').action, 'quarantine');
    const junk = mk('junked', 'junkFolder');
    assert.equal(junk.action, 'flag');
    assert.match(junk.action_by, /Junk/);
    assert.equal(mk('delivered', 'inbox').action_by, 'none');
});
