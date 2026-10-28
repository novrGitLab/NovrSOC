import type { DemoOrgId } from '../types';
import { seeded } from '../rng';
import { DEMO_SCENARIOS } from '../scenario';

const ago = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
const agoH = (hours: number) => new Date(Date.now() - hours * 3_600_000).toISOString();

export function demoTiOverview(org: DemoOrgId) {
    return seeded(`ti-overview:${org}`, (r) => ({
        indicators: { active: r.int(1800, 2600), new_last_24h: r.int(20, 80), by_type: { ip: r.int(600, 900), domain: r.int(300, 500), url: r.int(200, 400), hash: r.int(150, 300), cve: r.int(100, 250) } },
        matches: { new: r.int(1, 4), total: r.int(8, 20) },
        feeds: [
            { id: 'cisa_kev', name: 'CISA Known Exploited Vulnerabilities', configured: true, enabled: true, failing: false, stale: false, last_success_at: agoH(2) },
            { id: 'abusech', name: 'abuse.ch', configured: true, enabled: true, failing: false, stale: false, last_success_at: agoH(1) },
            { id: 'ngcert', name: 'ngCERT advisories', configured: true, enabled: true, failing: false, stale: false, last_success_at: agoH(6) },
            { id: 'circl', name: 'CIRCL pulse', configured: true, enabled: true, failing: false, stale: false, last_success_at: agoH(3) },
        ],
    }));
}

const NIGERIA_STATES_WITH_ACTIVITY = ['Lagos', 'Rivers', 'Kano', 'Federal Capital Territory', 'Oyo', 'Kaduna'];
export function demoTiMap(org: DemoOrgId) {
    const s = DEMO_SCENARIOS[org];
    return seeded(`ti-map:${org}`, (r) => ({
        states: NIGERIA_STATES_WITH_ACTIVITY.map((state, i) => ({ state, hosted: i === 0 ? r.int(8, 14) : r.int(0, 6), exposure: i === 0 ? r.int(3, 6) : r.int(0, 3) })),
        country_level: { targeting: r.int(2, 6), hosted_state_unknown: r.int(1, 5), exposure_state_unknown: r.int(0, 2) },
        targeting: [{ id: `demo-${org}-report-1`, title: `[DEMO] Source report: campaign targeting Nigerian ${s.title.includes('Firewall') ? 'telecommunications' : 'organisations'}`, kind: 'source_report' as const, source: 'Demo Threat Report', tlp: 'amber', actors: ['Demo Threat Actor Group'], published_at: ago(2) }],
        hosted: [], exposure: [], sectors: ['finance', 'ict', 'power'],
    }));
}

export function demoTiMatches(org: DemoOrgId, status?: string) {
    const s = DEMO_SCENARIOS[org];
    const all = seeded(`ti-matches:${org}`, (r) => ([
        { id: `demo-${org}-match-1`, indicator_id: `demo-${org}-indicator-1`, entity_type: 'alert', matched_field: 'source_ip', matched_value: s.indicatorValue, first_matched_at: ago(1), status: 'new',
            ti_indicators: { value: s.indicatorValue, malware_families: ['Demo-Stealer'], threat_types: ['credential-theft'], source_count: 3 } },
        ...Array.from({ length: 5 }, (_, i) => ({
            id: `demo-${org}-match-${i + 2}`, indicator_id: `demo-${org}-indicator-${i + 2}`, entity_type: r.pick(['finding', 'asset', 'case']), matched_field: r.pick(['source_ip', 'destination_ip', 'domain']),
            matched_value: `198.51.100.${r.int(10, 250)}`, first_matched_at: ago(r.int(1, 20)), status: r.pick(['new', 'reviewed', 'dismissed', 'promoted']),
            ti_indicators: { value: `198.51.100.${r.int(10, 250)}`, malware_families: [], threat_types: [r.pick(['scanning', 'phishing', 'c2'])], source_count: r.int(1, 5) },
        })),
    ]));
    return { matches: status && status !== 'all' ? all.filter((m) => m.status === status) : all };
}

export function demoTiVulnerabilities(org: DemoOrgId) {
    const s = DEMO_SCENARIOS[org];
    return seeded(`ti-vulns:${org}`, (r) => ({
        total: 4,
        vulnerabilities: [
            { cve: s.cveId, kev: { vendor: 'Demo Vendor', product: 'Demo Gateway', name: '[DEMO] Remote code execution' }, added: ago(3), your_open_findings: 1 },
            ...Array.from({ length: 3 }, () => ({ cve: `CVE-202${r.int(2, 5)}-${r.int(1000, 9999)}`, kev: { vendor: 'Demo Vendor', product: r.pick(['Demo Router OS', 'Demo VPN Gateway', 'Demo Mail Server']), name: '[DEMO] known exploited vulnerability' }, added: ago(r.int(4, 30)), your_open_findings: 0 })),
        ],
    }));
}

export function demoTiRelevant(org: DemoOrgId) {
    const s = DEMO_SCENARIOS[org];
    return seeded(`ti-relevant:${org}`, (r) => {
        const items = [
            { match_id: `demo-${org}-match-1`, indicator_id: `demo-${org}-indicator-1`, indicator_type: 'ip', indicator_value: s.indicatorValue, tier: 'critical' as const, reasons: ['[DEMO] Matched against a recent authentication event on a customer-facing asset'], last_matched_at: ago(1) },
            ...Array.from({ length: 4 }, (_, i) => ({ match_id: `demo-${org}-match-${i + 2}`, indicator_id: `demo-${org}-indicator-${i + 2}`, indicator_type: r.pick(['ip', 'domain']), indicator_value: `198.51.100.${r.int(10, 250)}`, tier: r.pick(['high', 'medium', 'low'] as const), reasons: ['[DEMO] Seen in organisation records, no further corroboration'], last_matched_at: ago(r.int(2, 15)) })),
        ];
        const by_tier = { critical: items.filter((i) => i.tier === 'critical').length, high: items.filter((i) => i.tier === 'high').length, medium: items.filter((i) => i.tier === 'medium').length, low: items.filter((i) => i.tier === 'low').length };
        return { generated_at: new Date().toISOString(), items, by_tier };
    });
}
