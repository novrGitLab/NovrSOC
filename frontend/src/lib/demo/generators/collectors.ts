import type { DemoOrgId } from '../types';
import { seeded } from '../rng';
import { DEMO_SCENARIOS } from '../scenario';
import { DEMO_ORGS } from '../orgs';

const ago = (mins: number) => new Date(Date.now() - mins * 60_000).toISOString();

export function demoCollectorId(org: DemoOrgId) { return `demo-${org}-collector-1`; }

export function demoCollectors(org: DemoOrgId) {
    return seeded(`collector:${org}`, (r) => ([{
        id: demoCollectorId(org), name: `${DEMO_ORGS[org].name.toLowerCase()}-site-1-demo`, status: 'connected' as const, effective_status: 'connected' as const,
        token_prefix: 'demo1234', vector_version: '0.60.0', last_heartbeat_at: ago(1), last_ip: '198.18.1.1',
        last_events_received: r.int(400, 900), last_events_forwarded: r.int(390, 890), last_delivery_failures: r.int(0, 2), last_buffer_pct: r.int(2, 18),
        config_version: 1, created_by: 'SOC Manager (Sample)', created_at: ago(60 * 24 * 7), enrollment_expires_at: null,
    }]));
}

export function demoCollectorDetail(org: DemoOrgId) {
    const s = DEMO_SCENARIOS[org];
    const heartbeats = seeded(`collector-hb:${org}`, (r) => Array.from({ length: 24 }, (_, i) => ({
        at: ago((24 - i) * 10), events_received: r.int(10, 40), events_forwarded: r.int(10, 40), delivery_failures: r.int(0, 1), buffer_pct: r.int(2, 20),
    })));
    return {
        sources: [
            { source_key: 'syslog_tcp', kind: 'syslog_tcp', label: 'Core firewall (demo)', events_total: 1842, last_event_at: ago(1) },
            { source_key: 'syslog_udp', kind: 'syslog_udp', label: 'Perimeter router (demo)', events_total: 963, last_event_at: ago(4) },
            { source_key: 'syslog_tls', kind: 'syslog_tls', label: s.assetName, events_total: 214, last_event_at: ago(60) },
        ],
        heartbeats,
    };
}

/** The "network five-tuple events" domain — real collector_log_events shape, demo-labelled. */
export function demoCollectorEvents(org: DemoOrgId) {
    const s = DEMO_SCENARIOS[org];
    return seeded(`collector-events:${org}`, (r) => ({
        events: [
            {
                id: `demo-${org}-event-0`, source_key: 'syslog_tcp', host: s.srcIp, received_at: ago(2), event_time: ago(2),
                message: `[SAMPLE] <134>firewall: action=block proto=${s.protocol} src=${s.srcIp}:${s.srcPort} dst=${s.dstIp}:${s.dstPort}`, truncated: false,
            },
            ...Array.from({ length: 8 }, (_, i) => {
                const srcIp = `198.51.100.${r.int(10, 250)}`;
                const dstIp = `198.18.${r.int(1, 15)}.${r.int(1, 254)}`;
                const srcPort = r.int(1024, 65000);
                const dstPort = r.pick([22, 443, 3389, 8080, 445]);
                const proto = r.pick(['TCP', 'UDP']);
                return {
                    id: `demo-${org}-event-${i + 1}`, source_key: r.pick(['syslog_tcp', 'syslog_udp']), host: srcIp, received_at: ago(5 + i * 7), event_time: ago(5 + i * 7),
                    message: `[SAMPLE] <134>firewall: action=${r.pick(['pass', 'block', 'reject'])} proto=${proto} src=${srcIp}:${srcPort} dst=${dstIp}:${dstPort}`, truncated: false,
                };
            }),
        ],
    }));
}
