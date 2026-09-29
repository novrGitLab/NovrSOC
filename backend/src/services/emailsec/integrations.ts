// External SOC integrations for Email Security:
//   • OpenCTI — confirmed Phish ID findings become observables + indicators (GraphQL API).
//   • Wazuh indexer (OpenSearch) — "related SOC alerts" for an investigation: endpoint/network
//     alerts that mention the same IPs or domains.
//   • Status of every external dependency, for the integration health panel.
//
// Nothing here reports success it didn't get: an unconfigured integration says so, a failed
// call returns its error.
import { search } from '../../lib/wazuh-indexer';
import { emailsecConfig } from './config';
import { isConfigured as vtConfigured } from '../virustotal';
import { sandbox } from './attachmentIntel';
import { m365Missing } from './connectors/microsoft365';
import { serviceAccount } from './connectors/googleWorkspace';

// ── OpenCTI ────────────────────────────────────────────────────────────────────────────────

export const openctiConfigured = () => !!(process.env.OPENCTI_URL && process.env.OPENCTI_TOKEN);

async function openctiQuery<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    const r = await fetch(`${process.env.OPENCTI_URL!.replace(/\/$/, '')}/graphql`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.OPENCTI_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, variables }),
        signal: AbortSignal.timeout(15_000),
    });
    const d = (await r.json().catch(() => null)) as { data?: T; errors?: { message: string }[] } | null;
    if (!r.ok || !d || d.errors?.length) throw new Error(d?.errors?.[0]?.message ?? `OpenCTI answered HTTP ${r.status}`);
    return d.data as T;
}

export async function openctiHealth(): Promise<{ ok: boolean; detail: string }> {
    if (!openctiConfigured()) return { ok: false, detail: 'Not configured (OPENCTI_URL, OPENCTI_TOKEN)' };
    try {
        const d = await openctiQuery<{ about?: { version?: string } }>('query { about { version } }', {});
        return { ok: true, detail: `OpenCTI ${d.about?.version ?? ''}`.trim() };
    } catch (err) {
        return { ok: false, detail: (err as Error).message };
    }
}

/**
 * Push a domain as a Domain-Name observable with an indicator. Refused below the configured
 * confidence threshold, so low-confidence discoveries never become threat intelligence.
 */
export async function pushDomainToOpenCti(domain: string, confidence: number, description: string, labels: string[]): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
    if (!openctiConfigured()) return { ok: false, error: 'OpenCTI is not configured (OPENCTI_URL, OPENCTI_TOKEN).' };
    const min = emailsecConfig.openctiMinConfidence();
    if (confidence < min) return { ok: false, error: `Confidence ${confidence} is below the OpenCTI threshold (${min}); only confirmed findings are shared.` };
    try {
        const d = await openctiQuery<{ stixCyberObservableAdd?: { id: string } }>(
            `mutation Add($value: String!, $desc: String, $score: Int, $labels: [String]) {
                stixCyberObservableAdd(type: "Domain-Name", DomainName: { value: $value }, x_opencti_description: $desc, x_opencti_score: $score, createIndicator: true, objectLabel: $labels) { id }
            }`,
            { value: domain, desc: description.slice(0, 2000), score: confidence, labels },
        );
        const id = d.stixCyberObservableAdd?.id;
        return id ? { ok: true, id } : { ok: false, error: 'OpenCTI returned no id.' };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

// ── Wazuh / OpenSearch ─────────────────────────────────────────────────────────────────────

export interface RelatedSocAlert { id: string; timestamp: string; rule: string; level: number; agent: string | null; match: string }

export async function relatedSocAlerts(values: string[], days = 30): Promise<{ available: boolean; alerts: RelatedSocAlert[]; error?: string }> {
    const terms = [...new Set(values.filter(Boolean))].slice(0, 20);
    if (!terms.length) return { available: true, alerts: [] };
    if (!process.env.WAZUH_INDEXER_HOST) return { available: false, alerts: [], error: 'Wazuh indexer not configured (WAZUH_INDEXER_HOST)' };
    try {
        const r = await search<{ hits?: { hits?: { _id: string; _source: { timestamp?: string; rule?: { description?: string; level?: number }; agent?: { name?: string }; data?: Record<string, unknown> } }[] } }>('wazuh-alerts-4.x-*', {
            size: 25,
            sort: [{ timestamp: 'desc' }],
            query: {
                bool: {
                    filter: [{ range: { timestamp: { gte: `now-${days}d` } } }],
                    should: [
                        { terms: { 'data.srcip': terms } }, { terms: { 'data.dstip': terms } },
                        ...terms.map((t) => ({ multi_match: { query: t, type: 'phrase', fields: ['data.url', 'data.hostname', 'data.query', 'full_log'] } })),
                    ],
                    minimum_should_match: 1,
                },
            },
        });
        return {
            available: true,
            alerts: (r?.hits?.hits ?? []).map((h) => {
                const blob = JSON.stringify(h._source).toLowerCase();
                return {
                    id: h._id, timestamp: h._source.timestamp ?? '', rule: h._source.rule?.description ?? 'Wazuh alert', level: h._source.rule?.level ?? 0,
                    agent: h._source.agent?.name ?? null, match: terms.find((t) => blob.includes(t.toLowerCase())) ?? '',
                };
            }),
        };
    } catch (err) {
        return { available: false, alerts: [], error: (err as Error).message };
    }
}

// ── Integration health ─────────────────────────────────────────────────────────────────────

export interface IntegrationStatus { id: string; label: string; state: 'configured' | 'not_configured'; detail: string; used_by: string[] }

export function integrationStatuses(): IntegrationStatus[] {
    const cfg = (id: string, label: string, ok: boolean, detail: string, used_by: string[]): IntegrationStatus => ({ id, label, state: ok ? 'configured' : 'not_configured', detail, used_by });
    const m365 = m365Missing();
    return [
        cfg('dns', 'DNS resolution', true, 'System resolver', ['DMARC', 'Phish ID']),
        cfg('rdap', 'RDAP / WHOIS', true, 'rdap.org (public)', ['Phish ID', 'URL intelligence']),
        cfg('crtsh', 'Certificate Transparency', true, 'crt.sh (public)', ['Phish ID']),
        cfg('openphish', 'OpenPhish / PhishTank', true, 'Public feeds', ['URL intelligence', 'Phish ID']),
        cfg('urlhaus', 'URLhaus', !!process.env.URLHAUS_API_KEY, process.env.URLHAUS_API_KEY ? 'API key set' : 'URLHAUS_API_KEY not set', ['URL intelligence']),
        cfg('virustotal', 'VirusTotal', vtConfigured(), vtConfigured() ? 'API key set' : 'VIRUSTOTAL_API_KEY not set', ['URL intelligence', 'Attachments']),
        cfg('sandbox', 'Attachment sandbox', sandbox().configured(), sandbox().configured() ? `CAPE at ${process.env.SANDBOX_URL}` : 'Sandbox unavailable — SANDBOX_URL not set', ['Attachments']),
        cfg('dmarc_inbound', 'DMARC report inbox (Mailgun)', !!process.env.MAILGUN_WEBHOOK_SIGNING_KEY, process.env.MAILGUN_WEBHOOK_SIGNING_KEY ? 'Signed webhook enabled' : 'MAILGUN_WEBHOOK_SIGNING_KEY not set — reports can still be uploaded by hand', ['DMARC']),
        cfg('microsoft365', 'Microsoft 365 app registration', m365.length === 0, m365.length ? `Missing ${m365.join(', ')}` : 'App credentials set', ['Messaging']),
        cfg('google_workspace', 'Google Workspace service account', !!serviceAccount(), serviceAccount() ? 'Service-account key set' : 'GOOGLE_WORKSPACE_SA_KEY not set', ['Messaging']),
        cfg('gateway', 'NovrSOC mail gateway', !!process.env.EMAIL_PROXY_TOKEN, process.env.EMAIL_PROXY_TOKEN ? 'Verdict endpoint enabled' : 'EMAIL_PROXY_TOKEN not set', ['Messaging']),
        cfg('opencti', 'OpenCTI', openctiConfigured(), openctiConfigured() ? `${process.env.OPENCTI_URL}` : 'OPENCTI_URL / OPENCTI_TOKEN not set', ['Phish ID']),
        cfg('wazuh', 'Wazuh indexer', !!process.env.WAZUH_INDEXER_HOST, process.env.WAZUH_INDEXER_HOST ? 'Configured' : 'WAZUH_INDEXER_HOST not set', ['Investigations']),
    ];
}
