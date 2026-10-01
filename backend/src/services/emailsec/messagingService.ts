// Messaging Suite: provider connections, synchronisation, event ingestion and correlation.
//
// Ingestion enriches each normalised event (URL + attachment intelligence), stores it, records
// its indicators, and correlates it with the other two modules:
//   • a link or sender domain that Phish ID is tracking → attached to that domain's alert;
//   • a source IP that DMARC classified as a suspicious sender → attached to that spoofing alert;
//   • otherwise a detection of medium severity or above opens its own alert.
import type { Db } from './db';
import { f } from './db';
import type { NormalizedEmailEvent, Detection, Provider } from './eventModel';
import { eventSeverity, primaryDetection } from './eventModel';
import { analyzeUrl, normalizeUrl, type UrlAnalysis } from './urlIntel';
import { analyzeAttachment, type AttachmentAnalysis } from './attachmentIntel';
import { correlateOrRaise, recordIndicators, type Indicator, maxSeverity } from './alerts';
import { registrableDomain } from './similarity';
import { microsoft365 } from './connectors/microsoft365';
import { googleWorkspace } from './connectors/googleWorkspace';
import { gateway } from './connectors/gateway';
import { ConnectorAuthError, ConnectorPermissionError } from './connectors/http';
import type { Connector, Connection, ConnectionStatus } from './connectors/types';

export const CONNECTORS: Record<Provider, Connector> = { microsoft365, google_workspace: googleWorkspace, gateway };
export const isProvider = (v: string): v is Provider => v in CONNECTORS;

export async function listConnections(db: Db, orgId: string) {
    const rows = await db.select<Connection>('messaging_connections', { filters: [f.eq('org_id', orgId)] });
    return (Object.keys(CONNECTORS) as Provider[]).map((p) => {
        const c = CONNECTORS[p];
        const row = rows.find((r) => r.provider === p) ?? null;
        const missing = c.missingConfig();
        return {
            provider: p, label: c.label, permissions: c.permissions, missing_config: missing,
            // Missing backend configuration outranks any stored status: nothing can work without it.
            status: (missing.length ? 'requires_configuration' : row?.status ?? 'not_connected') as ConnectionStatus,
            connection: row,
        };
    });
}

export function statusForError(err: unknown): ConnectionStatus {
    return err instanceof ConnectorAuthError ? 'auth_error' : err instanceof ConnectorPermissionError ? 'permission_error' : 'sync_error';
}

/** Create/refresh a connection row and verify it for real; the stored status is the verified one. */
export async function upsertAndVerify(db: Db, orgId: string, provider: Provider, fields: Partial<Connection>, actor: string): Promise<Connection> {
    const now = new Date().toISOString();
    const [row] = await db.upsert<Connection>('messaging_connections', {
        org_id: orgId, provider, status: 'not_connected', connected_by: actor, connected_at: now, updated_at: now, last_error: null, ...fields,
    }, ['org_id', 'provider']);
    return verifyConnection(db, row);
}

export async function verifyConnection(db: Db, conn: Connection): Promise<Connection> {
    const now = new Date().toISOString();
    let patch: Partial<Connection>;
    try {
        const v = await CONNECTORS[conn.provider].verify(conn);
        patch = { status: 'connected', last_error: null, tenant_name: v.tenant_name ?? conn.tenant_name };
    } catch (err) {
        patch = { status: statusForError(err), last_error: (err as Error).message };
    }
    const [updated] = await db.update<Connection>('messaging_connections', [f.eq('id', conn.id)], { ...patch, updated_at: now });
    return updated ?? { ...conn, ...patch };
}

export async function syncConnection(db: Db, conn: Connection): Promise<{ ok: boolean; fetched: number; stored: number; error?: string }> {
    const now = new Date().toISOString();
    try {
        const r = await CONNECTORS[conn.provider].sync(conn);
        const stored = await ingestEvents(db, conn.org_id, r.events);
        const lastEvent = r.events.map((e) => e.received_at).sort().pop() ?? conn.last_event_at;
        await db.update('messaging_connections', [f.eq('id', conn.id)], {
            status: 'connected', sync_cursor: r.cursor, last_sync: now, last_success_sync: now, last_event_at: lastEvent, last_error: null, updated_at: now,
        });
        return { ok: true, fetched: r.fetched, stored };
    } catch (err) {
        await db.update('messaging_connections', [f.eq('id', conn.id)], { status: statusForError(err), last_sync: now, last_error: (err as Error).message, updated_at: now });
        return { ok: false, fetched: 0, stored: 0, error: (err as Error).message };
    }
}

// ── Ingestion ──────────────────────────────────────────────────────────────────────────────

interface EventAnalysis { urls: UrlAnalysis[]; attachments: AttachmentAnalysis[] }

let analyzers = { url: (u: string) => analyzeUrl(u), attachment: analyzeAttachment };
/** Tests only: replace the network-backed analysers. */
export function setAnalyzers(a: Partial<typeof analyzers> | null): void {
    analyzers = { url: (u: string) => analyzeUrl(u), attachment: analyzeAttachment, ...(a ?? {}) };
}

/**
 * Enrich one event. Remote intelligence lookups only run for events the provider already
 * flagged, or whose links point at a domain Phish ID is tracking — looking up every link in
 * every clean message would hammer free intelligence feeds for no benefit.
 */
async function enrich(e: NormalizedEmailEvent, tracked: Set<string>): Promise<{ event: NormalizedEmailEvent; analysis: EventAnalysis | null }> {
    const linkDomains = e.urls.map((u) => (u.domain ? registrableDomain(u.domain) : null)).filter((d): d is string => !!d);
    const deep = e.detection !== 'clean' || linkDomains.some((d) => tracked.has(d));
    if (!deep) return { event: e, analysis: null };
    const urls = await Promise.all(e.urls.slice(0, 10).map((u) => analyzers.url(u.url)));
    const attachments = await Promise.all(e.attachments.slice(0, 5).map((a) => analyzers.attachment(a)));
    const cats = new Set<Detection>(e.categories.filter((c) => c !== 'clean'));
    const ti = [...e.ti_matches];
    for (const u of urls) if (u.verdict === 'malicious') { cats.add('malicious_url'); ti.push(...u.sources.filter((s) => s.malicious).map((s) => `${s.source}: ${u.normalized?.url}`)); }
    for (const a of attachments) {
        if (a.verdict === 'malicious') { cats.add('malware'); ti.push(...a.reputation.filter((r) => r.malicious).map((r) => `${r.source}: ${a.filename ?? a.sha256}`)); }
        else if (a.verdict === 'suspicious') cats.add('suspicious_attachment');
    }
    const categories: Detection[] = cats.size ? [...cats] : ['clean'];
    return {
        event: { ...e, categories, ti_matches: [...new Set(ti)], detection: primaryDetection(categories), severity: eventSeverity(categories, e.action, ti.length) },
        analysis: { urls, attachments },
    };
}

// Shared infrastructure: recorded as indicators, but never used to JOIN observations — two
// unrelated phishing emails that both link to docs.google.com or come from gmail.com are not
// the same incident. Provider MTA IPs are likewise shared, so IPs only correlate through DMARC.
const SHARED_DOMAINS = new Set([
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com', 'aol.com', 'proton.me', 'protonmail.com', 'yandex.com', 'gmx.com', 'zoho.com',
    'google.com', 'microsoft.com', 'office.com', 'office365.com', 'sharepoint.com', 'onmicrosoft.com', 'windows.net', 'azurewebsites.net', 'aka.ms',
    'apple.com', 'facebook.com', 'linkedin.com', 'twitter.com', 'x.com', 'youtube.com', 'instagram.com', 'whatsapp.com',
    'amazonaws.com', 'cloudfront.net', 'googleusercontent.com', 'dropbox.com', 'wetransfer.com', 'docusign.net', 'adobe.com', 'mailchimp.com', 'list-manage.com',
]);
export const isSharedDomain = (d: string) => SHARED_DOMAINS.has(d);
const correlatable = (xs: Indicator[]) => xs.filter((i) => i.type === 'url' || i.type === 'sha256' || (i.type === 'domain' && !isSharedDomain(i.value)));

function indicatorsOf(e: NormalizedEmailEvent): Indicator[] {
    const out: Indicator[] = [];
    if (e.sender_domain) out.push({ type: 'domain', value: registrableDomain(e.sender_domain) });
    if (e.sender) out.push({ type: 'email', value: e.sender });
    if (e.source_ip) out.push({ type: 'ip', value: e.source_ip });
    for (const u of e.urls) {
        const n = normalizeUrl(u.url);
        if (n) { out.push({ type: 'url', value: n.url }); out.push({ type: 'domain', value: n.domain }); }
    }
    for (const a of e.attachments) if (a.sha256) out.push({ type: 'sha256', value: a.sha256.toLowerCase() });
    return out;
}

export async function ingestEvents(db: Db, orgId: string, events: NormalizedEmailEvent[]): Promise<number> {
    if (!events.length) return 0;
    const [phish, suspiciousSources] = await Promise.all([
        db.select<{ id: string; domain: string; status: string }>('phishing_domains', { filters: [f.eq('org_id', orgId)], limit: 1000, select: 'id, domain, status' }),
        db.select<{ domain: string; source_ip: string }>('email_sending_sources', { filters: [f.eq('org_id', orgId), f.eq('classification', 'suspicious')], limit: 1000, select: 'domain, source_ip' }),
    ]);
    const tracked = new Set(phish.filter((p) => !['false_positive', 'resolved'].includes(p.status)).map((p) => p.domain));
    let stored = 0;

    for (const raw of events) {
        const { event: e, analysis } = await enrich(raw, tracked);
        const [row] = await db.upsert<{ id: string }>('email_events', { org_id: orgId, ...e, analysis }, ['org_id', 'provider', 'provider_event_id']);
        stored++;
        const indicators = indicatorsOf(e);
        await recordIndicators(db, orgId, indicators, { module: 'messaging', kind: 'email_event', id: row.id });

        const who = `${e.sender ?? 'unknown sender'} → ${e.recipient ?? 'unknown recipient'}`;
        const delivered = e.action === 'allow' || e.action === 'flag';
        const actionText = e.action_by === 'none' ? (delivered ? 'delivered' : e.action) : `${e.action} by ${e.action_by}`;

        // 1. Links / sender pointing at a Phish ID domain.
        const phishHits = indicators.filter((i) => i.type === 'domain' && tracked.has(i.value)).map((i) => i.value);
        for (const domain of [...new Set(phishHits)]) {
            const pd = phish.find((p) => p.domain === domain)!;
            const alert = await correlateOrRaise(db, orgId, [{ type: 'domain', value: domain }], {
                correlation_key: `phish:${domain}`, severity: delivered ? 'high' : 'medium', module: 'messaging', detection_type: 'brand_impersonation', entity: domain,
                title: `Email referencing look-alike domain ${domain}`, description: `A message (${who}) referenced ${domain}, which Phish ID is tracking as a possible impersonation of your brand.`,
                evidence: { summary: `Email ${who} referenced ${domain} (${actionText}).`, ref: { kind: 'email_event', id: row.id } }, indicators, related_event: row.id,
            });
            await db.insert('phishing_observations', { org_id: orgId, phishing_domain_id: pd.id, kind: 'email', summary: `Seen in email ${who} (${actionText}).`, data: { event_id: row.id } });
            if (alert) await db.update('email_events', [f.eq('id', row.id)], { alert_id: alert.id });
        }

        // 2. Source IP that DMARC reports flagged as spoofing.
        const spoof = e.source_ip ? suspiciousSources.find((s) => s.source_ip === e.source_ip) : undefined;
        if (spoof && !phishHits.length) {
            const alert = await correlateOrRaise(db, orgId, [{ type: 'ip', value: e.source_ip! }], {
                correlation_key: `dmarc-spoof:${spoof.domain}:${spoof.source_ip}`, severity: delivered ? 'high' : 'medium', module: 'messaging', detection_type: 'spoofing', entity: spoof.source_ip,
                title: `Unauthorised source sending as ${spoof.domain}`, description: `A message from ${spoof.source_ip}, already flagged by DMARC reports, reached a mailbox.`,
                evidence: { summary: `Email ${who} from DMARC-flagged source ${spoof.source_ip} (${actionText}).`, ref: { kind: 'email_event', id: row.id } }, indicators, related_event: row.id,
            });
            if (alert) await db.update('email_events', [f.eq('id', row.id)], { alert_id: alert.id });
        }

        // 3. Everything else the provider or enrichment flagged.
        if (!phishHits.length && !spoof && ['medium', 'high', 'critical'].includes(e.severity)) {
            const senderDomain = e.sender_domain ? registrableDomain(e.sender_domain) : null;
            // Freemail senders are grouped by address, not by the provider's domain.
            const entity = senderDomain && !isSharedDomain(senderDomain) ? senderDomain : e.sender ?? e.source_ip ?? row.id;
            const alert = await correlateOrRaise(db, orgId, correlatable(indicators), {
                correlation_key: `msg:${e.detection}:${entity}`, severity: maxSeverity('low', e.severity), module: 'messaging', detection_type: e.detection, entity,
                title: `${e.detection.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())} email from ${entity}`,
                description: `${e.provider === 'gateway' ? 'The NovrSOC mail gateway' : e.provider === 'microsoft365' ? 'Microsoft 365' : 'Google Workspace'} reported a ${e.detection.replace(/_/g, ' ')} message.`,
                evidence: { summary: `${who}${e.subject ? ` — "${e.subject.slice(0, 120)}"` : ''} (${actionText}).`, ref: { kind: 'email_event', id: row.id }, data: { categories: e.categories, ti: e.ti_matches } },
                indicators, related_event: row.id,
            });
            if (alert) await db.update('email_events', [f.eq('id', row.id)], { alert_id: alert.id });
        }
    }
    return stored;
}
