// Email Security background work — same setInterval pattern as the other jobs in this folder
// (no second scheduler). Each task has its own interval (services/emailsec/config.ts) and a
// running flag so a slow run is never overlapped by the next tick.
//
//   DMARC      DNS re-inspection of every protected domain (default every 6 h).
//              Report processing happens on arrival (upload / Mailgun), not on a timer.
//   Phish ID   Look-alike discovery per brand profile (default daily); enrichment + safe website
//              inspection of domains not refreshed in 24 h, a few at a time (default hourly).
//   Messaging  Sync every connected provider (default every 10 min).
//
// If the Email Security tables don't exist yet, each task logs that once and idles.
import { getDb, f, SchemaMissingError } from '../services/emailsec/db';
import { emailsecConfig } from '../services/emailsec/config';
import { runDomainCheck, type EmailDomain } from '../services/emailsec/dmarcService';
import { discover, enrichDomain, type PhishingDomain } from '../services/emailsec/phishService';
import { syncConnection } from '../services/emailsec/messagingService';
import type { Connection } from '../services/emailsec/connectors/types';

const running = new Set<string>();
const warned = new Set<string>();

async function task(name: string, fn: () => Promise<void>): Promise<void> {
    if (running.has(name)) return;
    running.add(name);
    try {
        await fn();
        warned.delete(name);
    } catch (err) {
        if (err instanceof SchemaMissingError) {
            if (!warned.has(name)) console.warn(`[emailsec] ${name}: ${err.message}`);
            warned.add(name);
        } else {
            console.error(`[emailsec] ${name} failed:`, err instanceof Error ? err.message : err);
        }
    } finally {
        running.delete(name);
    }
}

export async function runDnsChecks(): Promise<void> {
    const db = getDb();
    if (!db) return;
    const stale = new Date(Date.now() - emailsecConfig.dnsCheckMinutes() * 60_000).toISOString();
    const domains = await db.select<EmailDomain>('email_domains', { limit: 1000 });
    for (const d of domains.filter((x) => !x.last_checked || x.last_checked < stale)) await runDomainCheck(db, d);
}

export async function runDiscovery(): Promise<void> {
    const db = getDb();
    if (!db) return;
    const stale = new Date(Date.now() - emailsecConfig.discoveryMinutes() * 60_000).toISOString();
    const brands = await db.select<{ org_id: string; last_discovery: string | null }>('brand_profiles', { limit: 500 });
    for (const b of brands.filter((x) => !x.last_discovery || x.last_discovery < stale)) await discover(db, b.org_id);
}

export async function runEnrichment(): Promise<void> {
    const db = getDb();
    if (!db) return;
    const stale = new Date(Date.now() - 24 * 3600_000).toISOString();
    const rows = await db.select<PhishingDomain>('phishing_domains', {
        filters: [f.in('status', ['discovered', 'under_investigation', 'suspicious', 'confirmed_phishing'])], order: { col: 'last_enriched', asc: true }, limit: 200,
    });
    // A handful per run: each one is several external lookups plus a website fetch.
    for (const r of rows.filter((x) => !x.last_enriched || x.last_enriched < stale).slice(0, 10)) await enrichDomain(db, r);
}

export async function runProviderSync(): Promise<void> {
    const db = getDb();
    if (!db) return;
    const conns = await db.select<Connection>('messaging_connections', { filters: [f.in('status', ['connected', 'sync_error'])], limit: 500 });
    for (const c of conns) await syncConnection(db, c);
}

export function startEmailSecurityJob(): void {
    if (process.env.EMAILSEC_JOBS_DISABLED === 'true') {
        console.log('[emailsec] background jobs disabled (EMAILSEC_JOBS_DISABLED=true)');
        return;
    }
    const every = (minutes: number, name: string, fn: () => Promise<void>) => {
        setTimeout(() => void task(name, fn), 30_000 + Math.random() * 30_000).unref(); // after boot settles
        setInterval(() => void task(name, fn), Math.max(1, minutes) * 60_000).unref();
    };
    // Tick more often than the staleness windows so each item is refreshed close to on time.
    every(Math.min(60, emailsecConfig.dnsCheckMinutes()), 'dns-checks', runDnsChecks);
    every(Math.min(60, emailsecConfig.discoveryMinutes()), 'phish-discovery', runDiscovery);
    every(emailsecConfig.enrichMinutes(), 'phish-enrichment', runEnrichment);
    every(emailsecConfig.syncMinutes(), 'provider-sync', runProviderSync);
}
