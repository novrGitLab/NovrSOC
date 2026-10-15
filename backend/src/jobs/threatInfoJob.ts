// Threat Information System background work (phase P6), where mutating jobs run (lib/runtimeEnv.ts):
//   • every 6 hours: ThreatFox, URLhaus, Feodo Tracker (abuse.ch); daily: CISA KEV
//   • every hour: indicators past their validity are marked expired
//   • every 15 minutes: each organisation's new alerts, assets, findings and cases are matched
//     against active indicators (services/threatInfo.ts correlateOrg)
// Off with TI_ENABLED=false. ThreatFox and URLhaus need THREATFOX_API_KEY (an abuse.ch Auth-Key);
// without it those runs fail and the feed's health says why — nothing is pretended.

import { getSupabase } from '../services/geoEnrichment';
import { runFeed, expireIndicators, correlateOrg } from '../services/threatInfo';

export const lastThreatInfoRun: { correlation: Record<string, unknown> | null; at: string | null } = { correlation: null, at: null };

/** Organisations to correlate: those with Wazuh groups mapped or VMS scope. */
export async function correlationOrgs(): Promise<string[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const [m, s] = await Promise.all([
        supabase.from('wazuh_group_org_map').select('org_id'),
        supabase.from('vms_scopes').select('org_id'),
    ]);
    return [...new Set([...(m.data ?? []), ...(s.data ?? [])].map((r) => r.org_id as string).filter(Boolean))];
}

export function startThreatInfoJob(): void {
    if (process.env.TI_ENABLED === 'false') { console.log('[ti] disabled by TI_ENABLED=false'); return; }
    const busy = new Set<string>();
    const once = (name: string, fn: () => Promise<void>) => async () => {
        if (busy.has(name)) return;
        busy.add(name);
        try { await fn(); } catch (err) { console.error(`[ti] ${name} failed:`, err instanceof Error ? err.message : err); } finally { busy.delete(name); }
    };
    const feeds = (ids: string[]) => once(`feeds:${ids.join(',')}`, async () => {
        for (const id of ids) {
            const r = await runFeed(id);
            console.log(`[ti] ${id}: ${r.status}${r.counts ? ` ${JSON.stringify(r.counts)}` : ''}${r.error ? ` — ${r.error}` : ''}`);
        }
    });
    const expire = once('expire', async () => { const n = await expireIndicators(); if (n) console.log(`[ti] ${n} indicator(s) expired`); });
    const correlate = once('correlate', async () => {
        const result: Record<string, unknown> = {};
        for (const org of await correlationOrgs()) {
            try { result[org] = await correlateOrg(org); } catch (err) { result[org] = { error: err instanceof Error ? err.message : String(err) }; }
        }
        lastThreatInfoRun.correlation = result;
        lastThreatInfoRun.at = new Date().toISOString();
    });
    const abuse = feeds(['threatfox', 'urlhaus', 'feodo']);
    const kev = feeds(['cisa_kev']);
    setTimeout(() => { void abuse().then(kev).then(correlate); }, 90_000).unref();
    setInterval(() => { void abuse(); }, 6 * 60 * 60_000).unref();
    setInterval(() => { void kev(); }, 24 * 60 * 60_000).unref();
    setInterval(() => { void expire(); }, 60 * 60_000).unref();
    setInterval(() => { void correlate(); }, 15 * 60_000).unref();
}
