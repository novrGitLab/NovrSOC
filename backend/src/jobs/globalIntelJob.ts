// Global intelligence sync — OTX pulses (every 6h) and MITRE technique detections derived from
// Wazuh alerts (hourly).
//
// Persistence caveat, verified live 2026-09-07: neither `global_intel.threat_pulses` nor
// `global_intel.mitre_detections` exists, and the `global_intel` schema itself doesn't exist
// (PGRST106 "Invalid schema") — nor could PostgREST reach it if it did, without that schema
// being exposed in Supabase's API settings. These write to `public.threat_pulses` and
// `public.mitre_detections` instead (see backend/sql/2026-09-threat-intel.sql), and no-op
// quietly with a single log line until those tables exist.
//
// OTX caveat: OTX_API_KEY in the environment is invalid (403 on every endpoint, and 31 chars
// where a real key is 64), so the pulse half of this job returns 0 until a working key is set.
// The MITRE half reads Wazuh directly and is unaffected.

import { getSupabase } from '../services/geoEnrichment';
import { search } from '../lib/wazuh-indexer';

interface OTXPulse {
    id: string;
    name: string;
    description?: string;
    author_name?: string;
    tags?: string[];
    indicator_count?: number;
    malware_families?: unknown[];
    attack_ids?: Array<{ id?: string }>;
    created?: string;
}

// Table-missing is the expected steady state until the migration runs — logged once per call,
// not per row, and never escalated to an error.
function isMissingTable(code?: string): boolean {
    return code === 'PGRST205' || code === '42P01';
}

async function syncOTXPulses(): Promise<number> {
    const apiKey = process.env.OTX_API_KEY;
    if (!apiKey) return 0;
    const supabase = getSupabase();
    if (!supabase) return 0;

    try {
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const r = await fetch(`https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=${since}`, {
            headers: { 'X-OTX-API-KEY': apiKey },
            signal: AbortSignal.timeout(15000),
        });
        if (r.status === 401 || r.status === 403) {
            console.warn('[GlobalIntel] OTX rejected the API key — pulse sync skipped');
            return 0;
        }
        if (!r.ok) return 0;

        const data = (await r.json()) as { results?: OTXPulse[] };
        const pulses = data.results ?? [];
        if (pulses.length === 0) return 0;

        const { error } = await supabase.from('threat_pulses').upsert(
            pulses.map((p) => ({
                pulse_id: p.id,
                name: p.name,
                description: (p.description ?? '').slice(0, 500),
                author: p.author_name ?? null,
                tlp: 'white',
                tags: p.tags ?? [],
                ioc_count: p.indicator_count ?? 0,
                malware_families: p.malware_families ?? [],
                attack_ids: (p.attack_ids ?? []).map((a) => a.id).filter(Boolean),
                published_at: p.created ?? new Date().toISOString(),
            })),
            { onConflict: 'pulse_id' }
        );
        if (error) {
            if (!isMissingTable(error.code)) console.warn('[GlobalIntel] OTX persist failed:', error.message);
            return 0;
        }
        console.log(`[GlobalIntel] Synced ${pulses.length} OTX pulses`);
        return pulses.length;
    } catch (err) {
        console.warn('[GlobalIntel] OTX sync error:', err instanceof Error ? err.message : err);
        return 0;
    }
}

interface MitreAgg {
    aggregations?: {
        techniques?: {
            buckets?: Array<{
                key: string;
                doc_count: number;
                tactic?: { buckets?: Array<{ key: string }> };
                agents?: { buckets?: Array<{ key: string }> };
            }>;
        };
    };
}

async function syncMITREDetections(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    try {
        const result = await search<MitreAgg>('wazuh-alerts-4.x-*', {
            size: 0,
            query: { range: { timestamp: { gte: 'now-24h' } } },
            aggs: {
                techniques: {
                    terms: { field: 'rule.mitre.id', size: 50 },
                    aggs: {
                        tactic: { terms: { field: 'rule.mitre.tactic', size: 1 } },
                        agents: { terms: { field: 'agent.name', size: 5 } },
                    },
                },
            },
        });

        const buckets = result?.aggregations?.techniques?.buckets ?? [];
        if (buckets.length === 0) return 0;

        const { error } = await supabase.from('mitre_detections').upsert(
            buckets.map((b) => ({
                technique_id: b.key,
                tactic: b.tactic?.buckets?.[0]?.key ?? 'Unknown',
                detection_count: b.doc_count,
                agent_names: (b.agents?.buckets ?? []).map((a) => a.key),
                last_detected: new Date().toISOString(),
                org_id: 'cybernovr',
            })),
            { onConflict: 'technique_id,org_id' }
        );
        if (error) {
            if (!isMissingTable(error.code)) console.warn('[GlobalIntel] MITRE persist failed:', error.message);
            return 0;
        }
        console.log(`[GlobalIntel] Synced ${buckets.length} MITRE techniques`);
        return buckets.length;
    } catch (err) {
        console.warn('[GlobalIntel] MITRE sync error:', err instanceof Error ? err.message : err);
        return 0;
    }
}

export function startGlobalIntelJob(): void {
    console.log('[GlobalIntel] Job started — OTX every 6h, MITRE every 60 minutes');
    setTimeout(() => {
        void syncOTXPulses();
        void syncMITREDetections();
    }, 20_000).unref();

    setInterval(() => { void syncOTXPulses(); }, 6 * 60 * 60 * 1000).unref();
    setInterval(() => { void syncMITREDetections(); }, 60 * 60 * 1000).unref();
}
