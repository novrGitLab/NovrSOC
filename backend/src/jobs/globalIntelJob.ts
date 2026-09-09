// Global intelligence sync — CIRCL OSINT pulses (every 6h) and MITRE technique detections derived from
// Wazuh alerts (hourly).
//
// Persistence caveat, verified live 2026-09-07: neither `global_intel.threat_pulses` nor
// `global_intel.mitre_detections` exists, and the `global_intel` schema itself doesn't exist
// (PGRST106 "Invalid schema") — nor could PostgREST reach it if it did, without that schema
// being exposed in Supabase's API settings. These write to `public.threat_pulses` and
// `public.mitre_detections` instead (see backend/sql/2026-09-threat-intel.sql), and no-op
// quietly with a single log line until those tables exist.
//
// Pulse source: the keyless CIRCL OSINT MISP feed (services/circl.ts). This used to be
// AlienVault OTX, which was removed on 2026-09-09 — its key was invalid (403 on every endpoint,
// 31 chars where a real key is 64) and it contributed nothing. CIRCL needs no key at all, so
// this half of the job now produces real rows. The MITRE half reads Wazuh directly and is
// unaffected either way.

import { getSupabase } from '../services/geoEnrichment';
import { search } from '../lib/wazuh-indexer';
import { circlGetPulses } from '../services/circl';

// Table-missing is the expected steady state until the migration runs — logged once per call,
// not per row, and never escalated to an error.
function isMissingTable(code?: string): boolean {
    return code === 'PGRST205' || code === '42P01';
}

async function syncCIRCLPulses(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;

    try {
        const pulses = await circlGetPulses(50);
        if (pulses.length === 0) return 0;

        const { error } = await supabase.from('threat_pulses').upsert(
            pulses.map((p) => ({
                pulse_id: p.id,
                name: p.name,
                description: (p.description ?? '').slice(0, 500),
                author: p.author ?? null,
                tlp: p.tlp ?? 'white',
                tags: p.tags ?? [],
                // The manifest carries event metadata, not per-event attribute counts — fetching
                // every event file just to count IOCs would be thousands of requests per run.
                ioc_count: 0,
                malware_families: p.malware_families ?? [],
                attack_ids: p.attack_ids.map((a) => a.id).filter(Boolean),
                published_at: p.created,
            })),
            { onConflict: 'pulse_id' }
        );
        if (error) {
            if (!isMissingTable(error.code)) console.warn('[GlobalIntel] CIRCL persist failed:', error.message);
            return 0;
        }
        console.log(`[GlobalIntel] Synced ${pulses.length} CIRCL pulses`);
        return pulses.length;
    } catch (err) {
        console.warn('[GlobalIntel] CIRCL sync error:', err instanceof Error ? err.message : err);
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
    console.log('[GlobalIntel] Job started — CIRCL every 6h, MITRE every 60 minutes');
    setTimeout(() => {
        void syncCIRCLPulses();
        void syncMITREDetections();
    }, 20_000).unref();

    setInterval(() => { void syncCIRCLPulses(); }, 6 * 60 * 60 * 1000).unref();
    setInterval(() => { void syncMITREDetections(); }, 60 * 60 * 1000).unref();
}
