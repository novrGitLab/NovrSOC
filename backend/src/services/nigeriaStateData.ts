// Nigeria state-threat helpers, moved out of the deleted services/nigeriaDemoSeed.ts
// (2026-10 cleanup). Seeding fabricated demo data (SEED_DEMO_DATA) is gone. What remains:
//   * readSeededStates() / nigeriaStateToMapName() read the collector's nigeria_state_threats rows
//     for the Nigeria map (routes/dashboard.ts).
//   * hasDemoData() / clearDemoBaseline() are kept so any demo rows an earlier deploy already
//     wrote are still badged as demonstration data and wiped when the collector first writes
//     real counts (services/nigerianIntelCollector.ts), instead of fusing with real numbers.

import { getSupabase } from './geoEnrichment';

// Tag carried by every demo row the deleted seeder wrote.
export const DEMO_TAG = 'demo-data';

// nigeria_state_threats stores the capital as "FCT Abuja"; the map in routes/dashboard.ts keys
// its states by NIGERIA_STATE_CODES, where it's "Federal Capital Territory". Every other state
// name matches between the two.
export function nigeriaStateToMapName(dbName: string): string {
    return dbName === 'FCT Abuja' ? 'Federal Capital Territory' : dbName;
}

export interface SeededStateRow {
    state_name: string;
    attack_count: number | null;
    threat_score: number | null;
    dominant_type: string | null;
    critical_flag: boolean | null;
}

// True when the advisory table currently holds demo rows — drives the "demonstration data"
// badge in the UI. Checked against the database rather than an in-process flag so it survives a
// restart and stays correct if the rows are deleted by hand.
export async function hasDemoData(): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    try {
        const { data, error } = await supabase
            .from('nigeria_advisories')
            .select('advisory_id')
            .contains('tags', [DEMO_TAG])
            .limit(1);
        if (error) return false;
        return (data?.length ?? 0) > 0;
    } catch {
        return false;
    }
}

// Reads whatever is currently in nigeria_state_threats. The Nigeria map builds its states from
// Wazuh alerts, NOT from this table, so seeding alone would leave the map on zeros — routes/
// dashboard.ts overlays these rows only when Wazuh attributed nothing to any Nigerian state.
export async function readSeededStates(): Promise<SeededStateRow[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    try {
        const { data, error } = await supabase
            .from('nigeria_state_threats')
            .select('state_name, attack_count, threat_score, dominant_type, critical_flag')
            .gt('attack_count', 0);
        if (error) return [];
        return (data ?? []) as SeededStateRow[];
    } catch {
        return [];
    }
}

// Wipes the illustrative baseline so real collected data starts from clean zeros.
//
// This exists because the demo values and real telemetry write to the SAME columns. Without it,
// the collector's first real Nigerian IP would increment Lagos from its fabricated 847 to 848 —
// permanently fusing invented numbers with real ones, with no way to tell them apart afterwards.
// The collector calls this the moment it has real state data to write, and never otherwise.
export async function clearDemoBaseline(): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    try {
        const { error: stateError } = await supabase
            .from('nigeria_state_threats')
            .update({ attack_count: 0, threat_score: 0, critical_flag: false, dominant_type: null, last_updated: new Date().toISOString() })
            .gt('attack_count', 0);
        if (stateError) {
            console.warn('[NigeriaStateData] Could not clear state baseline:', stateError.message);
            return false;
        }

        // Only the demo advisories — anything genuinely collected is left alone.
        const { error: advError } = await supabase
            .from('nigeria_advisories')
            .delete()
            .contains('tags', [DEMO_TAG]);
        if (advError) console.warn('[NigeriaStateData] Could not clear demo advisories:', advError.message);

        console.log('[NigeriaStateData] Demo baseline cleared — real collected data takes over');
        return true;
    } catch (err) {
        console.warn('[NigeriaStateData] Clear failed:', err instanceof Error ? err.message : err);
        return false;
    }
}
