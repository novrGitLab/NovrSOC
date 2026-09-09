// Demonstration baseline for the Nigeria threat map and advisory feed.
//
// WHY THIS IS LABELLED DEMO DATA, EXPLICITLY:
// These numbers and advisories are illustrative. They are NOT collected intelligence and not
// telemetry — they're a plausible-looking baseline so the map and advisory pages aren't empty
// during a client demo, because the real collectors currently return almost nothing (ngCERT
// 403s from Railway's egress, and the CIRCL feed carries no Nigeria-tagged events today).
//
// Everything written here is therefore marked so it can never be mistaken for, or silently
// mixed with, real intel:
//   * every advisory_id is prefixed `DEMO-`
//   * every advisory `source` is suffixed ` (demo)` — so it reads "ngCERT (demo)", never "ngCERT"
//   * every advisory carries the `demo-data` tag, which is what the API uses to tell the
//     frontend to show a "demonstration data" badge
//   * no CVE identifiers are invented — a fabricated CVE could be copied into a real report
//
// Seeding is opt-in via SEED_DEMO_DATA=true. Without that env var this module does nothing, so
// a production deploy never silently fabricates threat data. Real collected advisories are
// never overwritten: seeding only fills a table that has no real rows in it.
//
// Schema note (verified live 2026-09-09): the `nigeria_intel` schema does not exist. The real
// tables are public.nigeria_state_threats and public.nigeria_advisories, and their columns are
// NOT the ones this feature was originally specced against — nigeria_state_threats has
// state_name/state_code/latitude/longitude/threat_score/attack_count/dominant_type/critical_flag,
// with no org_id, threat_count, critical_count, high_count or top_threat_type column. It also
// already contains all 37 rows (pre-seeded with coordinates), so this UPDATEs by state_name
// rather than inserting.

import { getSupabase } from './geoEnrichment';

export const DEMO_TAG = 'demo-data';

interface StateSeed {
    state: string;
    attacks: number;
    critical: number;
    dominant: string;
}

// Ordered roughly by internet/financial-sector density. Illustrative only.
//
// `state` must match nigeria_state_threats.state_name EXACTLY. Note the capital is stored as
// "FCT Abuja" there — not "FCT" (this feature's original spec) and not "Federal Capital
// Territory" (what routes/dashboard.ts's NIGERIA_STATE_CODES calls it). All three spellings are
// in play across the codebase; nigeriaStateToMapName() below bridges the last two.
const STATE_SEEDS: StateSeed[] = [
    { state: 'Lagos', attacks: 847, critical: 23, dominant: 'phishing' },
    { state: 'FCT Abuja', attacks: 421, critical: 12, dominant: 'ransomware' },
    { state: 'Rivers', attacks: 312, critical: 8, dominant: 'malware' },
    { state: 'Kano', attacks: 289, critical: 6, dominant: 'phishing' },
    { state: 'Oyo', attacks: 198, critical: 4, dominant: 'credential_theft' },
    { state: 'Anambra', attacks: 187, critical: 3, dominant: 'bec' },
    { state: 'Delta', attacks: 156, critical: 2, dominant: 'malware' },
    { state: 'Edo', attacks: 143, critical: 2, dominant: 'phishing' },
    { state: 'Ogun', attacks: 134, critical: 1, dominant: 'ransomware' },
    { state: 'Kaduna', attacks: 112, critical: 1, dominant: 'malware' },
    { state: 'Enugu', attacks: 98, critical: 1, dominant: 'phishing' },
    { state: 'Imo', attacks: 87, critical: 0, dominant: 'bec' },
    { state: 'Akwa Ibom', attacks: 76, critical: 0, dominant: 'malware' },
    { state: 'Cross River', attacks: 54, critical: 0, dominant: 'phishing' },
    { state: 'Plateau', attacks: 43, critical: 0, dominant: 'malware' },
    { state: 'Niger', attacks: 38, critical: 0, dominant: 'phishing' },
    { state: 'Borno', attacks: 34, critical: 0, dominant: 'malware' },
    { state: 'Bauchi', attacks: 29, critical: 0, dominant: 'phishing' },
    { state: 'Sokoto', attacks: 24, critical: 0, dominant: 'malware' },
    { state: 'Adamawa', attacks: 21, critical: 0, dominant: 'phishing' },
    { state: 'Benue', attacks: 19, critical: 0, dominant: 'malware' },
    { state: 'Abia', attacks: 17, critical: 0, dominant: 'bec' },
    { state: 'Ondo', attacks: 15, critical: 0, dominant: 'phishing' },
    { state: 'Osun', attacks: 14, critical: 0, dominant: 'malware' },
    { state: 'Ekiti', attacks: 12, critical: 0, dominant: 'phishing' },
    { state: 'Kwara', attacks: 11, critical: 0, dominant: 'malware' },
    { state: 'Nassarawa', attacks: 9, critical: 0, dominant: 'phishing' },
    { state: 'Kogi', attacks: 8, critical: 0, dominant: 'malware' },
    { state: 'Taraba', attacks: 7, critical: 0, dominant: 'phishing' },
    { state: 'Yobe', attacks: 6, critical: 0, dominant: 'malware' },
    { state: 'Gombe', attacks: 5, critical: 0, dominant: 'phishing' },
    { state: 'Zamfara', attacks: 4, critical: 0, dominant: 'malware' },
    { state: 'Kebbi', attacks: 3, critical: 0, dominant: 'phishing' },
    { state: 'Jigawa', attacks: 3, critical: 0, dominant: 'malware' },
    { state: 'Katsina', attacks: 2, critical: 0, dominant: 'phishing' },
    { state: 'Ebonyi', attacks: 2, critical: 0, dominant: 'phishing' },
    { state: 'Bayelsa', attacks: 2, critical: 0, dominant: 'malware' },
];

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

// threat_score is a 0-100 field the map colours by. Derived from attack volume on a log scale so
// Lagos doesn't flatten every other state to zero, then floored upward when criticals exist.
function deriveThreatScore(attacks: number, critical: number): number {
    if (attacks <= 0) return 0;
    const volume = Math.min(80, Math.round((Math.log10(attacks + 1) / Math.log10(900)) * 80));
    const criticalWeight = Math.min(20, critical * 2);
    return Math.min(100, volume + criticalWeight);
}

interface AdvisorySeed {
    advisory_id: string;
    source: string;
    title: string;
    description: string;
    severity: string;
    threat_type: string;
    tags: string[];
    source_url: string;
    published_at: string;
}

// Sector lives in `tags` — nigeria_advisories has no affected_sector column. The sector filter
// on the frontend reads tags, so `sector:banking` is the convention used here and by the UI.
const ADVISORY_SEEDS: AdvisorySeed[] = [
    {
        advisory_id: 'DEMO-NGCERT-001',
        source: 'ngCERT (demo)',
        title: 'Ransomware campaign targeting Nigerian financial institutions',
        description: 'Illustrative advisory. Describes a ransomware campaign against banks and financial service providers, of the kind ngCERT publishes. Not a real ngCERT bulletin — demonstration content only.',
        severity: 'critical',
        threat_type: 'ransomware',
        tags: ['ransomware', 'banking', 'nigeria', 'sector:banking', DEMO_TAG],
        source_url: 'https://cert.gov.ng/',
        published_at: '2026-08-15T00:00:00Z',
    },
    {
        advisory_id: 'DEMO-NGCERT-002',
        source: 'ngCERT (demo)',
        title: 'Business Email Compromise surge targeting Nigerian enterprises',
        description: 'Illustrative advisory. Describes a BEC wave in which attackers impersonate executives and finance staff to divert payments. Not a real ngCERT bulletin — demonstration content only.',
        severity: 'high',
        threat_type: 'bec',
        tags: ['bec', 'phishing', 'fraud', 'nigeria', 'sector:all', DEMO_TAG],
        source_url: 'https://cert.gov.ng/',
        published_at: '2026-08-22T00:00:00Z',
    },
    {
        advisory_id: 'DEMO-NCC-001',
        source: 'NCC-CSIRT (demo)',
        title: 'SIM swap fraud targeting mobile banking users',
        description: 'Illustrative advisory. Describes coordinated SIM swap attacks against telecom customers leading to unauthorised mobile banking access. Not a real NCC-CSIRT bulletin — demonstration content only.',
        severity: 'high',
        threat_type: 'fraud',
        tags: ['sim-swap', 'mobile-banking', 'telecom', 'nigeria', 'sector:telecommunications', DEMO_TAG],
        source_url: 'https://www.ncc.gov.ng/',
        published_at: '2026-08-18T00:00:00Z',
    },
    {
        advisory_id: 'DEMO-CBN-001',
        source: 'CBN (demo)',
        title: 'Advisory on fraudulent USSD transactions',
        description: 'Illustrative advisory. Describes fraudulent USSD-based transfers and the additional authentication controls a regulator would require for high-value USSD transactions. Not a real CBN circular — demonstration content only.',
        severity: 'high',
        threat_type: 'fraud',
        tags: ['ussd', 'fraud', 'banking', 'nigeria', 'sector:banking', DEMO_TAG],
        source_url: 'https://www.cbn.gov.ng/',
        published_at: '2026-09-01T00:00:00Z',
    },
    {
        advisory_id: 'DEMO-NGCERT-003',
        source: 'ngCERT (demo)',
        title: 'Phishing campaign impersonating government service portals',
        description: 'Illustrative advisory. Describes cloned government service portals used to harvest credentials and personal data from citizens and public-sector staff. Not a real ngCERT bulletin — demonstration content only.',
        severity: 'high',
        threat_type: 'phishing',
        tags: ['phishing', 'government', 'credential-theft', 'nigeria', 'sector:government', DEMO_TAG],
        source_url: 'https://cert.gov.ng/',
        published_at: '2026-09-03T00:00:00Z',
    },
    {
        advisory_id: 'DEMO-NGCERT-004',
        source: 'ngCERT (demo)',
        title: 'Supply chain compromise affecting fintech API providers',
        description: 'Illustrative advisory. Describes malicious code introduced through a third-party SDK update affecting fintech integrators. Not a real ngCERT bulletin — demonstration content only.',
        severity: 'critical',
        threat_type: 'supply_chain',
        tags: ['supply-chain', 'fintech', 'api', 'nigeria', 'sector:fintech', DEMO_TAG],
        source_url: 'https://cert.gov.ng/',
        published_at: '2026-09-05T00:00:00Z',
    },
];

export function isDemoSeedEnabled(): boolean {
    return process.env.SEED_DEMO_DATA === 'true';
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

async function seedStates(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;

    // Only fill a map that has nothing on it. If any state already carries a real attack count,
    // collection is working and demo values must not overwrite it.
    const { data: live, error: readError } = await supabase
        .from('nigeria_state_threats')
        .select('state_name, attack_count')
        .gt('attack_count', 0)
        .limit(1);
    if (readError) {
        console.warn('[NigeriaDemoSeed] Could not read state table:', readError.message);
        return 0;
    }
    if ((live?.length ?? 0) > 0) {
        console.log('[NigeriaDemoSeed] States already have live counts — demo seed skipped');
        return 0;
    }

    let updated = 0;
    for (const seed of STATE_SEEDS) {
        const { error } = await supabase
            .from('nigeria_state_threats')
            .update({
                attack_count: seed.attacks,
                threat_score: deriveThreatScore(seed.attacks, seed.critical),
                dominant_type: seed.dominant,
                critical_flag: seed.critical > 0,
                last_updated: new Date().toISOString(),
            })
            .eq('state_name', seed.state);
        if (!error) updated++;
    }
    console.log(`[NigeriaDemoSeed] Seeded ${updated} states with illustrative baseline values`);
    return updated;
}

async function seedAdvisories(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;

    const { data: existing, error: readError } = await supabase
        .from('nigeria_advisories')
        .select('advisory_id')
        .limit(1);
    if (readError) {
        console.warn('[NigeriaDemoSeed] Could not read advisories:', readError.message);
        return 0;
    }
    // Never insert demo rows alongside real collected advisories.
    if ((existing?.length ?? 0) > 0) {
        console.log('[NigeriaDemoSeed] Advisories already present — demo seed skipped');
        return 0;
    }

    const { error } = await supabase.from('nigeria_advisories').insert(
        ADVISORY_SEEDS.map((a) => ({ ...a, org_id: 'global' }))
    );
    if (error) {
        console.warn('[NigeriaDemoSeed] Advisory seed failed:', error.message);
        return 0;
    }
    console.log(`[NigeriaDemoSeed] Seeded ${ADVISORY_SEEDS.length} illustrative advisories`);
    return ADVISORY_SEEDS.length;
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

export async function seedNigerianDemoData(): Promise<{ states: number; advisories: number }> {
    if (!isDemoSeedEnabled()) {
        return { states: 0, advisories: 0 };
    }
    const states = await seedStates();
    const advisories = await seedAdvisories();
    return { states, advisories };
}
