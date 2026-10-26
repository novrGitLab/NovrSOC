// Shared types for the Threat Information System pages (phase P6). Every value comes from /api/ti.
// What a feed said is shown as that source's claim; analyst verdicts are separate.

export type IndicatorType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve';
export interface TiFeed {
    id: string; name: string; url: string; enabled: boolean; validity_days: number | null;
    last_run_at: string | null; last_success_at: string | null; last_error: string | null;
    last_counts: { fetched: number; new: number; updated: number; duplicates: number; invalid: number } | null;
    stale?: boolean; failing?: boolean; configured?: boolean;
}
export interface TiRun { id: string; feed_id: string; started_at: string; finished_at: string | null; status: 'running' | 'ok' | 'failed'; fetched: number; new: number; updated: number; duplicates: number; invalid: number; error: string | null }
export interface TiIndicator {
    id: string; type: IndicatorType; value: string; first_seen: string; last_seen: string; valid_until: string | null; status: 'active' | 'expired';
    max_confidence: number | null; tags: string[]; malware_families: string[]; threat_types: string[]; mitre_techniques: string[]; source_count: number;
}
export type Tlp = 'clear' | 'green' | 'amber' | 'amber+strict' | 'red';
export interface TiSource {
    id: string; feed_id: string; source_ref: string; confidence: number | null; first_seen: string | null; last_seen: string; context: Record<string, unknown>; ti_feeds?: { name: string } | null;
    tlp?: Tlp; distribution?: number | null;
    /** Why this record may not be exported at each ceiling (null = it may). */
    export?: { clear: string | null; green: string | null };
}
export interface TiMatch {
    id: string; indicator_id: string; entity_type: 'alert' | 'asset' | 'finding' | 'case'; entity_id: string; matched_field: string; matched_value: string;
    first_matched_at: string; last_matched_at: string; status: 'new' | 'reviewed' | 'promoted' | 'dismissed'; reviewed_by: string | null; case_id: string | null;
    ti_indicators?: Pick<TiIndicator, 'type' | 'value' | 'max_confidence' | 'malware_families' | 'threat_types' | 'source_count' | 'status'> | null;
}

// ── Relevance & reporting (R3.3D) ───────────────────────────────────────────────────────────
export type RelevanceTier = 'critical' | 'high' | 'medium' | 'low';
export interface RelevantItem {
    match_id: string; indicator_id: string; indicator_type: IndicatorType; indicator_value: string;
    malware_families: string[]; threat_types: string[]; confidence: number | null;
    entity_type: TiMatch['entity_type']; entity_id: string; matched_field: string; last_matched_at: string;
    status: TiMatch['status']; verified: boolean; case_id: string | null;
    kev: boolean; asset_criticality: 'low' | 'medium' | 'high' | 'critical' | null; asset_value: string | null;
    tier: RelevanceTier; reasons: string[]; labels_hidden?: boolean;
}
export interface RelevantIntel { generated_at: string; items: RelevantItem[]; by_tier: Record<RelevanceTier, number> }
export const TIER_LABEL: Record<RelevanceTier, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
export const TIER_STYLE: Record<RelevanceTier, string> = {
    critical: 'bg-red/10 text-red border-red/30', high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-blue/10 text-blue border-blue/30', low: 'bg-card-muted text-foreground-muted border-border',
};
export interface TiFeedback { id: string; verdict: 'confirmed_malicious' | 'suspicious' | 'benign' | 'false_positive'; note: string | null; actor: string; at: string }

export const VERDICT_LABEL: Record<TiFeedback['verdict'], string> = {
    confirmed_malicious: 'Confirmed malicious', suspicious: 'Suspicious', benign: 'Benign', false_positive: 'False positive',
};
export const MATCH_STATUS_STYLE: Record<TiMatch['status'], string> = {
    new: 'bg-red/10 text-red', reviewed: 'bg-blue/10 text-blue', promoted: 'bg-green/10 text-green', dismissed: 'bg-card-muted text-foreground-muted',
};
/** Where a matched record lives in the platform. */
export const entityHref = (m: Pick<TiMatch, 'entity_type' | 'entity_id' | 'case_id'>): string | null =>
    m.entity_type === 'asset' ? '/admin/vms/assets'
        : m.entity_type === 'finding' ? `/admin/vms/findings?id=${m.entity_id}`
            : m.entity_type === 'case' ? '/admin/secops/cases'
                : '/admin/secops/alerts';

// ── Threat Intelligence V1 (phase P25) ───────────────────────────────────────────────────────
export interface TiReport {
    id: string; feed_id: string; source_ref: string; title: string; published_at: string | null; source_updated_at?: string | null;
    tlp: Tlp; threat_level: string | null; tags?: string[]; target_countries: string[]; target_sectors: string[]; actors: string[]; malware: string[]; attack_patterns: string[]; attribute_count?: number | null;
}
export interface TiLocation { country_code: string | null; country: string | null; region: string | null; city: string | null; asn: string | null; as_org: string | null; method: 'source_stated' | 'geoip'; provider: string; precision: 'state' | 'country' | 'unknown'; looked_up_at: string }
export interface TiRelated { indicator_id: string; type: IndicatorType; value: string; status: string; last_seen: string; link: string; source: string }

export interface MapTargeting {
    id: string; kind: 'source_report' | 'advisory'; title: string; source: string; source_ref: string; published_at: string | null; tlp: Tlp;
    sectors: string[]; actors: string[]; malware: string[]; attribution: string; basis: string; location: { precision: 'country'; state: null }; url: string | null;
}
export interface MapHosted { indicator_id: string; type: IndicatorType; value: string; last_seen: string; malware: string[]; state: string | null; precision: 'state' | 'country'; method: string; provider: string; asn: string | null; as_org: string | null }
export interface MapExposure { match_id: string; indicator_id: string; value: string; entity_type: TiMatch['entity_type']; matched_field: string; status: TiMatch['status']; first_matched_at: string; state: string | null; precision: string }
export interface MapData {
    period: { from: string; to: string; days: number };
    states: { state: string; hosted: number; exposure: number }[];
    country_level: { targeting: number; hosted_state_unknown: number; exposure_state_unknown: number };
    targeting: MapTargeting[]; hosted: MapHosted[]; exposure: MapExposure[]; sectors: string[];
    withheld_reports: number; setup: { reports_table: boolean }; limitations: string[];
}

export interface TiActor {
    id: string; name: string; aliases: string[]; focus: 'nigeria' | 'global'; origin: string; motivation: string; targeted_sectors: string[]; targeted_regions: string[];
    techniques: { id: string; name: string }[]; description: string; damage: string; known_incidents: { year: string; title: string; description: string; source: string }[];
    reference: string; reference_url: string; library_confidence: string; last_active: string;
    source_mentions: { count: number; nigeria_targeting: number; last: string | null; reports: { id: string; title: string; published_at: string | null }[] };
}
export interface SourceNamedActor { name: string; count: number; last: string | null; nigeria: number; reports: { id: string; title: string; published_at: string | null }[] }

export interface TiVulnerability {
    id: string; cve: string; added: string;
    kev: { vendor?: string | null; product?: string | null; name?: string | null; required_action?: string | null; due_date?: string | null; ransomware?: string | null };
    nvd: { description: string | null; cvss_score: number | null; cvss_version: string | null; epss_score: number | null; epss_percentile: number | null; nvd_fetched_at: string | null; epss_fetched_at: string | null } | null;
    your_open_findings: number; your_assets: string[];
}
export interface TiAdvisory { advisory_id: string; source: string; title: string; severity: string | null; threat_type: string | null; tags: string[] | null; source_url: string | null; published_at: string | null }

export interface TaxiiClient { id: string; name: string; key_id: string; collections: string[]; max_tlp: 'clear' | 'green' | 'amber'; enabled: boolean; created_by: string; created_at: string; last_used_at: string | null; revoked_at: string | null }
export interface TiSources {
    feeds: (TiFeed & { retired?: boolean })[];
    runs: TiRun[];
    enrichment: { nvd: { last_fetch: string | null; configured_key: boolean; cves_tracked: number }; epss: { last_fetch: string | null } };
    misp: { configured: boolean; writes_enabled: boolean; last_check: MispCheck | null };
    ai: { provider: 'nvidia' | 'ollama'; configured: boolean; model: string; reachable: boolean; detail: string };
    engine: { correlation_last_run_at: string | null; correlation_errors: string[] | null };
    sharing: { source_records_by_tlp: Record<Tlp, number> };
    exchange: { taxii_discovery: string; api_root: string; collections: { id: string; alias: string; title: string; description: string }[]; active_clients: number | null };
}
export interface MispCheck { checked_at: string; configured: boolean; reachable: boolean; version: string | null; key_can_write: boolean | null; role: string | null; stix2_export: string; taxii21: string; writes_enabled_here: boolean; errors: string[] }

export const TLP_LABEL: Record<Tlp, string> = { clear: 'TLP:CLEAR', green: 'TLP:GREEN', amber: 'TLP:AMBER', 'amber+strict': 'TLP:AMBER+STRICT', red: 'TLP:RED' };
export const FEED_NAME: Record<string, string> = {
    threatfox: 'ThreatFox', urlhaus: 'URLhaus', feodo: 'Feodo Tracker', cisa_kev: 'CISA KEV', misp: 'MISP', misp_events: 'MISP events', opencti: 'OpenCTI (retired)',
};
/** "3 h ago", "2 d ago" — for freshness, next to the exact time. */
export function ago(iso: string | null | undefined, now: number): string {
    if (!iso) return 'never';
    const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 129600) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
}
