// Shared types for the Threat Information System pages (phase P6). Every value comes from /api/ti.
// What a feed said is shown as that source's claim; analyst verdicts are separate.

export type IndicatorType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve';
export interface TiFeed {
    id: string; name: string; url: string; enabled: boolean; validity_days: number | null;
    last_run_at: string | null; last_success_at: string | null; last_error: string | null;
    last_counts: { fetched: number; new: number; updated: number; duplicates: number; invalid: number } | null;
    stale?: boolean; failing?: boolean;
}
export interface TiRun { id: string; feed_id: string; started_at: string; finished_at: string | null; status: 'running' | 'ok' | 'failed'; fetched: number; new: number; updated: number; duplicates: number; invalid: number; error: string | null }
export interface TiIndicator {
    id: string; type: IndicatorType; value: string; first_seen: string; last_seen: string; valid_until: string | null; status: 'active' | 'expired';
    max_confidence: number | null; tags: string[]; malware_families: string[]; threat_types: string[]; mitre_techniques: string[]; source_count: number;
}
export interface TiSource { id: string; feed_id: string; source_ref: string; confidence: number | null; first_seen: string | null; last_seen: string; context: Record<string, unknown>; ti_feeds?: { name: string } | null }
export interface TiMatch {
    id: string; indicator_id: string; entity_type: 'alert' | 'asset' | 'finding' | 'case'; entity_id: string; matched_field: string; matched_value: string;
    first_matched_at: string; last_matched_at: string; status: 'new' | 'reviewed' | 'promoted' | 'dismissed'; reviewed_by: string | null; case_id: string | null;
    ti_indicators?: Pick<TiIndicator, 'type' | 'value' | 'max_confidence' | 'malware_families' | 'threat_types' | 'source_count' | 'status'> | null;
}
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
