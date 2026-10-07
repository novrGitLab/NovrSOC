// Threats — distinct threats derived from live Wazuh alerts (level 7+), not individual alerts.
//
// A threat is one rule firing from one source: rule + source IP when the alert has one,
// otherwise rule + agent (most host-based rules carry no IP). For each: first/last seen, alert
// count, affected assets (agents), MITRE technique, and a type read from the rule's groups.
//
// Status: analyst decisions (contained / resolved, assignee, escalation case) are stored in the
// threat_triage table (backend/sql/2026-09-threat-triage.sql), in memory until it exists.
// Without a decision, status is derived: Active if seen in the last 24 hours, else Monitoring.
// A resolved threat that fires again after it was resolved shows as Active (recurred).
import { createHash } from 'crypto';
import { search } from '../lib/wazuh-indexer';
import { getSupabase } from './geoEnrichment';
import { dbErrorMessage } from './cases';
import { severityFromLevel, SEVERITY_MIN_LEVEL, type Severity } from '../lib/severity';

export type ThreatStatus = 'active' | 'contained' | 'resolved' | 'monitoring';
// Threats are built from level 7+ alerts only, so 'low' never occurs in practice.
export type ThreatSeverity = Severity;

export interface Threat {
    id: string;
    name: string;
    type: string;
    source: 'Wazuh alert';
    severity: ThreatSeverity;
    status: ThreatStatus;
    recurred: boolean;
    rule_id: string;
    rule_level: number;
    source_ip: string | null;
    assets: string[];
    alert_count: number;
    first_seen: string;
    last_seen: string;
    mitre_technique_id: string | null;
    mitre_technique: string | null;
    mitre_tactic: string | null;
    assigned_to: string | null;
    case_id: string | null;
    case_number: string | null;
    decided_at: string | null;
}

export interface Triage {
    threat_id: string;
    org_id: string;
    status: 'contained' | 'resolved' | null;
    assigned_to: string | null;
    case_id: string | null;
    case_number: string | null;
    updated_by: string;
    updated_at: string;
    note: string | null;
}

const memoryTriage = new Map<string, Triage>();

const TYPE_RULES: [RegExp, string][] = [
    [/ransomware|malware|virus|rootkit|trojan|yara|virustotal|clamav/i, 'Malware'],
    [/phish/i, 'Phishing'],
    [/authentication_fail|brute|sshd|invalid_login|win_authentication/i, 'Brute Force'],
    [/sql_injection|xss|web_attack|attack|ids|suricata|exploit|shellshock|injection|lateral|privilege escalation|credential dump|mimikatz/i, 'Intrusion'],
    [/vulnerability/i, 'Vulnerability'],
    [/syscheck|fim|integrity/i, 'File Integrity'],
    [/sca|policy|audit|cis/i, 'Policy Violation'],
];
/** Type from the rule's groups and description; failing that, its MITRE tactic. */
export function threatType(groups: string[], description = '', tactic: string | null = null): string {
    const text = `${groups.join(' ')} ${description}`;
    for (const [re, label] of TYPE_RULES) if (re.test(text)) return label;
    return tactic ?? 'Suspicious Activity';
}

const threatId = (ruleId: string, key: string) => `THR-${createHash('sha1').update(`${ruleId}|${key}`).digest('hex').slice(0, 10)}`;

interface Bucket<T = unknown> { key: string; doc_count: number; [k: string]: T | unknown }
interface AggResponse {
    aggregations?: {
        rules?: {
            buckets?: (Bucket & {
                lvl?: { value?: number };
                sample?: { hits?: { hits?: { _source?: { rule?: { description?: string; groups?: string[]; mitre?: { id?: string[]; technique?: string[]; tactic?: string[] } } } }[] } };
                src?: { buckets?: (Bucket & { agents?: { buckets?: (Bucket & { first?: { value_as_string?: string }; last?: { value_as_string?: string } })[] } })[] };
            })[];
        };
    };
}

const NO_IP = '__none__';

/** Threats seen in the window, newest activity first. Throws if the indexer can't be read. */
export async function loadThreats(rangeHours: number): Promise<Omit<Threat, 'status' | 'recurred' | 'assigned_to' | 'case_id' | 'case_number' | 'decided_at'>[]> {
    const r = await search<AggResponse>('wazuh-alerts-4.x-*', {
        size: 0,
        query: { bool: { filter: [{ range: { timestamp: { gte: `now-${rangeHours}h` } } }, { range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.medium } } }] } },
        aggs: {
            rules: {
                terms: { field: 'rule.id', size: 100, order: { lvl: 'desc' } },
                aggs: {
                    lvl: { max: { field: 'rule.level' } },
                    sample: { top_hits: { size: 1, _source: ['rule.description', 'rule.groups', 'rule.mitre'] } },
                    src: {
                        terms: { field: 'data.srcip', size: 20, missing: NO_IP },
                        aggs: {
                            agents: {
                                terms: { field: 'agent.name', size: 20 },
                                aggs: { first: { min: { field: 'timestamp' } }, last: { max: { field: 'timestamp' } } },
                            },
                        },
                    },
                },
            },
        },
    });

    const out: Omit<Threat, 'status' | 'recurred' | 'assigned_to' | 'case_id' | 'case_number' | 'decided_at'>[] = [];
    for (const rule of r?.aggregations?.rules?.buckets ?? []) {
        const src = rule.sample?.hits?.hits?.[0]?._source?.rule ?? {};
        const level = Math.round(rule.lvl?.value ?? 7);
        const base = {
            name: src.description ?? `Wazuh rule ${rule.key}`,
            type: threatType(src.groups ?? [], src.description ?? '', src.mitre?.tactic?.[0] ?? null),
            source: 'Wazuh alert' as const,
            severity: severityFromLevel(level),
            rule_id: String(rule.key),
            rule_level: level,
            mitre_technique_id: src.mitre?.id?.[0] ?? null,
            mitre_technique: src.mitre?.technique?.[0] ?? null,
            mitre_tactic: src.mitre?.tactic?.[0] ?? null,
        };
        for (const ip of rule.src?.buckets ?? []) {
            const agents = ip.agents?.buckets ?? [];
            const span = (list: typeof agents) => ({
                first_seen: list.map((a) => a.first?.value_as_string ?? '').filter(Boolean).sort()[0] ?? '',
                last_seen: list.map((a) => a.last?.value_as_string ?? '').filter(Boolean).sort().at(-1) ?? '',
            });
            if (ip.key !== NO_IP) {
                // One threat per rule + source IP, spanning every agent it touched.
                out.push({ ...base, id: threatId(base.rule_id, `ip:${ip.key}`), source_ip: String(ip.key), assets: agents.map((a) => String(a.key)), alert_count: ip.doc_count, ...span(agents) });
            } else {
                // No IP: one threat per rule + agent.
                for (const a of agents) {
                    out.push({ ...base, id: threatId(base.rule_id, `agent:${a.key}`), source_ip: null, assets: [String(a.key)], alert_count: a.doc_count, ...span([a]) });
                }
            }
        }
    }
    return out.sort((a, b) => b.last_seen.localeCompare(a.last_seen));
}

// ── Triage store ─────────────────────────────────────────────────────────────────────────────

export async function readTriage(orgId: string): Promise<{ map: Map<string, Triage>; store: 'supabase' | 'memory' }> {
    const supabase = getSupabase();
    if (supabase) {
        const { data, error } = await supabase.from('threat_triage').select('*').eq('org_id', orgId);
        if (!error) return { map: new Map((data as Triage[]).map((t) => [t.threat_id, t])), store: 'supabase' };
        console.warn('[threats] threat_triage unavailable, using memory:', dbErrorMessage(error));
    }
    return { map: new Map([...memoryTriage].filter(([, t]) => t.org_id === orgId)), store: 'memory' };
}

export async function writeTriage(t: Triage): Promise<'supabase' | 'memory'> {
    const supabase = getSupabase();
    if (supabase) {
        const { error } = await supabase.from('threat_triage').upsert(t, { onConflict: 'threat_id' });
        if (!error) return 'supabase';
        console.warn('[threats] triage write failed, keeping in memory:', dbErrorMessage(error));
    }
    memoryTriage.set(t.threat_id, t);
    return 'memory';
}

export function applyTriage(t: Omit<Threat, 'status' | 'recurred' | 'assigned_to' | 'case_id' | 'case_number' | 'decided_at'>, tri: Triage | undefined): Threat {
    const derived: ThreatStatus = Date.parse(t.last_seen) >= Date.now() - 24 * 3600_000 ? 'active' : 'monitoring';
    // A decision stands until the threat fires again after it was made.
    const recurred = !!tri?.status && Date.parse(t.last_seen) > Date.parse(tri.updated_at);
    return {
        ...t,
        status: tri?.status && !recurred ? tri.status : derived,
        recurred,
        assigned_to: tri?.assigned_to ?? null,
        case_id: tri?.case_id ?? null,
        case_number: tri?.case_number ?? null,
        decided_at: tri?.status ? tri.updated_at : null,
    };
}
