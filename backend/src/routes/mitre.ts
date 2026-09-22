import { Router } from 'express';
import type { Request, Response } from 'express';
import { search } from '../lib/wazuh-indexer';
import { isConfigured as wazuhConfigured } from '../services/wazuh';
import { getSupabase } from '../services/geoEnrichment';

// MITRE ATT&CK and D3FEND.
//
// FIELD NAMING — the single most important thing in this file. Wazuh splits MITRE metadata
// across three fields and they are NOT interchangeable:
//
//     rule.mitre.id         -> technique IDs      e.g. "T1055"      <- this is what we key on
//     rule.mitre.technique  -> technique NAMES    e.g. "Process Injection"
//     rule.mitre.tactic     -> tactic names       e.g. "Defense Evasion"
//
// Aggregating on rule.mitre.technique (as is tempting, given the name) yields human-readable
// names, which then fail to match anything keyed by ID — the D3FEND map below, and the
// attack.mitre.org/techniques/<id>/ links in the UI. Confirmed live on this deployment:
// rule.mitre.id returns "T1055" while rule.mitre.tactic returns "Defense Evasion".
//
// The technique name is still useful, so it comes along as a sub-aggregation rather than being
// the thing we group by.

const router = Router();

const RANGE_HOURS: Record<string, number> = {
    '1h': 1, '6h': 6, '12h': 12, '24h': 24, '7d': 168, '30d': 720,
};

// Wazuh rule levels, per its own documentation.
const SEVERITY_LEVELS: Record<string, number[]> = {
    critical: [13, 14, 15],
    high: [10, 11, 12],
    medium: [7, 8, 9],
    low: [1, 2, 3, 4, 5, 6],
};

function severityForLevel(level: number): 'critical' | 'high' | 'medium' | 'low' {
    if (level >= 13) return 'critical';
    if (level >= 10) return 'high';
    if (level >= 7) return 'medium';
    return 'low';
}

interface TermBucket { key: string; doc_count: number }
interface TechniqueBucket {
    key: string;
    doc_count: number;
    technique_names?: { buckets?: TermBucket[] };
    tactics?: { buckets?: TermBucket[] };
    agents?: { buckets?: TermBucket[] };
    max_level?: { value?: number };
    rules?: { buckets?: TermBucket[] };
    latest_alert?: { hits?: { hits?: Array<{ _source?: unknown }> } };
}
interface TacticBucket extends TermBucket { technique_count?: { value?: number } }
interface TimelineBucket { key_as_string?: string; doc_count: number; techniques?: { value?: number } }

interface TechniquesResponse {
    aggregations?: {
        techniques?: { buckets?: TechniqueBucket[] };
        tactics_summary?: { buckets?: TacticBucket[] };
        agents_summary?: { buckets?: TacticBucket[] };
        timeline?: { buckets?: TimelineBucket[] };
    };
}

export interface DetectedTechnique {
    technique_id: string;
    technique_name: string;
    count: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
    max_level: number;
    tactics: string[];
    agents: Array<{ name: string; count: number }>;
    top_rules: string[];
    latest_alert: unknown;
}

export interface TechniquesResult {
    techniques: DetectedTechnique[];
    tactics_summary: Array<{ tactic: string; technique_count: number; alert_count: number }>;
    agents_summary: Array<{ agent: string; technique_count: number; alert_count: number }>;
    timeline: Array<{ time: string; alert_count: number; technique_count: number }>;
    total_techniques: number;
    total_alerts: number;
    range: string;
    since: string;
    error?: string;
}

/**
 * Shared so GET /defend can reuse it directly. The alternative — /defend making an HTTP request
 * back to this same server on localhost:PORT and forwarding the caller's Authorization header —
 * would add a network hop, assume the port, and break the moment the app sits behind a proxy
 * that terminates differently (which Railway does).
 */
export async function collectTechniques(params: {
    range?: string; agentId?: string; tactic?: string; severity?: string;
}): Promise<TechniquesResult> {
    const range = params.range && RANGE_HOURS[params.range] ? params.range : '24h';
    const hours = RANGE_HOURS[range];
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);

    const empty: TechniquesResult = {
        techniques: [], tactics_summary: [], agents_summary: [], timeline: [],
        total_techniques: 0, total_alerts: 0, range, since: since.toISOString(),
    };

    const must: Record<string, unknown>[] = [
        // Existence is checked on the ID field, since that is what everything downstream keys on.
        { exists: { field: 'rule.mitre.id' } },
        { range: { timestamp: { gte: since.toISOString() } } },
    ];

    if (params.agentId && params.agentId !== 'all') {
        must.push({ term: { 'agent.id': String(params.agentId).padStart(3, '0') } });
    }
    if (params.tactic && params.tactic !== 'all') {
        must.push({ term: { 'rule.mitre.tactic': params.tactic } });
    }
    if (params.severity && params.severity !== 'all' && SEVERITY_LEVELS[params.severity]) {
        must.push({ terms: { 'rule.level': SEVERITY_LEVELS[params.severity] } });
    }

    // An hourly histogram over 30 days would return 720 buckets for a sparkline; switch to daily
    // past the 24h mark.
    const interval = hours <= 24 ? 'hour' : 'day';

    try {
        const result = await search<TechniquesResponse>('wazuh-alerts-4.x-*', {
            size: 0,
            query: { bool: { must } },
            aggs: {
                techniques: {
                    terms: { field: 'rule.mitre.id', size: 100 },
                    aggs: {
                        technique_names: { terms: { field: 'rule.mitre.technique', size: 1 } },
                        tactics: { terms: { field: 'rule.mitre.tactic', size: 10 } },
                        agents: { terms: { field: 'agent.name', size: 20 } },
                        max_level: { max: { field: 'rule.level' } },
                        rules: { terms: { field: 'rule.description', size: 5 } },
                        latest_alert: {
                            top_hits: {
                                size: 1,
                                sort: [{ timestamp: { order: 'desc' } }],
                                _source: ['timestamp', 'agent.name', 'rule.description', 'rule.level'],
                            },
                        },
                    },
                },
                tactics_summary: {
                    terms: { field: 'rule.mitre.tactic', size: 20 },
                    aggs: { technique_count: { cardinality: { field: 'rule.mitre.id' } } },
                },
                agents_summary: {
                    terms: { field: 'agent.name', size: 20 },
                    aggs: { technique_count: { cardinality: { field: 'rule.mitre.id' } } },
                },
                timeline: {
                    date_histogram: { field: 'timestamp', calendar_interval: interval },
                    aggs: { techniques: { cardinality: { field: 'rule.mitre.id' } } },
                },
            },
        });

        const buckets = result?.aggregations?.techniques?.buckets ?? [];

        const techniques: DetectedTechnique[] = buckets.map((b) => {
            const maxLevel = Math.round(b.max_level?.value ?? 0);
            return {
                technique_id: b.key,
                technique_name: b.technique_names?.buckets?.[0]?.key ?? b.key,
                count: b.doc_count,
                severity: severityForLevel(maxLevel),
                max_level: maxLevel,
                tactics: (b.tactics?.buckets ?? []).map((t) => t.key),
                agents: (b.agents?.buckets ?? []).map((a) => ({ name: a.key, count: a.doc_count })),
                top_rules: (b.rules?.buckets ?? []).map((r) => r.key),
                latest_alert: b.latest_alert?.hits?.hits?.[0]?._source ?? null,
            };
        }).sort((a, b) => b.count - a.count);

        return {
            techniques,
            tactics_summary: (result?.aggregations?.tactics_summary?.buckets ?? []).map((b) => ({
                tactic: b.key, technique_count: b.technique_count?.value ?? 0, alert_count: b.doc_count,
            })),
            agents_summary: (result?.aggregations?.agents_summary?.buckets ?? []).map((b) => ({
                agent: b.key, technique_count: b.technique_count?.value ?? 0, alert_count: b.doc_count,
            })),
            timeline: (result?.aggregations?.timeline?.buckets ?? []).map((b) => ({
                time: b.key_as_string ?? '', alert_count: b.doc_count, technique_count: b.techniques?.value ?? 0,
            })),
            total_techniques: techniques.length,
            total_alerts: buckets.reduce((s, b) => s + b.doc_count, 0),
            range,
            since: since.toISOString(),
        };
    } catch (err) {
        console.error('[MITRE] techniques query failed:', err instanceof Error ? err.message : err);
        // 200 with an explicit error rather than a 500: the page renders filters, tabs and the
        // D3FEND view around this, and none of those should disappear because the indexer blipped.
        return { ...empty, error: 'Wazuh indexer unreachable' };
    }
}

// GET /api/mitre/techniques
router.get('/techniques', async (req: Request, res: Response) => {
    const result = await collectTechniques({
        range: typeof req.query.range === 'string' ? req.query.range : undefined,
        agentId: typeof req.query.agent_id === 'string' ? req.query.agent_id : undefined,
        tactic: typeof req.query.tactic === 'string' ? req.query.tactic : undefined,
        severity: typeof req.query.severity === 'string' ? req.query.severity : undefined,
    });
    res.json(result);
});

// GET /api/mitre/technique/:id — recent alerts for one technique.
router.get('/technique/:id', async (req: Request, res: Response) => {
    const { id } = req.params;
    const range = typeof req.query.range === 'string' && RANGE_HOURS[req.query.range] ? req.query.range : '7d';
    const since = new Date(Date.now() - RANGE_HOURS[range] * 60 * 60 * 1000);

    interface AlertHit {
        _source?: {
            timestamp?: string;
            agent?: { name?: string; id?: string };
            rule?: { description?: string; level?: number; mitre?: { id?: string[]; tactic?: string[]; technique?: string[] } };
            data?: { srcip?: string; dstip?: string };
        };
    }
    interface DetailResponse {
        hits?: { hits?: AlertHit[]; total?: { value?: number } };
        aggregations?: {
            agents?: { buckets?: TermBucket[] };
            rules?: { buckets?: TermBucket[] };
            daily?: { buckets?: TimelineBucket[] };
        };
    }

    try {
        const result = await search<DetailResponse>('wazuh-alerts-4.x-*', {
            size: 10,
            query: {
                bool: {
                    must: [
                        { term: { 'rule.mitre.id': id } },
                        { range: { timestamp: { gte: since.toISOString() } } },
                    ],
                },
            },
            sort: [{ timestamp: { order: 'desc' } }],
            _source: ['timestamp', 'agent.name', 'agent.id', 'rule.description', 'rule.level', 'rule.mitre', 'data.srcip', 'data.dstip'],
            aggs: {
                agents: { terms: { field: 'agent.name', size: 10 } },
                rules: { terms: { field: 'rule.description', size: 10 } },
                daily: { date_histogram: { field: 'timestamp', calendar_interval: 'day' } },
            },
        });

        // Flattened here rather than in the browser so the UI isn't guessing between
        // `a['agent.name']` and `a.agent?.name` depending on how the index stored it.
        const alerts = (result?.hits?.hits ?? []).map((h) => ({
            timestamp: h._source?.timestamp ?? '',
            agent_name: h._source?.agent?.name ?? 'Unknown',
            agent_id: h._source?.agent?.id ?? '',
            description: h._source?.rule?.description ?? '',
            level: h._source?.rule?.level ?? 0,
            severity: severityForLevel(h._source?.rule?.level ?? 0),
            source_ip: h._source?.data?.srcip ?? null,
        }));

        res.json({
            technique_id: id,
            alerts,
            total: result?.hits?.total?.value ?? alerts.length,
            agents: (result?.aggregations?.agents?.buckets ?? []).map((b) => ({ name: b.key, count: b.doc_count })),
            rules: (result?.aggregations?.rules?.buckets ?? []).map((b) => ({ name: b.key, count: b.doc_count })),
            daily: (result?.aggregations?.daily?.buckets ?? []).map((b) => ({ time: b.key_as_string ?? '', count: b.doc_count })),
            range,
        });
    } catch (err) {
        console.error('[MITRE] technique detail failed:', err instanceof Error ? err.message : err);
        res.json({ technique_id: id, alerts: [], total: 0, agents: [], rules: [], daily: [], error: 'Wazuh indexer unreachable' });
    }
});

// ── D3FEND ───────────────────────────────────────────────────────────────────────────
//
// Countermeasure status is a TRI-STATE, not a boolean, and that is deliberate.
//
// A hardcoded `implemented: true/false` per countermeasure is an assertion about this
// deployment's real defensive posture, and a coverage percentage computed from those assertions
// is the kind of number a CISO acts on. Several would have been plainly wrong: claiming D3-BAK
// (Backup) is implemented when Data Continuity shows no backup agent has ever reported would
// tell someone their ransomware countermeasure is in place when it is not.
//
// So: anything derivable from real platform state is derived (see resolveStatus below), and
// everything else reports 'unknown' rather than a confident false. 'unknown' is excluded from
// the score entirely, and the response reports how many were excluded — a 60% score over 10
// verifiable controls is meaningful; 60% over 10 guesses is not.

type CmStatus = 'implemented' | 'not_implemented' | 'unknown';

interface Countermeasure {
    id: string;
    name: string;
    description: string;
    /** Which real platform signal decides this, or null when nothing can decide it. */
    signal: 'wazuh_detection' | 'backup_reporting' | null;
}

const D3FEND_MAP: Record<string, { technique: string; countermeasures: Countermeasure[] }> = {
    T1078: {
        technique: 'Valid Accounts',
        countermeasures: [
            { id: 'D3-MFA', name: 'Multi-Factor Authentication', description: 'Require MFA for all accounts.', signal: null },
            { id: 'D3-UAM', name: 'User Account Management', description: 'Review and restrict account privileges.', signal: null },
            { id: 'D3-ANAA', name: 'Authentication Log Analysis', description: 'Monitor for unusual login patterns.', signal: 'wazuh_detection' },
        ],
    },
    T1566: {
        technique: 'Phishing',
        countermeasures: [
            { id: 'D3-HDPI', name: 'Homoglyph Detection', description: 'Detect lookalike domains used in phishing.', signal: null },
            { id: 'D3-SRA', name: 'Sender Reputation Analysis', description: 'Evaluate sender reputation before delivery.', signal: null },
            { id: 'D3-UA', name: 'URL Analysis', description: 'Analyse URLs in messages before delivery.', signal: null },
        ],
    },
    T1110: {
        technique: 'Brute Force',
        countermeasures: [
            { id: 'D3-AL', name: 'Account Locking', description: 'Lock accounts after repeated failures.', signal: null },
            { id: 'D3-MFA', name: 'Multi-Factor Authentication', description: 'Blunt credential stuffing with a second factor.', signal: null },
            { id: 'D3-NTA', name: 'Network Traffic Analysis', description: 'Detect brute-force patterns in traffic.', signal: 'wazuh_detection' },
        ],
    },
    T1046: {
        technique: 'Network Service Discovery',
        countermeasures: [
            { id: 'D3-NTA', name: 'Network Traffic Analysis', description: 'Detect scanning activity.', signal: 'wazuh_detection' },
            { id: 'D3-ITF', name: 'Inbound Traffic Filtering', description: 'Block unused ports at the perimeter.', signal: null },
        ],
    },
    T1055: {
        technique: 'Process Injection',
        countermeasures: [
            { id: 'D3-PSEP', name: 'Process Segment Execution Prevention', description: 'Prevent execution from injected memory segments.', signal: null },
            { id: 'D3-PA', name: 'Process Analysis', description: 'Monitor processes for injection indicators.', signal: 'wazuh_detection' },
            { id: 'D3-PCSV', name: 'Process Code Segment Verification', description: 'Verify process code integrity.', signal: null },
        ],
    },
    T1059: {
        technique: 'Command and Scripting Interpreter',
        countermeasures: [
            { id: 'D3-SEA', name: 'Script Execution Analysis', description: 'Monitor and analyse script execution.', signal: 'wazuh_detection' },
            { id: 'D3-EAL', name: 'Executable Allowlisting', description: 'Only allow approved executables to run.', signal: null },
            { id: 'D3-PSA', name: 'Process Spawn Analysis', description: 'Detect unusual process spawning.', signal: 'wazuh_detection' },
        ],
    },
    T1021: {
        technique: 'Remote Services',
        countermeasures: [
            { id: 'D3-MFA', name: 'Multi-Factor Authentication', description: 'Require MFA for remote access.', signal: null },
            { id: 'D3-NTA', name: 'Network Traffic Analysis', description: 'Monitor remote service connections.', signal: 'wazuh_detection' },
        ],
    },
    T1486: {
        technique: 'Data Encrypted for Impact',
        countermeasures: [
            { id: 'D3-BDI', name: 'Backup and Disaster Recovery', description: 'Maintain restorable offline backups.', signal: 'backup_reporting' },
            { id: 'D3-FAPA', name: 'File Access Pattern Analysis', description: 'Detect mass file encryption.', signal: null },
            { id: 'D3-NI', name: 'Network Isolation', description: 'Isolate affected systems automatically.', signal: null },
        ],
    },
    T1190: {
        technique: 'Exploit Public-Facing Application',
        countermeasures: [
            { id: 'D3-ITF', name: 'Inbound Traffic Filtering', description: 'Filter malicious web requests.', signal: null },
            { id: 'D3-SU', name: 'Software Update', description: 'Keep public-facing applications patched.', signal: null },
            { id: 'D3-AVS', name: 'Application Vulnerability Scanning', description: 'Scan regularly for known vulnerabilities.', signal: null },
        ],
    },
    T1112: {
        technique: 'Modify Registry',
        countermeasures: [
            { id: 'D3-SFA', name: 'System File Analysis', description: 'Monitor registry and system file changes.', signal: 'wazuh_detection' },
            { id: 'D3-EAL', name: 'Executable Allowlisting', description: 'Restrict what may modify protected keys.', signal: null },
        ],
    },
    T1053: {
        technique: 'Scheduled Task/Job',
        countermeasures: [
            { id: 'D3-SJA', name: 'Scheduled Job Analysis', description: 'Monitor creation of scheduled tasks.', signal: 'wazuh_detection' },
            { id: 'D3-PA', name: 'Process Analysis', description: 'Watch what scheduled jobs execute.', signal: 'wazuh_detection' },
        ],
    },
};

/** Whether a real backup agent has ever reported — decides D3-BDI honestly. */
async function backupsAreReporting(): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    try {
        const { data, error } = await supabase
            .from('backup_jobs').select('status').eq('status', 'success').limit(1);
        if (error) return false;
        return (data?.length ?? 0) > 0;
    } catch {
        return false;
    }
}

// GET /api/mitre/defend
router.get('/defend', async (req: Request, res: Response) => {
    const range = typeof req.query.range === 'string' ? req.query.range : '7d';

    const detected = await collectTechniques({ range });
    const detectedIds = detected.techniques.map((t) => t.technique_id);

    // Signals. Wazuh detecting a technique is genuine evidence that the corresponding
    // detection-type countermeasure is running — that is precisely what produced the alert.
    const wazuhRunning = wazuhConfigured() && detected.techniques.length > 0;
    const backupsOk = await backupsAreReporting();

    const resolveStatus = (cm: Countermeasure): { status: CmStatus; basis: string } => {
        if (cm.signal === 'wazuh_detection') {
            return wazuhRunning
                ? { status: 'implemented', basis: 'Wazuh is generating detections for this technique.' }
                : { status: 'unknown', basis: 'No Wazuh detections in this window to confirm from.' };
        }
        if (cm.signal === 'backup_reporting') {
            return backupsOk
                ? { status: 'implemented', basis: 'A backup agent has reported a successful run.' }
                : { status: 'not_implemented', basis: 'No backup agent has reported a successful run (see Data Continuity).' };
        }
        return { status: 'unknown', basis: 'NovrSOC has no signal for this control — assess manually.' };
    };

    const coverage = detectedIds
        .filter((id) => D3FEND_MAP[id])
        .map((id) => {
            const mapping = D3FEND_MAP[id];
            const countermeasures = mapping.countermeasures.map((cm) => {
                const { status, basis } = resolveStatus(cm);
                return { id: cm.id, name: cm.name, description: cm.description, status, basis };
            });
            const verifiable = countermeasures.filter((c) => c.status !== 'unknown');
            const implemented = countermeasures.filter((c) => c.status === 'implemented').length;
            return {
                attack_technique: id,
                technique_name: mapping.technique,
                countermeasures,
                // Scored over verifiable controls only; null when none can be verified, so the
                // UI shows "not assessable" rather than a misleading 0%.
                coverage_score: verifiable.length > 0 ? Math.round((implemented / verifiable.length) * 100) : null,
                implemented_count: implemented,
                verifiable_count: verifiable.length,
                unknown_count: countermeasures.length - verifiable.length,
                total_count: countermeasures.length,
            };
        });

    const allCms = coverage.flatMap((c) => c.countermeasures);
    const verifiable = allCms.filter((c) => c.status !== 'unknown');
    const implemented = allCms.filter((c) => c.status === 'implemented').length;

    res.json({
        coverage,
        uncovered_techniques: detectedIds.filter((id) => !D3FEND_MAP[id]),
        overall_score: verifiable.length > 0 ? Math.round((implemented / verifiable.length) * 100) : null,
        detected_count: detectedIds.length,
        covered_count: coverage.length,
        verifiable_count: verifiable.length,
        unknown_count: allCms.length - verifiable.length,
        range,
        scoring_note: 'Scored over countermeasures NovrSOC can verify from platform state. Controls it has no signal for are reported as unknown and excluded rather than assumed absent.',
        ...(detected.error && { error: detected.error }),
    });
});

export default router;
