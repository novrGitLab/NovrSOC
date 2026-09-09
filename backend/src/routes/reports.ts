import { Router } from 'express';
import { getAgentNamesForGroup } from '../lib/wazuh-group';
import { search } from '../lib/wazuh-indexer';
import { FRAMEWORKS } from '../lib/mock/compliance';

const router = Router();
import { CTIP_URL, isCTIPConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured } from '../lib/legacyBackend';

interface ReportRequestBody {
    orgId: number;
    orgName: string;
    wazuhGroup: string | null;
    month: string;
    period_start: string;
    period_end: string;
}

function countResult(res: Record<string, unknown> | null): number {
    const hits = res?.hits as { total?: { value?: number } } | undefined;
    return hits?.total?.value ?? 0;
}

// POST /api/reports/generate
router.post('/generate', async (req, res) => {
    const body = req.body as ReportRequestBody;
    const { orgId, orgName, wazuhGroup, month, period_start, period_end } = body ?? {};
    if (!orgId || !orgName || !month || !period_start || !period_end) {
        res.status(400).json({ error: 'orgId, orgName, month, period_start, and period_end are required' });
        return;
    }

    const agentNames = wazuhGroup ? await getAgentNamesForGroup(wazuhGroup) : null;
    const periodRange = { range: { timestamp: { gte: period_start, lte: period_end } } };
    const alertsMust: unknown[] = [periodRange];
    if (agentNames) alertsMust.push({ terms: { 'agent.name': agentNames } });
    const alertsQuery = { bool: { must: alertsMust } };

    const vulnQuery = agentNames ? { bool: { must: [{ terms: { 'agent.name': agentNames } }] } } : { match_all: {} };

    const [
        totalRes, criticalRes, highRes, mediumRes, topIncidentsRes, activeAssetsRes,
        dailyRes, vulnCountRes, vulnTopRes, ctipRes, vendorRes, scanRes, advisoriesRes,
    ] = await Promise.allSettled([
        search('wazuh-alerts-4.x-*', { size: 0, track_total_hits: true, query: alertsQuery }),
        search('wazuh-alerts-4.x-*', { size: 0, track_total_hits: true, query: { bool: { must: [...alertsMust, { range: { 'rule.level': { gte: 12 } } }] } } }),
        search('wazuh-alerts-4.x-*', { size: 0, track_total_hits: true, query: { bool: { must: [...alertsMust, { range: { 'rule.level': { gte: 10 } } }] } } }),
        search('wazuh-alerts-4.x-*', { size: 0, track_total_hits: true, query: { bool: { must: [...alertsMust, { range: { 'rule.level': { gte: 7, lte: 9 } } }] } } }),
        search('wazuh-alerts-4.x-*', {
            size: 0,
            query: alertsQuery,
            aggs: {
                top: {
                    terms: { field: 'rule.description', size: 5 },
                    aggs: { max_level: { max: { field: 'rule.level' } }, top_agent: { terms: { field: 'agent.name', size: 1 } } },
                },
            },
        }),
        search('wazuh-alerts-4.x-*', { size: 0, query: alertsQuery, aggs: { distinct_assets: { cardinality: { field: 'agent.name' } } } }),
        search('wazuh-alerts-4.x-*', {
            size: 0,
            query: alertsQuery,
            aggs: {
                per_day: {
                    date_histogram: { field: 'timestamp', calendar_interval: 'day', min_doc_count: 0 },
                    aggs: {
                        critical: { filter: { range: { 'rule.level': { gte: 12 } } } },
                        high: { filter: { range: { 'rule.level': { gte: 10, lt: 12 } } } },
                    },
                },
            },
        }),
        search('wazuh-states-vulnerabilities-*', { size: 0, track_total_hits: true, query: vulnQuery }),
        search('wazuh-states-vulnerabilities-*', {
            size: 10,
            sort: [{ 'vulnerability.score.base': { order: 'desc' } }],
            _source: ['vulnerability.id', 'vulnerability.severity', 'vulnerability.score.base', 'vulnerability.under_evaluation', 'package.name', 'package.version'],
            query: vulnQuery,
        }),
        fetch(`${CTIP_URL}/api/ctip/stats`, { cache: 'no-store', signal: AbortSignal.timeout(5000) }).then((r) => r.json()).catch(() => null),
        fetch(`${BACKEND_URL}/api/vendor-assessments?org_id=${orgId}`, { cache: 'no-store', signal: AbortSignal.timeout(5000) }).then((r) => r.json()).catch(() => null),
        fetch(`${BACKEND_URL}/api/scan-history?org_id=${orgId}`, { cache: 'no-store', signal: AbortSignal.timeout(5000) }).then((r) => r.json()).catch(() => null),
        fetch(`${BACKEND_URL}/api/advisories`, { cache: 'no-store', signal: AbortSignal.timeout(5000) }).then((r) => r.json()).catch(() => null),
    ]).then((results) => results.map((r) => (r.status === 'fulfilled' ? r.value : null))) as [
        Record<string, unknown> | null, Record<string, unknown> | null, Record<string, unknown> | null, Record<string, unknown> | null,
        Record<string, unknown> | null, Record<string, unknown> | null, Record<string, unknown> | null, Record<string, unknown> | null,
        Record<string, unknown> | null, unknown, unknown, unknown, unknown,
    ];

    type TopIncidentBucket = { key: string; doc_count: number; max_level?: { value?: number }; top_agent?: { buckets?: { key: string }[] } };
    const topIncidentBuckets = (topIncidentsRes?.aggregations as { top?: { buckets?: TopIncidentBucket[] } } | undefined)?.top?.buckets ?? [];
    const severityForLevel = (level: number) => (level >= 12 ? 'Critical' : level >= 10 ? 'High' : level >= 7 ? 'Medium' : 'Low');
    const top_incidents = topIncidentBuckets.map((b) => ({
        description: b.key,
        count: b.doc_count,
        severity: severityForLevel(b.max_level?.value ?? 0),
        agent: b.top_agent?.buckets?.[0]?.key ?? '—',
    }));

    const active_assets = (activeAssetsRes?.aggregations as { distinct_assets?: { value?: number } } | undefined)?.distinct_assets?.value ?? 0;

    type DailyBucket = { key_as_string?: string; doc_count: number; critical?: { doc_count?: number }; high?: { doc_count?: number } };
    const dailyBuckets = (dailyRes?.aggregations as { per_day?: { buckets?: DailyBucket[] } } | undefined)?.per_day?.buckets ?? [];
    const daily_alerts = dailyBuckets.map((b) => ({
        date: b.key_as_string ? new Date(b.key_as_string).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '—',
        count: b.doc_count,
        critical: b.critical?.doc_count ?? 0,
        high: b.high?.doc_count ?? 0,
    }));

    const vulnHits = (vulnTopRes?.hits as { hits?: { _source?: Record<string, unknown> }[] } | undefined)?.hits ?? [];
    const top_vulnerabilities = vulnHits.map((h) => {
        const v = h._source?.vulnerability as Record<string, unknown> | undefined;
        const pkg = h._source?.package as Record<string, unknown> | undefined;
        return {
            cve: (v?.id as string) ?? '',
            severity: (v?.severity as string) ?? '',
            cvss_score: ((v?.score as Record<string, unknown> | undefined)?.base as number) ?? null,
            package: pkg?.name ? `${pkg.name as string} ${(pkg.version as string) ?? ''}`.trim() : '',
            status: v?.under_evaluation ? 'Under Evaluation' : 'Confirmed',
        };
    });

    const ctipStats = ctipRes as { total_iocs?: number; active_campaigns?: number; exploitable_cves_this_week?: number } | null;

    const report = {
        orgId,
        orgName,
        wazuhGroup: wazuhGroup ?? null,
        month,
        period_start,
        period_end,
        generated_at: new Date().toISOString(),
        wazuh: {
            total_alerts: countResult(totalRes),
            critical_alerts: countResult(criticalRes),
            high_alerts: countResult(highRes),
            medium_alerts: countResult(mediumRes),
            top_incidents,
            active_assets,
            vulnerability_count: countResult(vulnCountRes),
            daily_alerts,
            top_vulnerabilities,
        },
        ctip: {
            total_iocs: ctipStats?.total_iocs ?? 0,
            active_campaigns: ctipStats?.active_campaigns ?? 0,
            exploitable_cves: ctipStats?.exploitable_cves_this_week ?? 0,
        },
        postgres: {
            vendor_assessments: Array.isArray((vendorRes as { assessments?: unknown[] } | null)?.assessments)
                ? (vendorRes as { assessments: unknown[] }).assessments.length
                : 0,
            scans_performed: Array.isArray((scanRes as { scans?: unknown[] } | null)?.scans)
                ? (scanRes as { scans: unknown[] }).scans.length
                : 0,
            advisories_count: Array.isArray((advisoriesRes as { advisories?: unknown[] } | null)?.advisories)
                ? (advisoriesRes as { advisories: unknown[] }).advisories.length
                : 0,
        },
        compliance: FRAMEWORKS,
    };

    // Best-effort: persist to report history via the backend service. The backend
    // does not yet expose this endpoint (see report for details) — failures here
    // must never block returning the report data to the client.
    fetch(`${BACKEND_URL}/api/report-history`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id: orgId, period: month, generated_by: 'portal', data_json: report }),
        signal: AbortSignal.timeout(5000),
    }).catch(() => {});

    res.json(report);
});

export default router;
