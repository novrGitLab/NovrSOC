// R3.3E — unified report generation. Deliberately thin: every section below calls the SAME real,
// already-shipped, already-tested function the interactive report page calls — periodReport() for
// VMS, orgStats()/gaps()/coverageState()/loadTi() for CNII (the exact figures GET /api/cnii/profile
// already returns to an executive — nothing from the staff-only, unredacted cniiNational.ts
// routes), orgMetrics() for SecOps, and relevantIntel() for Threat Intelligence. This file adds
// no new query logic for any of those three; it only adds the small amount of TLP-aware
// aggregation threatInfo.ts's own /report route already does (reimplemented here rather than
// imported, to avoid refactoring that route's tested code for this release — see the R3.3E
// report's "known limitations" for why).
//
// TLP ceiling: every call here takes an explicit `ceiling` rather than reading it from a live
// request (there is no request — this runs from a scheduler or a "generate now" click that has
// already resolved its own viewer). Scheduled and emailed reports MUST pass 'amber' (the client
// ceiling) regardless of who ends up receiving them — see services/reportDelivery.ts — because an
// email leaves the platform's access-controlled UI the moment it's sent. Only an interactive
// "generate now" + immediate in-app view by a signed-in staff member may pass 'red'.

import { getSupabase } from './geoEnrichment';
import { periodReport } from './vmsContinuous';
import { orgStats, gaps as cniiGaps, type OrgStats } from '../routes/cnii';
import { loadTi } from '../routes/cniiNational';
import { coverageState } from '../lib/cniiCoverage';
import { orgMetrics } from './securityAssessment';
import { relevantIntel, type RelevantItem } from './threatInfo';
import { hasServiceAccess, type ServiceKey } from '../lib/serviceAccess';
import { TLP_ORDER, isTlp, type Tlp } from './tiPolicy';

export type ReportType = 'vms' | 'cnii' | 'threat_intel' | 'executive_summary';
export type ReportFormat = 'executive' | 'technical';

export interface GeneratedReport {
    org: string;
    org_name: string;
    report_type: ReportType;
    format: ReportFormat;
    period_days: number;
    generated_at: string;
    ceiling: Tlp;
    data: Record<string, unknown>;
    /** Sections that could not be produced (a disabled module, a missing table) — shown in the
     * report itself, never silently dropped. */
    warnings: string[];
}

const mayView = (tlp: unknown, ceiling: Tlp) => TLP_ORDER.indexOf(isTlp(tlp) ? tlp : 'amber') <= TLP_ORDER.indexOf(ceiling);

/** The same label-blanking threatInfo.ts's hideRestrictedLabels() applies to live indicator
 * routes, reimplemented against an explicit ceiling instead of a live request (see header). */
async function redactRelevantItems(items: RelevantItem[], ceiling: Tlp): Promise<RelevantItem[]> {
    if (ceiling === 'red' || !items.length) return items;
    const supabase = getSupabase();
    if (!supabase) return items;
    const ids = [...new Set(items.map((i) => i.indicator_id))];
    const byIndicator = new Map<string, Tlp[]>();
    for (let i = 0; i < ids.length; i += 300) {
        const { data } = await supabase.from('ti_indicator_sources').select('indicator_id, tlp').in('indicator_id', ids.slice(i, i + 300));
        for (const s of data ?? []) byIndicator.set(s.indicator_id as string, [...(byIndicator.get(s.indicator_id as string) ?? []), s.tlp as Tlp]);
    }
    return items.map((it) => {
        const tlps = byIndicator.get(it.indicator_id);
        if (!tlps || tlps.every((t) => mayView(t, ceiling))) return it;
        return { ...it, malware_families: [], threat_types: [] };
    });
}

async function orgName(org: string): Promise<string> {
    const supabase = getSupabase();
    if (!supabase) return org;
    const { data } = await supabase.from('organisations').select('name').eq('slug', org).maybeSingle();
    return (data?.name as string | undefined) ?? org;
}

async function vmsSection(org: string, days: number) {
    return periodReport(org, days);
}

async function cniiSection(org: string, ceiling: Tlp) {
    const stats = (await orgStats([org]))[org] as OrgStats;
    const { data: assetIds } = await getSupabase()!.from('vms_assets').select('id').eq('org_id', org).eq('status', 'active').limit(50_000);
    const ti = await loadTi((assetIds ?? []).map((a) => a.id as string));
    const rows = [...ti.tiByAsset.values()].flat();
    // Same minimisation /profile already applies to a client role: counts only, never the
    // indicator value, type or malware label — so there is nothing left to redact by ceiling here.
    void ceiling;
    const verified = rows.filter((m) => m.status === 'promoted' || !!m.case_id).length;
    return {
        stats,
        gaps: cniiGaps(stats),
        coverage_state: coverageState(stats),
        threat_intelligence: { total: rows.length, verified, contextual: rows.length - verified },
    };
}

const DAY = 86_400_000;
async function tiSection(org: string, days: number, ceiling: Tlp) {
    const supabase = getSupabase()!;
    const since = new Date(Date.now() - days * DAY).toISOString();
    const relevant = await relevantIntel(org);
    const topRaw = relevant.items.slice(0, 20);
    const top = await redactRelevantItems(topRaw, ceiling);
    const [activeCount, matchesAll, verifiedCount, kevRes] = await Promise.all([
        supabase.from('ti_indicators').select('id', { count: 'exact', head: true }).eq('status', 'active'),
        supabase.from('ti_matches').select('status').eq('org_id', org).neq('status', 'dismissed').limit(10_000),
        supabase.from('ti_matches').select('id', { count: 'exact', head: true }).eq('org_id', org).or('status.eq.promoted,case_id.not.is.null'),
        supabase.from('ti_indicators').select('id, value').eq('type', 'cve').gte('first_seen', since).limit(500),
    ]);
    const matchesByStatus: Record<string, number> = { new: 0, reviewed: 0, promoted: 0 };
    for (const m of matchesAll.data ?? []) matchesByStatus[m.status as string] = (matchesByStatus[m.status as string] ?? 0) + 1;
    const kevCves = (kevRes.data ?? []).map((d) => d.value as string);
    const kevFindings = kevCves.length
        ? await supabase.from('vms_findings').select('id, cve_ids').eq('org_id', org).overlaps('cve_ids', kevCves).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'])
        : { data: [] as { id: string; cve_ids: string[] }[] };
    return {
        period_days: days,
        indicators_active: activeCount.count ?? 0,
        matches: { total: (matchesAll.data ?? []).length, by_status: matchesByStatus, verified: verifiedCount.count ?? 0 },
        relevant: { by_tier: relevant.by_tier, top },
        kev: { new_in_period: kevCves.length, your_open_findings: (kevFindings.data ?? []).length },
    };
}

function secopsSection(m: Awaited<ReturnType<typeof orgMetrics>>) {
    // orgMetrics() already never fabricates detection time (always null) and keeps workload
    // (staff names) out of anything client-facing — this report never includes workload either.
    const { workload: _workload, ...rest } = m;
    return rest;
}

/** The single entry point every scheduled/manual report run calls. */
export async function generateReportData(org: string, type: ReportType, format: ReportFormat, periodDays: number, ceiling: Tlp): Promise<GeneratedReport> {
    const name = await orgName(org);
    const base = { org, org_name: name, report_type: type, format, period_days: periodDays, generated_at: new Date().toISOString(), ceiling };
    const warnings: string[] = [];

    if (type === 'vms') return { ...base, data: await vmsSection(org, periodDays), warnings };
    if (type === 'cnii') return { ...base, data: await cniiSection(org, ceiling), warnings };
    if (type === 'threat_intel') return { ...base, data: await tiSection(org, periodDays, ceiling), warnings };

    // executive_summary: only the sections this organisation actually has access to — never a
    // guess at data from a disabled module, and never a failure of the whole report because one
    // module isn't enabled.
    const data: Record<string, unknown> = {};
    const checks: [ServiceKey, string][] = [['vms', 'vms'], ['cnii_watch', 'cnii'], ['threat_intel', 'threat_intel']];
    for (const [service, key] of checks) {
        const allowed = await hasServiceAccess(org, service);
        if (!allowed) { warnings.push(`${key}: not available — this module is not enabled for this organisation.`); continue; }
        try {
            if (key === 'vms') data.vms = await vmsSection(org, periodDays);
            else if (key === 'cnii') data.cnii = await cniiSection(org, ceiling);
            else data.threat_intel = await tiSection(org, periodDays, ceiling);
        } catch (err) {
            warnings.push(`${key}: could not be generated — ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    try {
        data.secops = secopsSection(await orgMetrics(org, name));
    } catch (err) {
        warnings.push(`secops: could not be generated — ${err instanceof Error ? err.message : String(err)}`);
    }
    if (Object.keys(data).length === 0) warnings.push('No module produced data for this organisation — check its service entitlements.');
    return { ...base, data, warnings };
}
