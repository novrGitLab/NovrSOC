// R3.3E — server-side CSV generation for scheduled/downloaded reports. A direct, pure-function
// port of frontend/src/lib/vmsFormat.ts's toCsv() (same quoting and formula-injection
// neutralisation) — no new dependency, since CSV is just text. The frontend's own download
// buttons stay exactly as they are; this only gives the scheduler and the download route
// something to generate without a browser.

import type { GeneratedReport } from './reportGeneration';

export function toCsv(rows: Record<string, unknown>[], columns: { key: string; header: string }[]): string {
    const cell = (v: unknown) => {
        let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join('; ') : typeof v === 'object' ? JSON.stringify(v) : String(v);
        if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
        return `"${s.replace(/"/g, '""')}"`;
    };
    return [columns.map((c) => cell(c.header)).join(','), ...rows.map((r) => columns.map((c) => cell(r[c.key])).join(','))].join('\r\n');
}

/** The one table each report type is most useful as a CSV of — matching what each report page's
 * own ExportCsvButton already exports today (VmsReport's top_open findings, TiReport's relevant
 * matches). CNII and the executive summary export their headline figures as a single-row table,
 * since neither has an existing per-row CSV export to mirror. */
export function reportToCsv(report: GeneratedReport): string {
    const d = report.data;
    if (report.report_type === 'vms') {
        const rows = (d.top_open as Record<string, unknown>[] | undefined) ?? [];
        return toCsv(rows, [
            { key: 'priority', header: 'Priority' }, { key: 'severity', header: 'Severity' }, { key: 'title', header: 'Title' },
            { key: 'asset', header: 'Asset' }, { key: 'cve_ids', header: 'CVE IDs' }, { key: 'cvss', header: 'CVSS' },
            { key: 'known_exploited', header: 'Known Exploited' }, { key: 'status', header: 'Status' }, { key: 'due_at', header: 'Due' },
        ]);
    }
    if (report.report_type === 'threat_intel') {
        const relevant = d.relevant as { top?: Record<string, unknown>[] } | undefined;
        return toCsv(relevant?.top ?? [], [
            { key: 'tier', header: 'Tier' }, { key: 'indicator_type', header: 'Type' }, { key: 'indicator_value', header: 'Value' },
            { key: 'entity_type', header: 'Matched' }, { key: 'verified', header: 'Verified' }, { key: 'kev', header: 'KEV' },
            { key: 'asset_criticality', header: 'Asset criticality' }, { key: 'confidence', header: 'Confidence' }, { key: 'last_matched_at', header: 'Last matched' },
        ]);
    }
    if (report.report_type === 'cnii') {
        const stats = (d.stats ?? {}) as Record<string, unknown>;
        const open = (stats.open_findings ?? {}) as Record<string, unknown>;
        return toCsv([{
            assets: stats.assets, internet_facing: stats.internet_facing, p1: open.P1, p2: open.P2, p3: open.P3, p4: open.P4,
            kev_open: stats.kev_open, active_scopes: stats.active_scopes, coverage_state: d.coverage_state, gaps: (d.gaps as string[] | undefined)?.join('; '),
        }], [
            { key: 'assets', header: 'Assets' }, { key: 'internet_facing', header: 'Internet-facing' },
            { key: 'p1', header: 'Open P1' }, { key: 'p2', header: 'Open P2' }, { key: 'p3', header: 'Open P3' }, { key: 'p4', header: 'Open P4' },
            { key: 'kev_open', header: 'KEV open' }, { key: 'active_scopes', header: 'Active scopes' },
            { key: 'coverage_state', header: 'Coverage state' }, { key: 'gaps', header: 'Gaps' },
        ]);
    }
    // executive_summary: one row per module that actually produced data, plus the warnings.
    const rows = Object.entries(d).map(([module, value]) => ({ module, summary: JSON.stringify(value).slice(0, 500) }));
    return toCsv(rows, [{ key: 'module', header: 'Module' }, { key: 'summary', header: 'Summary (JSON, truncated)' }]);
}
