'use client';

// Executive Risk Dashboard (brief §2). Every number here comes from the already-fetched findings
// list or the report API's own counts — nothing is computed from an assumption, and the overall
// risk rating cites the platform's one existing, documented scoring formula (lib/riskScore.ts)
// rather than inventing a second one.
import { KpiCard, SEVERITY_META, riskColor } from '../kit';
import { severityCounts, cvssDistribution, meanRiskScore, riskBand, affectedAssetCount, remediationStatusCounts, type SeverityCounts } from './reportHelpers';

interface FindingLite { scanner_severity: string | null; scanner_cvss: number | null; risk_score: number | null; asset_value: string; status: string; due_at: string | null; cve_ids: string[] }

export function RiskDashboard({ findings, totalUniqueVulnerabilities, trendSummary }: { findings: FindingLite[]; totalUniqueVulnerabilities: number; trendSummary: string | null }) {
    const sev = severityCounts(findings);
    const dist = cvssDistribution(findings);
    const mean = meanRiskScore(findings);
    const band = riskBand(mean);
    const affected = affectedAssetCount(findings);
    const remediation = remediationStatusCounts(findings);
    const maxBand = Math.max(1, ...dist.bands.map((b) => b.count));

    return (
        <div className="space-y-4">
            <h2 className="text-sm font-black text-foreground">Executive Risk Dashboard</h2>

            <div className="bg-card border border-border rounded-2xl vms-print-card p-4 flex flex-wrap items-center gap-6">
                <div>
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Overall Risk Rating</p>
                    <p className="text-2xl font-black text-foreground" style={{ color: mean !== null ? riskColor(mean) : undefined }}>{band}{mean !== null && <span className="text-sm font-bold text-foreground-muted ml-2">({mean}/100)</span>}</p>
                </div>
                <p className="text-[11px] text-foreground-muted max-w-md">
                    Mean of each currently-open finding&apos;s risk score — 45% technical severity (CVSS or scanner
                    severity), 30% exploitation likelihood (CISA KEV / EPSS), 15% exposure, 10% asset criticality.
                    Full per-finding breakdown: Vulnerability Management → Risk.
                </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <KpiCard label="Total unique vulnerabilities" value={totalUniqueVulnerabilities} />
                <KpiCard label="Affected hosts/assets" value={affected} />
                <KpiCard label="Critical findings" value={sev.critical} tone={sev.critical > 0 ? 'critical' : 'good'} />
                <KpiCard label="High findings" value={sev.high} tone={sev.high > 0 ? 'serious' : 'good'} />
                <KpiCard label="Overdue remediation" value={remediation.overdue} tone={remediation.overdue > 0 ? 'warning' : 'good'} />
            </div>

            <div className="bg-card border border-border rounded-2xl vms-print-card p-4">
                <p className="text-xs font-bold text-foreground mb-3">Findings by Severity</p>
                <div className="flex items-end gap-3 h-24">
                    {(Object.keys(sev) as (keyof SeverityCounts)[]).map((k) => (
                        <div key={k} className="flex flex-col items-center gap-1 flex-1">
                            <span className="text-[11px] font-black text-foreground">{sev[k]}</span>
                            <div className="w-full rounded-t-md" style={{ height: `${Math.max(4, (sev[k] / Math.max(1, ...Object.values(sev))) * 72)}px`, background: SEVERITY_META[k]?.color }} />
                            <span className="text-[9px] text-foreground-muted uppercase">{SEVERITY_META[k]?.label ?? k}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="bg-card border border-border rounded-2xl vms-print-card p-4">
                <p className="text-xs font-bold text-foreground mb-1">CVSS Score Distribution</p>
                <p className="text-[10px] text-foreground-muted mb-3">{dist.noCvss} finding(s) carry no CVSS score and are not included in the bars below.</p>
                <div className="flex items-end gap-1.5 h-20">
                    {dist.bands.map((b) => (
                        <div key={b.score} className="flex flex-col items-center gap-1 flex-1">
                            <span className="text-[9px] font-bold text-foreground-muted">{b.count || ''}</span>
                            <div className="w-full rounded-t-sm bg-purple/60" style={{ height: `${Math.max(2, (b.count / maxBand) * 56)}px` }} />
                            <span className="text-[8px] text-foreground-muted">{b.score}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="bg-card border border-border rounded-2xl vms-print-card p-4 text-xs">
                <p className="font-bold text-foreground mb-2">Remediation Status</p>
                <p className="text-foreground-muted">
                    {remediation.open} open · {remediation.in_progress} in progress · {remediation.fixed_pending_verification} awaiting verification ·
                    {' '}{remediation.verified} verified fixed · {remediation.risk_accepted} risk accepted
                    {remediation.overdue > 0 && <span className="text-amber font-bold"> · {remediation.overdue} overdue</span>}
                </p>
            </div>

            {trendSummary && (
                <div className="bg-card border border-border rounded-2xl vms-print-card p-4 text-xs">
                    <p className="font-bold text-foreground mb-1">Risk Trend</p>
                    <p className="text-foreground-muted">{trendSummary}</p>
                </div>
            )}
        </div>
    );
}
