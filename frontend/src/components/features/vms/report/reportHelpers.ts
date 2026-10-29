// Pure helpers for the Vulnerability Management report (/admin/vms/report). Kept side-effect-free
// and framework-free so they're directly unit-testable (frontend/scripts/vmsReport.test.mjs) —
// no DOM, no fetch, no React.

export interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number }

/** Counts findings by scanner_severity — never invents a bucket a finding doesn't have. */
export function severityCounts(findings: { scanner_severity: string | null }[]): SeverityCounts {
    const out: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
        const s = f.scanner_severity as keyof SeverityCounts | null;
        if (s && s in out) out[s]++;
    }
    return out;
}

/** Buckets findings by whole-number CVSS score (0-10) for a distribution chart. Findings with no
 * CVSS at all are counted separately and never folded into band 0, which is a real score. */
export interface CvssDistribution { bands: { score: number; count: number }[]; noCvss: number }
export function cvssDistribution(findings: { scanner_cvss: number | null }[]): CvssDistribution {
    const bands = Array.from({ length: 11 }, (_, score) => ({ score, count: 0 }));
    let noCvss = 0;
    for (const f of findings) {
        if (f.scanner_cvss === null || f.scanner_cvss === undefined) { noCvss++; continue; }
        const band = Math.min(10, Math.max(0, Math.round(f.scanner_cvss)));
        bands[band].count++;
    }
    return { bands, noCvss };
}

export type RiskBand = 'Critical' | 'High' | 'Medium' | 'Low' | 'Minimal' | 'Not available';

/** Bands a mean 0-100 risk score (lib/riskScore.ts's documented formula) into a label. Thresholds
 * mirror that formula's own P1/P2/P3 cutoffs (80/60/35) so the report's language matches the
 * platform's existing priority bands rather than inventing a second scale. */
export function riskBand(meanScore: number | null): RiskBand {
    if (meanScore === null) return 'Not available';
    if (meanScore >= 80) return 'Critical';
    if (meanScore >= 60) return 'High';
    if (meanScore >= 35) return 'Medium';
    if (meanScore > 0) return 'Low';
    return 'Minimal';
}

/** Mean risk_score across open findings that have one computed; null when none do (never 0, which
 * would misreport "no risk" as a measured fact rather than "nothing to average"). */
export function meanRiskScore(findings: { risk_score: number | null }[]): number | null {
    const scored = findings.map((f) => f.risk_score).filter((s): s is number => s !== null && s !== undefined && Number.isFinite(s));
    if (scored.length === 0) return null;
    return Math.round((scored.reduce((a, b) => a + b, 0) / scored.length) * 10) / 10;
}

/** CVSS display text for one finding — honest about what is and isn't known. Never asserts a
 * version the data doesn't carry (the brief: never show v3.1 data labelled v4.0 or vice versa). */
export function formatCvss(score: number | null, version: string | null, vector: string | null): string {
    if (score === null || score === undefined) return 'Not available';
    const v = version ? `CVSS v${version}` : 'CVSS';
    const vec = vector ? ` (${vector})` : version ? '' : ' — version not reported by the scanner';
    return `${v}: ${score.toFixed(1)}${vec}`;
}

/** A deterministic, human-meaningful report identifier for this view/export — not a stored
 * artifact id (this page has none; the scheduled Reporting Center's report_jobs is a separate
 * system). Stable for the same org+period+mode within a minute, so re-rendering doesn't change
 * it, but distinct exports a minute apart are still distinguishable. */
export function reportId(orgSlug: string, days: number, generatedAt: Date = new Date()): string {
    const stamp = generatedAt.toISOString().slice(0, 16).replace(/[-:T]/g, '');
    const org = (orgSlug || 'org').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) || 'ORG';
    return `VMR-${org}-${stamp}-${days}D`;
}

/** Affected-asset count from a finding list — distinct asset_value, not finding count (one asset
 * can carry several findings). */
export function affectedAssetCount(findings: { asset_value: string }[]): number {
    return new Set(findings.map((f) => f.asset_value)).size;
}

export interface RemediationStatusCounts { open: number; in_progress: number; fixed_pending_verification: number; verified: number; risk_accepted: number; overdue: number }
export function remediationStatusCounts(findings: { status: string; due_at: string | null }[], now = Date.now()): RemediationStatusCounts {
    const out: RemediationStatusCounts = { open: 0, in_progress: 0, fixed_pending_verification: 0, verified: 0, risk_accepted: 0, overdue: 0 };
    for (const f of findings) {
        if (f.status === 'open' || f.status === 'acknowledged' || f.status === 'reopened') out.open++;
        else if (f.status === 'in_progress') out.in_progress++;
        else if (f.status === 'fixed_pending_verification') out.fixed_pending_verification++;
        else if (f.status === 'verified') out.verified++;
        else if (f.status === 'risk_accepted') out.risk_accepted++;
        if (f.due_at && Date.parse(f.due_at) < now && f.status !== 'verified' && f.status !== 'risk_accepted' && f.status !== 'false_positive') out.overdue++;
    }
    return out;
}
