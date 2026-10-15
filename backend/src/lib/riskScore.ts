// VMS risk prioritisation (phase P5). One documented formula; every finding stores the inputs and
// what each contributed (risk_factors), so a priority can always be explained.
//
//   score = 45% technical severity  — CVSS base score × 10; without a CVSS, the scanner's severity
//                                      (critical 95, high 75, medium 50, low 25, info 0)
//         + 30% exploitation         — 100 if the CVE is in CISA KEV; otherwise EPSS probability × 100;
//                                      0 when there is no exploitation evidence (unknown counts as 0
//                                      here, and is shown as "unknown", never as "not exploited")
//         + 15% exposure             — internet-facing 100, unknown 60, internal 30
//         + 10% business criticality — critical 100, high 75, medium 50, low 25 (set on the asset)
//
//   Priority:  P1 when the CVE is in KEV and the asset is internet-facing, or score >= 80
//              P2 score >= 60    P3 score >= 35    P4 otherwise
//   Remediation due: P1 2 days, P2 7 days, P3 30 days, P4 90 days from first detection.
// Informational findings (scanner severity "info", no CVSS) are always P4.
//
//   Evidence (phase P9): a finding that rests on a version a third party saw (version_match) or on
//   a third-party claim (intelligence) is unconfirmed. Its score is computed the same way, but its
//   priority is never above P3 until a scanner check confirms it — the platform does not call a
//   system vulnerable because a fingerprint resembles a vulnerable version.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';
export type EvidenceClass = 'scanner_check' | 'package_inventory' | 'version_match' | 'exposure' | 'intelligence';
export const UNCONFIRMED: readonly EvidenceClass[] = ['version_match', 'intelligence'];

export interface RiskInput {
    scanner_severity: Severity;
    cvss: number | null;
    kev: boolean | null;          // null = not looked up / no CVE
    epss: number | null;          // probability 0..1, null = unknown
    exposure: 'internet' | 'internal' | 'unknown';
    criticality: 'low' | 'medium' | 'high' | 'critical';
    evidence_class?: EvidenceClass;   // absent = scanner_check (findings before P9)
}
export interface RiskResult { score: number; priority: Priority; due_days: number; factors: Record<string, unknown> }

export const WEIGHTS = { technical: 0.45, exploitation: 0.30, exposure: 0.15, criticality: 0.10 } as const;
export const DUE_DAYS: Record<Priority, number> = { P1: 2, P2: 7, P3: 30, P4: 90 };
const SEVERITY_POINTS: Record<Severity, number> = { critical: 95, high: 75, medium: 50, low: 25, info: 0 };
const EXPOSURE_POINTS = { internet: 100, unknown: 60, internal: 30 } as const;
const CRITICALITY_POINTS = { critical: 100, high: 75, medium: 50, low: 25 } as const;

export function riskScore(i: RiskInput): RiskResult {
    const cvss = i.cvss !== null && Number.isFinite(i.cvss) ? Math.min(Math.max(i.cvss, 0), 10) : null;
    const technical = cvss !== null ? cvss * 10 : SEVERITY_POINTS[i.scanner_severity];
    const epss = i.epss !== null && Number.isFinite(i.epss) ? Math.min(Math.max(i.epss, 0), 1) : null;
    const exploitation = i.kev ? 100 : epss !== null ? epss * 100 : 0;
    const exposure = EXPOSURE_POINTS[i.exposure];
    const criticality = CRITICALITY_POINTS[i.criticality];
    const raw = technical * WEIGHTS.technical + exploitation * WEIGHTS.exploitation + exposure * WEIGHTS.exposure + criticality * WEIGHTS.criticality;
    const score = Math.round(raw);
    const informational = i.scanner_severity === 'info' && cvss === null;
    const computed: Priority = informational ? 'P4'
        : (i.kev && i.exposure === 'internet') || score >= 80 ? 'P1'
        : score >= 60 ? 'P2' : score >= 35 ? 'P3' : 'P4';
    const evidence = i.evidence_class ?? 'scanner_check';
    const capped = UNCONFIRMED.includes(evidence) && (computed === 'P1' || computed === 'P2');
    const priority: Priority = capped ? 'P3' : computed;
    return {
        score, priority, due_days: DUE_DAYS[priority],
        factors: {
            technical: { points: technical, basis: cvss !== null ? `CVSS ${cvss}` : `scanner severity ${i.scanner_severity}`, weight: WEIGHTS.technical },
            exploitation: { points: Math.round(exploitation * 10) / 10, basis: i.kev ? 'in CISA KEV' : epss !== null ? `EPSS ${epss}` : 'no exploitation data (unknown)', weight: WEIGHTS.exploitation },
            exposure: { points: exposure, basis: i.exposure, weight: WEIGHTS.exposure },
            criticality: { points: criticality, basis: i.criticality, weight: WEIGHTS.criticality },
            evidence: { basis: evidence, confirmed: !UNCONFIRMED.includes(evidence), ...(capped ? { capped_from: computed } : {}) },
            rule: capped ? `unconfirmed (${evidence.replace('_', ' ')}): ${computed} capped at P3 until a scanner confirms it`
                : informational ? 'informational finding' : i.kev && i.exposure === 'internet' ? 'KEV on an internet-facing asset' : `score ${score}`,
        },
    };
}
