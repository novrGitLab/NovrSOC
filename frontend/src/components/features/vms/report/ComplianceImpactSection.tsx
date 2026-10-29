'use client';

// Compliance Impact (brief §4): a per-finding table, not just an aggregate count, scoped to the
// four frameworks the brief names. Built from mapCVEToCompliance (@/lib/complianceMapping, a
// byte-for-byte port of the backend's own deterministic rules table — see that file's header).
// "Not assessed" is shown wherever no mapping exists, never an invented control.
import Link from 'next/link';
import { mapCVEToCompliance, FRAMEWORK_DISPLAY_NAME, REPORT_FRAMEWORKS } from '@/lib/complianceMapping';

interface FindingLite { id: string; title: string; asset_value: string; scanner_severity: string | null; scanner_cvss: number | null; remediation?: string | null; cve_ids: string[]; status: string }

const STATUS_STYLE: Record<string, string> = { FAIL: 'bg-red/10 text-red', 'AT RISK': 'bg-amber/10 text-amber' };
const OPEN_STATUSES = ['open', 'acknowledged', 'in_progress', 'reopened', 'fixed_pending_verification'];

export function ComplianceImpactSection({ findings, findingsPath }: { findings: FindingLite[]; findingsPath: string }) {
    const open = findings.filter((f) => OPEN_STATUSES.includes(f.status));
    const rows = open.flatMap((f) =>
        mapCVEToCompliance({ severity: f.scanner_severity, cvss: f.scanner_cvss })
            .filter((i) => (REPORT_FRAMEWORKS as readonly string[]).includes(i.framework))
            .map((impact) => ({ finding: f, impact }))
    );
    const byFramework = REPORT_FRAMEWORKS.map((fw) => ({ fw, rows: rows.filter((r) => r.impact.framework === fw) }));

    return (
        <div className="space-y-3">
            <div>
                <h2 className="text-sm font-black text-foreground">Compliance Impact</h2>
                <p className="text-[11px] text-foreground-muted max-w-2xl">
                    A deterministic mapping from open-finding severity to the framework clauses it bears on —
                    not an audit result. It does not account for compensating controls, patch SLAs or assessed
                    scope, and a scanner finding alone is never asserted as a confirmed compliance violation: FAIL
                    means the specific technical control this finding bears on is unmet as evidenced here; AT RISK
                    means the finding is relevant context for that control, not proof it has failed.
                </p>
            </div>
            {rows.length === 0 ? (
                <p className="text-xs text-foreground-muted bg-card border border-border rounded-xl p-4">Not assessed — no open critical/high-severity finding currently maps to a tracked control in these four frameworks.</p>
            ) : (
                <div className="space-y-4">
                    {byFramework.map(({ fw, rows: fwRows }) => fwRows.length === 0 ? null : (
                        <div key={fw} className="bg-card border border-border rounded-2xl vms-print-card overflow-hidden">
                            <div className="px-4 py-2.5 border-b border-border bg-card-muted/50">
                                <p className="text-xs font-black text-foreground">{FRAMEWORK_DISPLAY_NAME[fw] ?? fw}</p>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-[11px]">
                                    <thead><tr className="text-left text-foreground-muted border-b border-border">
                                        <th className="px-4 py-2">Control</th><th className="px-2 py-2">Finding</th><th className="px-2 py-2">Impact</th>
                                        <th className="px-2 py-2">Remediation Recommendation</th><th className="px-2 py-2">Evidence</th>
                                    </tr></thead>
                                    <tbody>
                                        {fwRows.map(({ finding, impact }, i) => (
                                            <tr key={`${finding.id}-${impact.control}-${i}`} className="border-b border-border last:border-0 align-top">
                                                <td className="px-4 py-2 font-semibold text-foreground whitespace-nowrap">{impact.control}</td>
                                                <td className="px-2 py-2"><Link href={`${findingsPath}?id=${finding.id}`} className="text-blue hover:underline">{finding.title}</Link><p className="text-foreground-muted">{finding.asset_value}</p></td>
                                                <td className="px-2 py-2"><span className={`inline-block px-1.5 py-0.5 rounded font-bold ${STATUS_STYLE[impact.status]}`}>{impact.status}</span><p className="text-foreground-muted mt-1">{impact.rationale}</p></td>
                                                <td className="px-2 py-2 text-foreground-muted">{finding.remediation || 'See finding detail'}</td>
                                                <td className="px-2 py-2 text-foreground-muted font-mono">{finding.cve_ids.length ? finding.cve_ids.join(', ') : `scanner severity: ${finding.scanner_severity ?? 'n/a'}`}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
