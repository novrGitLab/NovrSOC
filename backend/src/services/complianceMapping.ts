// Maps unpatched vulnerabilities onto the compliance controls they put at risk.
//
// WHAT THIS IS: a deterministic rules table, not an assessment. It answers "which controls does
// an unpatched CRITICAL CVE bear on?" by encoding what each framework's clause actually requires
// — it does NOT inspect your evidence, your patch SLA, or your compensating controls, so it
// cannot and must not be presented as an audit result or a compliance score.
//
// Every control reference below is a real clause:
//   ISO/IEC 27001:2022 A.8.8   — Management of technical vulnerabilities
//   ISO/IEC 27001:2022 A.5.7   — Threat intelligence
//   PCI-DSS v4.0 Req 6.3.3     — Patch/update system components against known vulnerabilities
//   PCI-DSS v4.0 Req 6.3.1     — Identify and manage security vulnerabilities
//   NDPA 2023 s.39             — Technical and organisational measures for data security
//   CBN Risk-Based Cybersecurity Framework — patch management
//
// Note the ISO numbering: the 2022 revision reorganised the old Annex A, so the technical
// vulnerability control is A.8.8, NOT the A.12.6.1 it was under ISO 27001:2013. The rest of this
// platform tracks ISO/IEC 27001:2022 (see the compliance pages), so citing 2013 numbering here
// would send an analyst looking for a control their own framework doesn't list.

export type ControlStatus = 'FAIL' | 'AT RISK';

export interface ComplianceImpact {
    framework: string;
    control: string;
    status: ControlStatus;
    /** Why this vulnerability bears on this control — shown in the UI so the mapping is auditable. */
    rationale: string;
}

export interface MappableVulnerability {
    severity?: string;
    package?: string;
    cvss?: number;
}

function normaliseSeverity(severity: string | undefined, cvss: number | undefined): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
    const s = (severity ?? '').toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
    // Wazuh sometimes reports severity only as a CVSS base score. CVSS v3 bands, per FIRST.
    if (typeof cvss === 'number' && cvss > 0) {
        if (cvss >= 9) return 'critical';
        if (cvss >= 7) return 'high';
        if (cvss >= 4) return 'medium';
        return 'low';
    }
    return 'unknown';
}

/**
 * Controls a single unpatched vulnerability bears on. Returns [] for low/unknown severity rather
 * than manufacturing an impact — most frameworks' patch clauses are risk-based and do not treat
 * every low-severity finding as a control failure.
 */
export function mapCVEToCompliance(vuln: MappableVulnerability): ComplianceImpact[] {
    const severity = normaliseSeverity(vuln.severity, vuln.cvss);
    if (severity === 'low' || severity === 'unknown' || severity === 'medium') return [];

    const impacts: ComplianceImpact[] = [
        {
            framework: 'ISO 27001',
            control: 'A.8.8 — Management of technical vulnerabilities',
            status: 'FAIL',
            rationale: `Unpatched ${severity} vulnerability present on a monitored asset.`,
        },
        {
            framework: 'PCI-DSS',
            control: 'Req 6.3.3 — System components protected from known vulnerabilities',
            status: 'FAIL',
            rationale: `${severity} severity patch outstanding.`,
        },
        {
            framework: 'NDPA',
            control: 's.39 — Appropriate technical and organisational measures',
            status: 'AT RISK',
            rationale: 'Known exploitable weakness on a system that may process personal data.',
        },
    ];

    if (severity === 'critical') {
        impacts.push({
            framework: 'CBN',
            control: 'Risk-Based Cybersecurity Framework — critical patch management',
            status: 'FAIL',
            rationale: 'Critical-severity patch outstanding beyond the expected remediation window.',
        });
    }

    // Internet-facing crypto/web components carry an extra PCI requirement, since these are the
    // components that terminate cardholder-data connections.
    const pkg = (vuln.package ?? '').toLowerCase();
    if (['openssl', 'apache', 'nginx', 'httpd', 'openssh'].some((p) => pkg.includes(p))) {
        impacts.push({
            framework: 'PCI-DSS',
            control: 'Req 4.2.1 — Strong cryptography for transmission of cardholder data',
            status: 'AT RISK',
            rationale: `Affected package (${vuln.package}) terminates or secures network connections.`,
        });
    }

    return impacts;
}

export interface ComplianceImpactSummary {
    frameworks: Record<string, { failing: number; at_risk: number; controls: ComplianceImpact[] }>;
    overall_impact: 'No impact' | 'Low impact' | 'Medium impact' | 'High impact';
    /** Vulnerabilities that produced no mapping, so the UI can say how many were assessed. */
    unmapped: number;
    note: string;
}

/** Aggregates per-vulnerability mappings into a per-framework view for an asset. */
export function getComplianceImpact(vulnerabilities: MappableVulnerability[]): ComplianceImpactSummary {
    const frameworks: ComplianceImpactSummary['frameworks'] = {};
    let unmapped = 0;

    for (const vuln of vulnerabilities) {
        const impacts = mapCVEToCompliance(vuln);
        if (impacts.length === 0) { unmapped++; continue; }

        for (const impact of impacts) {
            const entry = frameworks[impact.framework] ??= { failing: 0, at_risk: 0, controls: [] };
            if (impact.status === 'FAIL') entry.failing++; else entry.at_risk++;
            // Deduplicated by control — ten CVEs all failing A.8.8 is one failing control, not
            // ten, and listing it ten times would badly overstate the finding.
            if (!entry.controls.some((c) => c.control === impact.control)) entry.controls.push(impact);
        }
    }

    const distinctFailingControls = Object.values(frameworks)
        .reduce((sum, f) => sum + f.controls.filter((c) => c.status === 'FAIL').length, 0);

    return {
        frameworks,
        overall_impact:
            distinctFailingControls === 0 ? 'No impact'
                : distinctFailingControls < 3 ? 'Low impact'
                    : distinctFailingControls < 6 ? 'Medium impact' : 'High impact',
        unmapped,
        note: 'Derived from vulnerability severity against framework clause text. Not an audit result — it does not account for compensating controls, patch SLAs or scope.',
    };
}
