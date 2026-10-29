// Client-side mirror of backend/src/services/complianceMapping.ts — kept byte-for-byte identical
// in logic and citations so the two never silently disagree. Ported (not called over the network)
// because it is a pure function and the VMS report needs it per-row for potentially hundreds of
// findings in a table; a round trip per row is not worth it for a deterministic rules lookup.
// If the backend version changes, update this one the same way.
//
// WHAT THIS IS: a deterministic rules table, not an assessment. It answers "which controls does
// an unpatched CRITICAL/HIGH vulnerability bear on?" by encoding what each framework's clause
// actually requires — it does NOT inspect your evidence, your patch SLA, or your compensating
// controls, so it cannot and must not be presented as an audit result or a compliance score.

export type ControlStatus = 'FAIL' | 'AT RISK';

export interface ComplianceImpact {
    framework: string;
    control: string;
    status: ControlStatus;
    rationale: string;
}

export interface MappableVulnerability {
    severity?: string | null;
    package?: string | null;
    cvss?: number | null;
}

function normaliseSeverity(severity: string | null | undefined, cvss: number | null | undefined): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
    const s = (severity ?? '').toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
    if (typeof cvss === 'number' && cvss > 0) {
        if (cvss >= 9) return 'critical';
        if (cvss >= 7) return 'high';
        if (cvss >= 4) return 'medium';
        return 'low';
    }
    return 'unknown';
}

/** Controls a single unpatched vulnerability bears on. [] for low/unknown/medium severity rather
 * than manufacturing an impact — most frameworks' patch clauses are risk-based. */
export function mapCVEToCompliance(vuln: MappableVulnerability): ComplianceImpact[] {
    const severity = normaliseSeverity(vuln.severity, vuln.cvss);
    if (severity === 'low' || severity === 'unknown' || severity === 'medium') return [];

    const impacts: ComplianceImpact[] = [
        { framework: 'ISO 27001', control: 'A.8.8 — Management of technical vulnerabilities', status: 'FAIL', rationale: `Unpatched ${severity} vulnerability present on a monitored asset.` },
        { framework: 'PCI-DSS', control: 'Req 6.3.3 — System components protected from known vulnerabilities', status: 'FAIL', rationale: `${severity} severity patch outstanding.` },
        { framework: 'NDPA', control: 's.39 — Appropriate technical and organisational measures', status: 'AT RISK', rationale: 'Known exploitable weakness on a system that may process personal data.' },
        { framework: 'NIST CSF', control: 'PR.PS-02 — Software is maintained, replaced and removed commensurate with risk', status: 'FAIL', rationale: `Unpatched ${severity} vulnerability: software maintenance has not kept pace with its risk.` },
        { framework: 'GDPR', control: 'Art. 32(1)(b) — Ongoing confidentiality, integrity, availability and resilience of processing systems', status: 'AT RISK', rationale: 'Known exploitable weakness on a system that may process personal data in scope of GDPR.' },
        { framework: 'NCC', control: 'Guidelines for the Nigerian Communications Sector — network and information security obligations', status: 'AT RISK', rationale: `Unpatched ${severity} vulnerability on a monitored network asset.` },
        { framework: 'CIS Controls', control: '7.7 — Remediate Detected Vulnerabilities', status: 'FAIL', rationale: `${severity[0].toUpperCase()}${severity.slice(1)}-severity vulnerability outstanding against CIS's risk-based remediation timeline for this control.` },
        { framework: 'CIS Controls', control: '7.1 — Establish and Maintain a Vulnerability Management Process', status: 'AT RISK', rationale: 'An open, unremediated finding is evidence the process has not yet closed this item — not proof the process itself is absent.' },
    ];

    if (severity === 'critical') {
        impacts.push({ framework: 'CBN', control: 'Risk-Based Cybersecurity Framework — critical patch management', status: 'FAIL', rationale: 'Critical-severity patch outstanding beyond the expected remediation window.' });
    }

    const pkg = (vuln.package ?? '').toLowerCase();
    if (['openssl', 'apache', 'nginx', 'httpd', 'openssh'].some((p) => pkg.includes(p))) {
        impacts.push({ framework: 'PCI-DSS', control: 'Req 4.2.1 — Strong cryptography for transmission of cardholder data', status: 'AT RISK', rationale: `Affected package (${vuln.package}) terminates or secures network connections.` });
    }

    return impacts;
}

/** Full names for display, per the report brief's exact framework versions. The backend's own
 * data keys stay short ('ISO 27001' etc.) so nothing that already depends on those keys elsewhere
 * in the platform (the compliance dashboard, CNII reports) needs to change. */
export const FRAMEWORK_DISPLAY_NAME: Record<string, string> = {
    'ISO 27001': 'ISO/IEC 27001:2022',
    'NIST CSF': 'NIST CSF 2.0',
    'PCI-DSS': 'PCI DSS v4.0.1',
    'CIS Controls': 'CIS Controls v8',
    NDPA: 'NDPA 2023',
    GDPR: 'GDPR',
    NCC: 'NCC Guidelines',
    CBN: 'CBN Risk-Based Cybersecurity Framework',
};

/** The four frameworks the report's Compliance Impact section is scoped to (brief §4) — the
 * mapping function still returns the others (NDPA/GDPR/NCC/CBN) for the rest of the platform,
 * this just filters what this one section displays. */
export const REPORT_FRAMEWORKS = ['ISO 27001', 'NIST CSF', 'PCI-DSS', 'CIS Controls'] as const;
