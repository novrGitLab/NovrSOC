// CNII Watch intake: shapes returned by /api/cnii/intake (backend/src/services/cniiIntake.ts) and the
// labels the pages show. Every label is derived from a stored field — none is simulated. Kept free of
// imports so the frontend tests can load it directly (scripts/cnii-intake.test.mjs).

export type IntakeStatus = 'confirmed' | 'candidate' | 'rejected';
export interface IntakeAddress { ip: string; ptr: string[]; asn: string | null; holder: string | null; prefix?: string | null; public: boolean; reserved: boolean; covered_by: { org_id: string; scope_id?: string; scope: string }[] }
export interface IntakeEvidence { kind: string; detail: string; source: string; strength: 'trusted' | 'supporting' | 'context' }
export interface IntakeAuthorisation {
    scope_ids: string[]; targets: string[]; approved_addresses: string[]; reference: string; evidence: string;
    activities: { discovery: boolean; ports: boolean; vuln: boolean }; approved_by: string; approved_at: string; expires_at: string;
    revoked_by: string | null; revoked_at: string | null; revoke_reason?: string;
}
export interface IntakeSubmission {
    id: string; value: string; kind: 'domain' | 'ip'; status: IntakeStatus; basis: string | null; reason: string;
    org_id: string | null; sector_id: string | null; subfield: string | null; ips: string[];
    resolution: { resolved_at: string; errors: string[]; truncated: boolean; addresses: IntakeAddress[] };
    evidence: IntakeEvidence[]; suggestion: { sectorId: string; subfield: string; note: string } | null;
    decided_by: string | null; decided_at: string | null; decision_note?: string | null;
    submitted_by: string; submitted_at: string; resolved_at?: string | null; updated_at: string;
    authorisation?: IntakeAuthorisation | null;
    open_by_severity?: Record<string, number>; last_assessment_at?: string | null;
}

export const MAX_BULK = 25;
const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
/** Client-side check of one entry only; the backend validates again. */
export function intakeInputError(v: string): string | null {
    const s = v.trim();
    if (!s) return 'Enter a domain or IP address';
    if (/[/\s]|^\w+:\/\/|\*/.test(s)) return 'A domain or IP only — no URL, path, wildcard or range';
    if (IPV4.test(s) || (s.includes(':') && /^[0-9a-f:.]+$/i.test(s))) return null;
    return DOMAIN.test(s.replace(/\.$/, '')) ? null : 'Not a valid domain name or IP address';
}
/** Entries of a comma-, space-, semicolon- or newline-separated list (the backend's bulk format). */
export const splitEntries = (v: string): string[] => v.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

/** CNII review status, from the backend status and basis. */
export const CNII_STATUS: Record<IntakeStatus, { label: string; style: string }> = {
    candidate: { label: 'Requires review', style: 'bg-amber/10 text-amber' },
    confirmed: { label: 'Confirmed CNII', style: 'bg-green/10 text-green' },
    rejected: { label: 'Not CNII', style: 'bg-card-muted text-foreground-muted' },
};
export function reviewBasis(s: Pick<IntakeSubmission, 'status' | 'basis'>): string {
    if (s.basis === 'authorised_scope') return 'Confirmed from platform records (designated operator\'s authorised scope)';
    if (s.basis === 'analyst_confirmed') return 'Confirmed by a manager';
    if (s.basis === 'analyst_rejected') return 'Marked not CNII by a manager';
    if (s.basis === 'manual_registration') return 'Registered manually — not verified';
    return s.status === 'candidate' ? 'Not yet linked to a CNII operator' : '';
}

export type AuthKey = 'not_applicable' | 'awaiting' | 'vms_scope' | 'authorised' | 'expired' | 'revoked';
/** Scan authorisation status, from the stored CNII authorisation (and, for scope-confirmed assets, the scope basis). */
export function authState(s: Pick<IntakeSubmission, 'status' | 'basis' | 'authorisation'>, now = Date.now()): { key: AuthKey; label: string; style: string } {
    const a = s.authorisation;
    if (s.status !== 'confirmed') return { key: 'not_applicable', label: 'Not applicable until confirmed', style: 'text-foreground-muted' };
    if (a?.revoked_at) return { key: 'revoked', label: 'Revoked', style: 'bg-red/10 text-red' };
    if (a && Date.parse(a.expires_at) <= now) return { key: 'expired', label: 'Expired', style: 'bg-card-muted text-foreground-muted' };
    if (a) return { key: 'authorised', label: 'Authorised', style: 'bg-green/10 text-green' };
    if (s.basis === 'authorised_scope') return { key: 'vms_scope', label: 'Covered by a VMS scope entry', style: 'bg-blue/10 text-blue' };
    return { key: 'awaiting', label: 'Awaiting scan authorisation', style: 'bg-amber/10 text-amber' };
}
export const scanTypes = (a: Pick<IntakeAuthorisation, 'activities'>): string =>
    ['Discovery', a.activities.ports && 'Port scan', a.activities.vuln && 'Vulnerability checks (Nuclei)'].filter(Boolean).join(' · ');

/** Sector, or the suggestion labelled as one, or Unknown. Never presents a suggestion as confirmed. */
export function sectorContext(s: Pick<IntakeSubmission, 'status' | 'sector_id' | 'subfield' | 'basis' | 'suggestion'>): { text: string; kind: 'confirmed' | 'claimed' | 'suggested' | 'unknown' } {
    const sub = s.subfield ? ` / ${s.subfield}` : '';
    if (s.status === 'confirmed' && s.sector_id) return { text: `${s.sector_id}${sub}`, kind: 'confirmed' };
    if (s.basis === 'manual_registration' && s.sector_id) return { text: `${s.sector_id} (registered, unverified)`, kind: 'claimed' };
    if (s.suggestion?.sectorId) return { text: `${s.suggestion.sectorId}${s.suggestion.subfield ? ` / ${s.suggestion.subfield}` : ''} (suggested)`, kind: 'suggested' };
    return { text: 'Unknown / Requires review', kind: 'unknown' };
}
/** Network operator context from registry data — the operator, not the owner. */
export function networkContext(s: Pick<IntakeSubmission, 'resolution'>): string {
    const a = s.resolution?.addresses?.find((x) => x.holder);
    if (a) return `${a.asn ? `AS${String(a.asn).replace(/^AS/i, '')} ` : ''}${a.holder}`;
    if (s.resolution?.addresses?.some((x) => !x.public)) return 'Private or reserved address';
    return 'No registry data';
}

/** What is missing or conflicting in the evidence — shown to the analyst, never hidden. */
export function gapsOf(s: IntakeSubmission): string[] {
    const g: string[] = [];
    for (const e of s.resolution?.errors ?? []) g.push(`DNS: ${e}`);
    if (s.kind === 'domain' && !(s.resolution?.addresses ?? []).length) g.push('No address resolved for this name');
    if (s.resolution?.truncated) g.push('More addresses than are kept (first 16 only)');
    if ((s.resolution?.addresses ?? []).length && !(s.resolution.addresses.some((a) => a.holder))) g.push('No registry (ASN/holder) data');
    const orgs = new Set((s.resolution?.addresses ?? []).flatMap((a) => a.covered_by.map((c) => c.org_id)));
    if (orgs.size > 1) g.push(`Its addresses are in the scope of different organisations (${[...orgs].join(', ')})`);
    if (s.status === 'confirmed' && s.org_id && orgs.size && !orgs.has(s.org_id)) g.push(`Its addresses are in another organisation's scope than the confirmed operator (${s.org_id})`);
    if (s.status !== 'confirmed' && !s.org_id) g.push('Operating organisation unknown');
    if (s.status !== 'confirmed' && !s.sector_id && !s.suggestion) g.push('Sector unknown');
    return g;
}

/** Evidence grouped by what it is: observed facts, platform records, suggestions, human decisions. */
export function evidenceGroups(s: IntakeSubmission): { facts: IntakeEvidence[]; records: IntakeEvidence[]; human: IntakeEvidence[] } {
    const human = s.evidence.filter((e) => e.kind === 'manual_registration');
    const records = s.evidence.filter((e) => e.kind === 'authorised_scope' || e.kind === 'cnii_profile' || e.kind === 'address_in_scope');
    const facts = s.evidence.filter((e) => !human.includes(e) && !records.includes(e));
    return { facts, records, human };
}

/** Days from now to a chosen expiry date (end of that day, UTC), within 1..max. */
export function daysUntil(dateIso: string, max = 90, now = Date.now()): number | null {
    const t = Date.parse(`${dateIso}T23:59:59Z`);
    if (Number.isNaN(t)) return null;
    const d = Math.ceil((t - now) / 86_400_000);
    return d >= 1 && d <= max ? d : null;
}
