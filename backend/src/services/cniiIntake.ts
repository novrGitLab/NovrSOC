// CNII Watch intake (phase P17): an analyst submits a domain or IP; the backend resolves it,
// gathers evidence, decides whether it can be linked to a CNII organisation, and — once linked —
// adds the in-scope values to that organisation's VMS inventory and assesses them with the existing
// Full Assessment (services/vmsAssessments.ts: scope, exclusions, worker routing all apply).
//
// Evidence, strongest first:
//   authorised scope  an organisation's active scope entry (approved by a manager, with its
//                     authorisation reference) covers the submitted value
//   CNII profile      that organisation is classified into a sector, designated or candidate
//   registry / DNS    RIPEstat holder and AS, reverse DNS — context only, never ownership
//   AI                a suggestion an analyst may use when deciding — never evidence
// A submission is confirmed automatically only when exactly one designated CNII organisation holds
// the submitted value itself in active authorised scope. For a domain, an address it resolves to
// being in someone's scope is NOT enough (shared hosting, CDNs): it is recorded as evidence only.
// Everything else stays a candidate with the reason, until a manager confirms or rejects it.
//
// P18 adds: bulk submission (each entry independent), manual registration (an analyst's claim of
// organisation and sector — a candidate until a manager confirms it, authorising nothing), and CNII
// scan authorisation: a manager's evidence-backed approval written as exact VMS scope entries
// (origin 'cnii'; a domain without subdomains pinned to its approved addresses, plus chosen IPs), so
// every existing scope check enforces it and nothing is bypassed.
//
// Safety: the backend never connects to a resolved address; it only asks DNS and RIPEstat. Loopback,
// link-local, multicast and unspecified addresses are never linked or assessed. Private addresses
// are linked only when an organisation's scope explicitly covers them, and assessed only through a
// worker that declares a route (Full Assessment planning).

import { isIP } from 'net';
import { dns, setDnsForTests } from '../lib/dnsResolve';
import { getSupabase } from './geoEnrichment';
import { coveringScope, normalizeHostname, parseTarget, type ScopeEntry, type Target } from '../lib/vmsScope';
import { classifySector } from '../lib/cnii-classify';
import { SECTOR_BY_ID } from '../lib/cnii-sectors';
import { asHolder, ipNetworkInfo } from './ripeStat';
import { cleanAsHolder } from '../lib/spiderfoot';
import { isNonPublicIp } from '../lib/netClass';
import { createAssessment, describe, type AssessmentRow } from './vmsAssessments';

export const P17_MISSING = 'CNII intake is not set up yet (run sql/2026-10-23_p17_cnii_intake.sql)';
export const MAX_IPS = 16;
const ENRICH_IPS = 8;
export const SCHEDULE_INTERVAL_HOURS = 48;
export const SCHEDULE_MAX_DAYS = 60;

// ── Dependencies (injectable for tests: no network in tests) ─────────────────────────────────
export interface IntakeDeps {
    resolve4: (h: string) => Promise<string[]>;
    resolve6: (h: string) => Promise<string[]>;
    reverse: (ip: string) => Promise<string[]>;
    networkInfo: (ip: string) => Promise<{ asns: string[]; prefix: string | null } | null>;
    holder: (asn: string) => Promise<string | null>;
}
function defaultDeps(): IntakeDeps {
    return { ...dns(), networkInfo: ipNetworkInfo, holder: asHolder };
}
let depsOverride: Partial<IntakeDeps> | null = null;
/** Also answers the shared resolver (lib/dnsResolve.ts), so queue-time pin checks see the same DNS. */
export function setIntakeDepsForTests(d: Partial<IntakeDeps> | null): void {
    depsOverride = d;
    setDnsForTests(d ? { ...(d.resolve4 ? { resolve4: d.resolve4 } : {}), ...(d.resolve6 ? { resolve6: d.resolve6 } : {}), ...(d.reverse ? { reverse: d.reverse } : {}) } : null);
}
const deps = (): IntakeDeps => ({ ...defaultDeps(), ...(depsOverride ?? {}) });

// ── Input ───────────────────────────────────────────────────────────────────────────────────
/** A domain or IP, normalised; null for anything else (URLs, wildcards, ports, CIDRs). */
export function parseIntake(input: unknown): { kind: 'domain' | 'ip'; value: string } | null {
    const s = typeof input === 'string' ? input.trim().toLowerCase().replace(/\.$/, '') : '';
    if (!s || s.length > 253) return null;
    if (isIP(s)) return { kind: 'ip', value: s };
    const h = normalizeHostname(s);
    return h ? { kind: 'domain', value: h } : null;
}

export const MAX_BULK = 25;
export type BulkEntry = { input: string; kind?: 'domain' | 'ip'; value?: string; outcome: 'valid' | 'invalid' | 'duplicate' };
/** Comma-, space- or newline-separated entries, each validated and normalised on its own; repeats marked. */
export function parseIntakeList(input: unknown): { entries: BulkEntry[]; too_many: boolean } {
    const raw = Array.isArray(input) ? input.map(String) : typeof input === 'string' ? input.split(/[\s,;]+/) : [];
    const items = raw.map((x) => x.trim()).filter(Boolean);
    const seen = new Set<string>();
    const entries = items.slice(0, MAX_BULK).map((i): BulkEntry => {
        const p = parseIntake(i);
        if (!p) return { input: i.slice(0, 253), outcome: 'invalid' };
        if (seen.has(p.value)) return { input: i, ...p, outcome: 'duplicate' };
        seen.add(p.value);
        return { input: i, ...p, outcome: 'valid' };
    });
    return { entries, too_many: items.length > MAX_BULK };
}

/** Addresses that are never linked or assessed, whatever a scope says. */
export function reservedAddress(ip: string): boolean {
    const v = ip.toLowerCase();
    if (isIP(v) === 4) {
        const [a, b] = v.split('.').map(Number);
        return a === 0 || a === 127 || (a === 169 && b === 254) || a >= 224;
    }
    return v === '::' || v === '::1' || v.startsWith('fe80:') || v.startsWith('ff');
}

// ── Resolution and enrichment ───────────────────────────────────────────────────────────────
const quiet = async (p: Promise<string[]>): Promise<{ values: string[]; error: string | null }> => {
    try { return { values: await p, error: null }; } catch (e) {
        const code = (e as { code?: string }).code ?? '';
        return { values: [], error: ['ENOTFOUND', 'ENODATA', 'NXDOMAIN'].includes(code) ? null : (code || 'lookup failed') };
    }
};
export interface AddressInfo { ip: string; ptr: string[]; asn: string | null; holder: string | null; holder_raw: string | null; prefix: string | null; public: boolean; reserved: boolean; covered_by: { org_id: string; scope_id: string; scope: string }[] }
export interface Resolution { resolved_at: string; a: string[]; aaaa: string[]; errors: string[]; truncated: boolean; addresses: AddressInfo[] }

export async function resolveIntake(kind: 'domain' | 'ip', value: string): Promise<Resolution> {
    const d = deps();
    const errors: string[] = [];
    let a: string[] = [];
    let aaaa: string[] = [];
    if (kind === 'domain') {
        const [r4, r6] = await Promise.all([quiet(d.resolve4(value)), quiet(d.resolve6(value))]);
        a = [...new Set(r4.values.map((x) => x.toLowerCase()))].sort();
        aaaa = [...new Set(r6.values.map((x) => x.toLowerCase()))].sort();
        if (r4.error) errors.push(`A lookup: ${r4.error}`);
        if (r6.error) errors.push(`AAAA lookup: ${r6.error}`);
        if (!a.length && !aaaa.length && !errors.length) errors.push('The name has no A or AAAA records');
    }
    const all = kind === 'ip' ? [value] : [...a, ...aaaa];
    const ips = all.slice(0, MAX_IPS);
    const addresses = await Promise.all(ips.map(async (ip, i): Promise<AddressInfo> => {
        const reserved = reservedAddress(ip);
        const pub = !isNonPublicIp(ip);
        const ptr = reserved ? { values: [], error: null } : await quiet(d.reverse(ip));
        let net: { asns: string[]; prefix: string | null } | null = null;
        let raw: string | null = null;
        // Registry data only for public addresses, and for the first few of a large answer.
        if (pub && !reserved && i < ENRICH_IPS) {
            net = await d.networkInfo(ip).catch(() => null);
            raw = net?.asns[0] ? await d.holder(net.asns[0]).catch(() => null) : null;
        }
        return { ip, ptr: ptr.values.map((x) => x.toLowerCase()).slice(0, 10), asn: net?.asns[0] ?? null, holder: raw ? cleanAsHolder(raw) : null, holder_raw: raw, prefix: net?.prefix ?? null, public: pub, reserved, covered_by: [] };
    }));
    return { resolved_at: new Date().toISOString(), a, aaaa, errors, truncated: all.length > ips.length, addresses };
}

// ── Classification (pure) ───────────────────────────────────────────────────────────────────
export interface Profile { org_id: string; sector_id: string; subfield: string | null; designation: 'designated' | 'candidate' }
export interface Evidence { kind: string; detail: string; source: string; strength: 'trusted' | 'supporting' | 'context' }
export interface Decision { status: 'confirmed' | 'candidate'; basis: 'authorised_scope' | null; reason: string; org_id: string | null; sector_id: string | null; subfield: string | null; evidence: Evidence[] }

const scopeLabel = (s: ScopeEntry & { authorization_reference?: string }) => `${s.kind} ${s.value}${s.authorization_reference ? ` (ref ${s.authorization_reference})` : ''}`;
function coverage(t: Target | null, scopes: ScopeEntry[]): ScopeEntry[] {
    if (!t) return [];
    return scopes.filter((s) => coveringScope(t, [s], 'passive'));
}

/** What the evidence supports. Pure: scopes of every organisation, CNII profiles. */
export function classifyIntake(kind: 'domain' | 'ip', value: string, res: Resolution, scopes: ScopeEntry[], profiles: Profile[], names: Map<string, string> = new Map()): Decision {
    const evidence: Evidence[] = [];
    const profileOf = new Map(profiles.map((p) => [p.org_id, p]));
    const name = (o: string) => names.get(o) ?? o;
    for (const a of res.addresses) {
        a.covered_by = a.reserved ? [] : coverage(parseTarget(a.ip), scopes).map((s) => ({ org_id: s.org_id, scope_id: s.id, scope: scopeLabel(s) }));
        if (a.reserved) evidence.push({ kind: 'reserved_address', detail: `${a.ip} is a loopback, link-local, multicast or unspecified address: never linked or assessed`, source: kind === 'domain' ? 'dns' : 'input', strength: 'context' });
        else if (!a.public) evidence.push({ kind: 'private_address', detail: `${a.ip} is a private address: linked only if an organisation's scope covers it, assessed only through a worker with a route to it`, source: kind === 'domain' ? 'dns' : 'input', strength: 'context' });
        if (a.holder) evidence.push({ kind: 'registry', detail: `${a.ip} is announced by ${a.asn ?? 'an AS'} held by ${a.holder}: the network operator, not necessarily the owner`, source: 'ripestat', strength: 'context' });
        if (a.ptr.length) evidence.push({ kind: 'reverse_dns', detail: `${a.ip} reverse DNS: ${a.ptr.slice(0, 3).join(', ')}`, source: 'dns', strength: 'context' });
        if (kind === 'domain') for (const c of a.covered_by) evidence.push({ kind: 'address_in_scope', detail: `${a.ip} is inside ${name(c.org_id)}'s authorised scope ${c.scope}; the address alone does not show who operates ${value} (shared hosting and CDNs are common)`, source: 'vms_scopes', strength: 'supporting' });
    }
    const own = coverage(parseTarget(value), scopes);
    const orgs = [...new Set(own.map((s) => s.org_id))];
    for (const s of own) evidence.push({ kind: 'authorised_scope', detail: `${value} is inside ${name(s.org_id)}'s active authorised scope ${scopeLabel(s)}`, source: 'vms_scopes', strength: 'trusted' });
    const none = { basis: null, org_id: null, sector_id: null, subfield: null } as const;
    if (!orgs.length) return { status: 'candidate', ...none, reason: `${value} is not inside any organisation's active authorised scope, so it cannot be linked to a CNII operator from trusted records`, evidence };
    if (orgs.length > 1) return { status: 'candidate', ...none, reason: `${value} is inside the authorised scope of more than one organisation (${orgs.map(name).join(', ')}): a manager must decide`, evidence };
    const org = orgs[0];
    const p = profileOf.get(org);
    if (!p) return { status: 'candidate', ...none, org_id: org, reason: `${value} is in ${name(org)}'s authorised scope, but ${name(org)} has no CNII sector profile`, evidence };
    evidence.push({ kind: 'cnii_profile', detail: `${name(org)} is classified ${SECTOR_BY_ID[p.sector_id] ? p.sector_id : p.sector_id}${p.subfield ? ` / ${p.subfield}` : ''} (${p.designation})`, source: 'cnii_org_profiles', strength: p.designation === 'designated' ? 'trusted' : 'supporting' });
    if (p.designation !== 'designated') return { status: 'candidate', ...none, org_id: org, sector_id: p.sector_id, subfield: p.subfield, reason: `${value} is in ${name(org)}'s authorised scope, but ${name(org)} is only a CNII candidate (not designated)`, evidence };
    return { status: 'confirmed', basis: 'authorised_scope', org_id: org, sector_id: p.sector_id, subfield: p.subfield, reason: `${value} is in the authorised scope of ${name(org)}, a designated CNII operator in ${p.sector_id}`, evidence };
}

/** Keyword sector suggestion from registry names and the domain: a hint, never evidence. */
export function keywordSuggestion(kind: 'domain' | 'ip', value: string, res: Resolution) {
    const a = res.addresses.find((x) => x.holder) ?? null;
    const s = classifySector(a?.holder ?? '', a?.holder_raw ?? '', a?.asn ?? '', kind === 'domain' ? value : (res.addresses[0]?.ptr[0] ?? ''));
    return s.sectorId ? { ...s, note: 'Keyword match on registry and DNS names only: a hint for the analyst, not evidence of ownership or CNII status' } : null;
}

// ── Database ────────────────────────────────────────────────────────────────────────────────
const db = () => getSupabase()!;
export const isMissingP17 = (e: { code?: string; message?: string } | null) => !!e && (e.code === 'PGRST205' || e.code === '42P01' || /cnii_submissions/.test(e.message ?? ''));

async function allScopes(): Promise<ScopeEntry[]> {
    const { data, error } = await db().from('vms_scopes').select('*').eq('status', 'active').gt('expires_at', new Date().toISOString()).limit(10_000);
    if (error) throw new Error(`scopes unreadable: ${error.message}`);
    return (data ?? []) as ScopeEntry[];
}
async function context() {
    const [scopes, profs, orgs] = await Promise.all([
        allScopes(),
        db().from('cnii_org_profiles').select('org_id, sector_id, subfield, designation').limit(5000),
        db().from('organisations').select('slug, name').limit(5000),
    ]);
    if (profs.error) throw new Error(`CNII profiles unreadable: ${profs.error.message}`);
    return { scopes, profiles: (profs.data ?? []) as Profile[], names: new Map((orgs.data ?? []).map((o) => [o.slug as string, o.name as string])) };
}

/** Values of a confirmed submission inside its organisation's active scope, as VMS assets (created or reused). */
export async function linkToInventory(org: string, kind: 'domain' | 'ip', value: string, res: Resolution, scopes: ScopeEntry[]): Promise<{ asset_ids: string[]; linked: string[]; not_in_scope: string[] }> {
    const mine = scopes.filter((s) => s.org_id === org);
    const now = new Date().toISOString();
    const targets: { type: 'host' | 'ip'; value: string; ips: string[] }[] = [];
    const notInScope: string[] = [];
    const candidates: { type: 'host' | 'ip'; value: string; ips: string[] }[] = kind === 'domain' ? [{ type: 'host', value, ips: res.addresses.filter((a) => !a.reserved).map((a) => a.ip) }] : [];
    for (const a of res.addresses) if (!a.reserved) candidates.push({ type: 'ip', value: a.ip, ips: [a.ip] });
    for (const c of candidates) {
        const t = parseTarget(c.value);
        if (t && coveringScope(t, mine, 'passive')) targets.push(c); else notInScope.push(c.value);
    }
    const ids: string[] = [];
    for (const t of targets) {
        const scope = coveringScope(parseTarget(t.value)!, mine, 'passive')!;
        const { data: ex } = await db().from('vms_assets').select('id, discovery_sources, ips').eq('org_id', org).eq('asset_type', t.type).eq('value', t.value).maybeSingle();
        if (ex) {
            await db().from('vms_assets').update({ discovery_sources: [...new Set([...(ex.discovery_sources ?? []), 'cnii_intake'])], ...(t.type === 'host' && t.ips.length ? { ips: [...new Set([...(ex.ips ?? []), ...t.ips])].sort() } : {}) }).eq('id', ex.id);
            ids.push(ex.id);
            continue;
        }
        const ins = await db().from('vms_assets').insert({ org_id: org, asset_type: t.type, value: t.value, ips: t.ips, hostnames: t.type === 'host' ? [t.value] : [], discovery_sources: ['cnii_intake'], scope_id: scope.id, confidence: 'confirmed', exposure: t.ips.some((ip) => !isNonPublicIp(ip)) ? 'internet' : 'internal', first_seen: now, last_seen: now }).select('id').single();
        if (ins.error) throw new Error(`asset insert failed: ${ins.error.message}`);
        ids.push(ins.data.id);
        await db().from('vms_asset_events').insert({ org_id: org, asset_id: ins.data.id, event: 'asset_new', details: { value: t.value, source: 'cnii_intake' } });
    }
    return { asset_ids: ids, linked: targets.map((t) => t.value), not_in_scope: notInScope };
}

export type Submission = Record<string, unknown> & { id: string; value: string; kind: 'domain' | 'ip'; status: string; basis: string | null; org_id: string | null; ips: string[]; resolution: Resolution; asset_ids: string[] };

/** Submits (or re-checks) a value. Idempotent on the normalised value; a manager's decision is kept. */
export async function submitIntake(kind: 'domain' | 'ip', value: string, by: string) {
    const res = await resolveIntake(kind, value);
    const ctx = await context();
    const d = classifyIntake(kind, value, res, ctx.scopes, ctx.profiles, ctx.names);
    const { data: prev, error: pErr } = await db().from('cnii_submissions').select('*').eq('value', value).maybeSingle();
    if (pErr) throw Object.assign(new Error(pErr.message), { code: pErr.code });
    const decidedByPerson = prev && (prev.basis === 'analyst_confirmed' || prev.basis === 'analyst_rejected');
    // A manual registration (P18) stays until trusted records confirm the value or a manager decides.
    const registered = prev?.basis === 'manual_registration' && d.status !== 'confirmed';
    const keptEvidence = ((prev?.evidence ?? []) as Evidence[]).filter((e) => e.kind === 'manual_registration');
    const now = new Date().toISOString();
    const fresh = {
        kind, ips: res.addresses.map((a) => a.ip), resolution: res, evidence: [...d.evidence, ...keptEvidence], suggestion: keywordSuggestion(kind, value, res), resolved_at: res.resolved_at, updated_at: now,
        // Automatic status only where no person has decided; a person's decision stands until they change it.
        ...(decidedByPerson || registered ? {} : { status: d.status, basis: d.basis, reason: d.reason, org_id: d.org_id, sector_id: d.sector_id, subfield: d.subfield }),
    };
    const saved = prev
        ? await db().from('cnii_submissions').update(fresh).eq('id', prev.id).select('*').single()
        : await db().from('cnii_submissions').insert({ value, submitted_by: by, submitted_at: now, ...fresh }).select('*').single();
    if (saved.error) throw Object.assign(new Error(saved.error.message), { code: saved.error.code });
    let row = saved.data as Submission;
    let link: Awaited<ReturnType<typeof linkToInventory>> | null = null;
    if (row.status === 'confirmed' && row.org_id) {
        link = await linkToInventory(row.org_id, kind, value, res, ctx.scopes);
        const upd = await db().from('cnii_submissions').update({ asset_ids: [...new Set([...(row.asset_ids ?? []), ...link.asset_ids])] }).eq('id', row.id).select('*').single();
        if (!upd.error) row = upd.data as Submission;
    }
    return { submission: row, created: !prev, decision: d, link };
}

/** A manager's decision: confirm (linking to an organisation with a CNII profile) or reject. */
export async function decideIntake(id: string, by: string, input: { decision: 'confirm' | 'reject'; org_id?: string; note: string }) {
    const { data: s, error } = await db().from('cnii_submissions').select('*').eq('id', id).maybeSingle();
    if (error) throw Object.assign(new Error(error.message), { code: error.code });
    if (!s) return { ok: false as const, status: 404, error: 'Submission not found' };
    const now = new Date().toISOString();
    if (input.decision === 'reject') {
        const { data } = await db().from('cnii_submissions').update({ status: 'rejected', basis: 'analyst_rejected', reason: `Rejected by ${by}: ${input.note}`, decided_by: by, decided_at: now, decision_note: input.note, updated_at: now }).eq('id', id).select('*').single();
        return { ok: true as const, submission: data as Submission, link: null };
    }
    const orgId = input.org_id ?? (s.basis === 'manual_registration' ? s.org_id : null);
    if (!orgId) return { ok: false as const, status: 400, error: 'Confirming needs the organisation that operates it' };
    const ctx = await context();
    const p = ctx.profiles.find((x) => x.org_id === orgId);
    if (!p) return { ok: false as const, status: 409, error: 'That organisation has no CNII sector profile: classify it first' };
    const { data } = await db().from('cnii_submissions').update({
        status: 'confirmed', basis: 'analyst_confirmed', org_id: p.org_id, sector_id: p.sector_id, subfield: p.subfield,
        reason: `Confirmed by ${by} as operated by ${ctx.names.get(p.org_id) ?? p.org_id}: ${input.note}`, decided_by: by, decided_at: now, decision_note: input.note, updated_at: now,
    }).eq('id', id).select('*').single();
    const link = await linkToInventory(p.org_id, s.kind, s.value, s.resolution as Resolution, ctx.scopes);
    const upd = await db().from('cnii_submissions').update({ asset_ids: [...new Set([...((data?.asset_ids as string[]) ?? []), ...link.asset_ids])] }).eq('id', id).select('*').single();
    return { ok: true as const, submission: (upd.data ?? data) as Submission, link };
}

/** Values of a confirmed submission that may be assessed: in its organisation's scope, not reserved. */
export function assessableTargets(s: Submission, scopes: ScopeEntry[]): string[] {
    if (s.status !== 'confirmed' || !s.org_id) return [];
    const mine = scopes.filter((x) => x.org_id === s.org_id);
    const values = [...(s.kind === 'domain' ? [s.value] : []), ...(s.resolution?.addresses ?? []).filter((a) => !a.reserved).map((a) => a.ip)];
    return [...new Set(values)].filter((v) => { const t = parseTarget(v); return !!t && !!coveringScope(t, mine, 'passive'); }).slice(0, 10);
}

/** Full Assessments for the chosen targets, through the existing planner (scope, exclusions, workers). */
export async function assessIntake(s: Submission, by: string, ip: string, only?: string[]) {
    const scopes = await allScopes();
    const allowed = assessableTargets(s, scopes);
    const targets = only?.length ? allowed.filter((t) => only.includes(t)) : allowed;
    const refused = (only ?? []).filter((t) => !allowed.includes(t)).map((t) => ({ target: t, error: 'Not an in-scope value of this confirmed submission' }));
    type Result = { target: string; ok: boolean; existing?: boolean; assessment_id?: string; status?: string; error?: string };
    const results: Result[] = [];
    for (const t of targets) {
        const r = await createAssessment(s.org_id!, by, { target: t }, ip);
        results.push(r.ok ? { target: t, ok: true, existing: r.existing, assessment_id: r.assessment.id, status: r.assessment.status } : { target: t, ok: false, error: r.error });
    }
    return { results: [...results, ...refused.map((x): Result => ({ ...x, ok: false }))], not_assessable: s.status !== 'confirmed' ? 'Only a confirmed submission can be assessed' : !allowed.length ? 'No value of this submission is inside its organisation\'s active authorised scope' : null };
}

/** Recurring Full Assessment every 48 h, ending after at most 60 days, one schedule per target. */
export async function scheduleIntake(s: Submission, by: string, days: number, now = Date.now()) {
    const scopes = await allScopes();
    const targets = assessableTargets(s, scopes);
    const endsAt = new Date(now + Math.min(Math.max(1, days), SCHEDULE_MAX_DAYS) * 86_400_000).toISOString();
    const out: { target: string; schedule_id?: string; existing: boolean; error?: string }[] = [];
    for (const t of targets) {
        const scope = coveringScope(parseTarget(t)!, scopes.filter((x) => x.org_id === s.org_id), 'discovery');
        if (!scope) { out.push({ target: t, existing: false, error: 'Its scope entry allows passive monitoring only' }); continue; }
        const { data: ex } = await db().from('vms_scan_schedules').select('id, ends_at').eq('org_id', s.org_id!).eq('kind', 'full_assessment').eq('enabled', true).contains('targets', [t]).limit(1);
        if (ex?.length) { out.push({ target: t, schedule_id: ex[0].id, existing: true }); continue; }
        const ins = await db().from('vms_scan_schedules').insert({ org_id: s.org_id, scope_id: scope.id, kind: 'full_assessment', targets: [t], interval_hours: SCHEDULE_INTERVAL_HOURS, next_run_at: new Date(now + SCHEDULE_INTERVAL_HOURS * 3_600_000).toISOString(), ends_at: endsAt, enabled: true, created_by: by }).select('id').single();
        out.push(ins.error ? { target: t, existing: false, error: /ends_at|full_assessment|check constraint/i.test(ins.error.message) ? P17_MISSING : 'Could not save the schedule' } : { target: t, schedule_id: ins.data.id, existing: false });
    }
    return { ends_at: endsAt, interval_hours: SCHEDULE_INTERVAL_HOURS, schedules: out };
}

/** Assessments, findings and schedules of a submission's values in its organisation. */
export async function intakeResults(s: Submission) {
    if (!s.org_id || s.status !== 'confirmed') return { assessments: [], findings: [], severity: {}, schedules: [], note: 'Results are shown once the submission is confirmed and linked to an organisation' };
    const values = [...new Set([s.value, ...(s.ips ?? [])])];
    const [as, fs, sch] = await Promise.all([
        db().from('vms_assessments').select('*').eq('org_id', s.org_id).in('target', values).order('requested_at', { ascending: false }).limit(20),
        db().from('vms_findings').select('id, title, rule_id, cve_ids, scanner_severity, priority, risk_score, status, asset_value, port, protocol, evidence_class, source_class, detected_by, remediation, first_seen, last_seen').eq('org_id', s.org_id).in('asset_value', values).order('risk_score', { ascending: false, nullsFirst: false }).limit(200),
        db().from('vms_scan_schedules').select('id, kind, targets, interval_hours, next_run_at, ends_at, enabled, last_run_at, last_result').eq('org_id', s.org_id).eq('kind', 'full_assessment').overlaps('targets', values).limit(20),
    ]);
    const described = as.error ? [] : await describe((as.data ?? []) as AssessmentRow[]);
    const findings = fs.data ?? [];
    const ids = findings.slice(0, 100).map((f) => f.id);
    const { data: ev } = ids.length ? await db().from('vms_finding_evidence').select('finding_id, source, observed_at, matched_at, evidence').eq('org_id', s.org_id).in('finding_id', ids).order('observed_at', { ascending: false }).limit(1000) : { data: [] as Record<string, unknown>[] };
    const latest = new Map<string, unknown>();
    for (const e of ev ?? []) if (!latest.has(e.finding_id as string)) latest.set(e.finding_id as string, e);
    const OPEN = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
    const severity: Record<string, number> = {};
    for (const f of findings) if (OPEN.includes(f.status)) severity[f.scanner_severity] = (severity[f.scanner_severity] ?? 0) + 1;
    return {
        assessments: described.map(({ all_job_ids: _j, ...a }) => a),
        assessments_available: !as.error,
        findings: findings.map((f) => ({ ...f, latest_evidence: latest.get(f.id) ?? null })),
        severity, schedules: sch.error ? [] : sch.data ?? [], schedules_available: !sch.error,
        note: null,
    };
}

// ── Manual registration (P18) ─────────────────────────────────────────────────────────────────
/** An analyst registers an IP against an organisation and sector, with a justification. It stays a
 *  candidate — never on the watch list — and authorises nothing, until a manager confirms it. */
export async function registerManual(by: string, input: { org_id: string; sector_id: string; ip: string; justification: string }) {
    const v = parseIntake(input.ip);
    if (!v || v.kind !== 'ip') return { ok: false as const, status: 400, error: 'Give one IP address' };
    if (!SECTOR_BY_ID[input.sector_id]) return { ok: false as const, status: 400, error: 'Unknown sector' };
    const { data: org } = await db().from('organisations').select('slug, name').eq('slug', input.org_id).maybeSingle();
    if (!org) return { ok: false as const, status: 404, error: 'Organisation not found' };
    const { data: prof } = await db().from('cnii_org_profiles').select('sector_id').eq('org_id', input.org_id).maybeSingle();
    if (prof && prof.sector_id !== input.sector_id) return { ok: false as const, status: 409, error: `${org.name} is classified in ${prof.sector_id}, not ${input.sector_id}` };
    const r = await submitIntake('ip', v.value, by);
    const s = r.submission;
    if (s.status === 'confirmed') return { ok: true as const, submission: s, registered: false, note: 'Already confirmed from trusted records or a manager decision; nothing registered' };
    if (s.basis === 'analyst_rejected') return { ok: false as const, status: 409, error: 'A manager marked this address not CNII; a manager must reconsider it' };
    const now = new Date().toISOString();
    const ev: Evidence = { kind: 'manual_registration', detail: `Registered by ${by} for ${org.name} in ${input.sector_id}: ${input.justification} (unverified)`, source: 'analyst', strength: 'supporting' };
    const { data, error } = await db().from('cnii_submissions').update({
        basis: 'manual_registration', status: 'candidate', org_id: input.org_id, sector_id: input.sector_id, subfield: null,
        reason: `Registered manually for ${org.name} (${input.sector_id}), not verified: a manager must confirm it before it is CNII, and scanning needs a separate authorisation`,
        evidence: [...((s.evidence ?? []) as Evidence[]).filter((e) => e.kind !== 'manual_registration'), ev], updated_at: now,
    }).eq('id', s.id).select('*').single();
    if (error) return { ok: false as const, status: /basis|check constraint/i.test(error.message) ? 503 : 502, error: /basis|check constraint/i.test(error.message) ? P18_MISSING : 'Could not register the asset' };
    return { ok: true as const, submission: data as Submission, registered: true, note: null };
}

// ── CNII scan authorisation (P18) ─────────────────────────────────────────────────────────────
export const P18_MISSING = 'CNII scan authorisation is not set up yet (run sql/2026-10-24_p18_cnii_authorisation.sql)';
export const MAX_AUTH_DAYS = 90;
export interface AuthoriseInput { reference: string; evidence: string; expires_days: number; allow_port_scan: boolean; allow_vuln_scan: boolean; addresses?: string[] }

/**
 * A manager authorises scanning of a confirmed submission. Written as exact VMS scope entries in the
 * operator's organisation (origin 'cnii'), so the API, Full Assessment, scheduler, worker and ingest
 * all enforce it with their existing checks:
 *   • a domain: the name only (no subdomains), pinned to every address it resolves to now;
 *   • the addresses chosen (default: its public ones), each as a single-IP entry.
 * Refused when the name resolves to a reserved address or not at all. An existing general scope entry
 * for the same value is left untouched and reported.
 */
export async function authoriseIntake(s: Submission, by: string, input: AuthoriseInput, now = Date.now()) {
    if (s.status !== 'confirmed' || !s.org_id) return { ok: false as const, status: 409, error: 'Only a confirmed CNII submission can be authorised for scanning' };
    const res = await resolveIntake(s.kind, s.value);
    const current = res.addresses;
    if (s.kind === 'domain' && !current.length) return { ok: false as const, status: 409, error: `${s.value} does not resolve now${res.errors.length ? ` (${res.errors.join('; ')})` : ''}: nothing to pin the approval to` };
    if (current.some((a) => a.reserved)) return { ok: false as const, status: 409, error: `${s.value} resolves to a reserved address (${current.filter((a) => a.reserved).map((a) => a.ip).join(', ')}): never authorised` };
    if (res.truncated) return { ok: false as const, status: 409, error: `${s.value} resolves to more addresses than can be pinned; authorise its addresses as VMS scope entries instead` };
    const wanted = input.addresses?.length ? input.addresses.map((a) => a.trim().toLowerCase()) : current.filter((a) => a.public).map((a) => a.ip);
    const unknown = wanted.filter((a) => !current.some((c) => c.ip === a));
    if (unknown.length) return { ok: false as const, status: 400, error: `Not addresses of ${s.value} now: ${unknown.join(', ')}` };
    const expires = new Date(now + Math.min(Math.max(1, input.expires_days), MAX_AUTH_DAYS) * 86_400_000).toISOString();
    const pins = s.kind === 'domain' ? current.map((a) => a.ip) : [];
    const targets: { kind: 'domain' | 'ip'; value: string; pinned: string[] }[] = [
        ...(s.kind === 'domain' ? [{ kind: 'domain' as const, value: s.value, pinned: pins }] : []),
        ...[...new Set(s.kind === 'ip' ? [s.value] : wanted)].map((ip) => ({ kind: 'ip' as const, value: ip, pinned: [] as string[] })),
    ];
    const results: { target: string; scope_id?: string; outcome: 'created' | 'updated' | 'existing_vms_scope'; detail?: string }[] = [];
    for (const t of targets) {
        const row = {
            allow_discovery: true, allow_port_scan: input.allow_port_scan, allow_vuln_scan: input.allow_vuln_scan, include_subdomains: false, exclusions: [],
            authorization_reference: `CNII ${input.reference}`.slice(0, 300), notes: `CNII scan authorisation for submission ${s.id}: ${input.evidence}`.slice(0, 2000),
            approved_by: by, approved_at: new Date(now).toISOString(), expires_at: expires, origin: 'cnii', cnii_submission_id: s.id, pinned_addresses: t.pinned,
        };
        const { data: ex, error: exErr } = await db().from('vms_scopes').select('*').eq('org_id', s.org_id).eq('kind', t.kind).eq('value', t.value).eq('status', 'active').maybeSingle();
        if (exErr) throw Object.assign(new Error(exErr.message), { code: exErr.code });
        if (ex && (ex.origin !== 'cnii' || ex.cnii_submission_id !== s.id)) { results.push({ target: t.value, scope_id: ex.id, outcome: 'existing_vms_scope', detail: `Already authorised by ${ex.origin === 'cnii' ? 'another CNII approval' : 'a VMS scope entry'} (ref ${ex.authorization_reference}); left unchanged` }); continue; }
        const w = ex ? await db().from('vms_scopes').update(row).eq('id', ex.id).select('id').single()
            : await db().from('vms_scopes').insert({ org_id: s.org_id, kind: t.kind, value: t.value, status: 'active', ...row }).select('id').single();
        if (w.error) {
            if (w.error.code === 'PGRST204' || w.error.code === '42703' || /origin|pinned_addresses|cnii_submission_id/.test(w.error.message)) return { ok: false as const, status: 503, error: P18_MISSING };
            throw Object.assign(new Error(w.error.message), { code: w.error.code });
        }
        results.push({ target: t.value, scope_id: w.data.id, outcome: ex ? 'updated' : 'created' });
    }
    const authorisation = {
        scope_ids: results.filter((r) => r.outcome !== 'existing_vms_scope').map((r) => r.scope_id), targets: results.map((r) => r.target), approved_addresses: pins,
        reference: input.reference, evidence: input.evidence, activities: { discovery: true, ports: input.allow_port_scan, vuln: input.allow_vuln_scan },
        approved_by: by, approved_at: new Date(now).toISOString(), expires_at: expires, revoked_by: null, revoked_at: null,
    };
    const upd = await db().from('cnii_submissions').update({ authorisation, resolution: res, ips: current.map((a) => a.ip), resolved_at: res.resolved_at, updated_at: new Date(now).toISOString() }).eq('id', s.id).select('*').single();
    if (upd.error) return { ok: false as const, status: /authorisation/.test(upd.error.message) ? 503 : 502, error: /authorisation/.test(upd.error.message) ? P18_MISSING : 'The scope entries were written but the submission could not be updated' };
    // Now inside scope: add the values to the organisation's inventory.
    const link = await linkToInventory(s.org_id, s.kind, s.value, res, await allScopes());
    await db().from('cnii_submissions').update({ asset_ids: [...new Set([...((upd.data.asset_ids as string[]) ?? []), ...link.asset_ids])] }).eq('id', s.id);
    return { ok: true as const, results, authorisation, link };
}

/** Revokes the scope entries a CNII approval created and stops its Full Assessment schedules. */
export async function revokeIntakeAuthorisation(s: Submission, by: string, reason: string) {
    const now = new Date().toISOString();
    const { data: scopes, error } = await db().from('vms_scopes').update({ status: 'revoked', revoked_by: by, revoked_at: now }).eq('cnii_submission_id', s.id).eq('origin', 'cnii').eq('status', 'active').select('id, value');
    if (error) return { ok: false as const, status: /origin|cnii_submission_id/.test(error.message) ? 503 : 502, error: /origin|cnii_submission_id/.test(error.message) ? P18_MISSING : 'Could not revoke' };
    const ids = (scopes ?? []).map((x) => x.id);
    if (ids.length) await db().from('vms_scan_schedules').update({ enabled: false, last_result: `Disabled: CNII authorisation revoked by ${by}`, updated_at: now }).in('scope_id', ids);
    const auth = { ...((s.authorisation as Record<string, unknown> | null) ?? {}), revoked_by: by, revoked_at: now, revoke_reason: reason };
    await db().from('cnii_submissions').update({ authorisation: auth, updated_at: now }).eq('id', s.id);
    return { ok: true as const, revoked: (scopes ?? []).map((x) => x.value) };
}
