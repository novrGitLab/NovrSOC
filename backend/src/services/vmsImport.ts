// VMS asset onboarding (phase P27): Wazuh agents by group, and manual IP / domain / CIDR / CSV
// imports, into the one asset inventory. Imports add assets; they never add or widen scope. An
// imported asset outside an approved scope is listed as "not authorised" and is not scanned.
//
// Wazuh: a group can be imported only by the organisation it is mapped to (wazuh_group_org_map);
// an agent whose groups map to more than one organisation is left out (ambiguous ownership). Agents
// are always re-read from Wazuh on import: nothing the browser sends is trusted beyond which agent
// ids to take. Endpoints are matched by agent id, then by name — the same as the hourly Wazuh sync
// (services/wazuhVulnSync.ts), which keeps them current afterwards. IP discovery reads each agent's
// interface addresses (syscollector netaddr) for the preview and the import record; the endpoint's
// scanned address stays the agent's registered one, as the sync maintains it.
//
// Manual / CSV: one value per row (IP, hostname/domain or CIDR), with optional type, owner and
// criticality. Rows are validated and de-duplicated within the batch and against the inventory;
// a dry run reports what would happen without writing anything.

import { isIP } from 'net';
import { getSupabase } from './geoEnrichment';
import { getAgentsForGroup, type WazuhAgent } from '../lib/wazuh-group';
import { getAgentAddresses } from './wazuh';
import { parseCidr } from '../lib/cidr';
import { parseTarget, coveringScope, type ScopeEntry, type Activity } from '../lib/vmsScope';
import { isPrivateAddress } from './emailsec/safeFetch';
import { refreshEligibility } from './vmsEligibility';

export const MAX_IMPORT_ROWS = 1000;
export const MAX_CSV_BYTES = 512 * 1024;
const ACTIVITIES: Activity[] = ['discovery', 'ports', 'vuln'];

export interface Authorisation { status: 'authorised' | 'pending_approval' | 'not_authorised' | 'not_applicable'; activities: Activity[]; scope_id: string | null; expires_at: string | null }

/** Whether (and for what) a target is inside an approved scope; pending requests are reported as such. */
export function authorisationFor(target: string | null, active: ScopeEntry[], pending: ScopeEntry[], now = Date.now()): Authorisation {
    const t = target ? parseTarget(target) : null;
    if (!t) return { status: 'not_applicable', activities: [], scope_id: null, expires_at: null };
    const activities = ACTIVITIES.filter((a) => coveringScope(t, active, a, now));
    if (activities.length) {
        const s = coveringScope(t, active, activities[activities.length - 1], now)!;
        return { status: 'authorised', activities, scope_id: s.id, expires_at: s.expires_at };
    }
    // A pending entry is "usable" only once active: test it as if it were.
    const asActive = pending.map((p) => ({ ...p, status: 'active' as const }));
    if (ACTIVITIES.some((a) => coveringScope(t, asActive, a, now))) return { status: 'pending_approval', activities: [], scope_id: null, expires_at: null };
    return { status: 'not_authorised', activities: [], scope_id: null, expires_at: null };
}

/** The address or name an asset would be scanned at. */
export const scanTargetOf = (a: { asset_type: string; value: string; ips?: string[] | null }) => (a.asset_type === 'endpoint' ? (a.ips ?? [])[0] ?? null : a.asset_type === 'cidr' || a.asset_type === 'asn' ? null : a.value);

export async function scopesForAuthorisation(org: string): Promise<{ active: ScopeEntry[]; pending: ScopeEntry[] }> {
    const { data } = await getSupabase()!.from('vms_scopes').select('*').eq('org_id', org).in('status', ['active', 'pending']);
    const rows = (data ?? []) as ScopeEntry[];
    return { active: rows.filter((s) => s.status === 'active'), pending: rows.filter((s) => s.status === 'pending') };
}

// ── Manual and CSV ────────────────────────────────────────────────────────────────────────────
export interface ImportRow { value: string; type?: string; owner?: string; criticality?: string }
export interface RowResult { row: number; value: string; type: string | null; status: 'new' | 'existing' | 'duplicate' | 'invalid'; reason?: string; asset_id?: string; authorisation?: Authorisation }

const CRIT = ['low', 'medium', 'high', 'critical'];

/** A CSV body as rows: an optional header naming value,type,owner,criticality; otherwise column 1 is the value. */
export function parseCsv(text: string): { ok: true; rows: ImportRow[] } | { ok: false; error: string } {
    if (Buffer.byteLength(text, 'utf8') > MAX_CSV_BYTES) return { ok: false, error: `The CSV is larger than ${MAX_CSV_BYTES / 1024} KB` };
    const lines = text.replace(/^﻿/, '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    if (!lines.length) return { ok: false, error: 'The CSV has no rows' };
    const split = (l: string) => l.split(',').map((c) => c.trim().replace(/^"(.*)"$/, '$1'));
    const head = split(lines[0]).map((h) => h.toLowerCase());
    const hasHeader = head.includes('value') || head.includes('asset') || head.includes('target');
    const col = (n: string, ...alts: string[]) => [n, ...alts].map((x) => head.indexOf(x)).find((i) => i >= 0) ?? -1;
    const iv = hasHeader ? col('value', 'asset', 'target') : 0;
    const it = hasHeader ? col('type') : -1, io = hasHeader ? col('owner') : -1, ic = hasHeader ? col('criticality') : -1;
    const rows = (hasHeader ? lines.slice(1) : lines).map((l) => {
        const c = split(l);
        return { value: c[iv] ?? '', ...(it >= 0 && c[it] ? { type: c[it] } : {}), ...(io >= 0 && c[io] ? { owner: c[io] } : {}), ...(ic >= 0 && c[ic] ? { criticality: c[ic] } : {}) };
    });
    if (rows.length > MAX_IMPORT_ROWS) return { ok: false, error: `At most ${MAX_IMPORT_ROWS} rows per import` };
    return { ok: true, rows };
}

/** The asset a row describes, or why it is not valid. */
export function normaliseRow(r: ImportRow): { ok: true; asset_type: 'ip' | 'host' | 'domain' | 'cidr'; value: string; exposure: 'internet' | 'internal' | 'unknown' } | { ok: false; reason: string } {
    const raw = (r.value ?? '').trim();
    const type = (r.type ?? '').trim().toLowerCase();
    if (!raw) return { ok: false, reason: 'empty value' };
    if (type && !['ip', 'domain', 'host', 'cidr'].includes(type)) return { ok: false, reason: `unknown type "${type.slice(0, 20)}" (ip, domain, host or cidr)` };
    if (type === 'cidr' || (!type && raw.includes('/'))) {
        const c = parseCidr(raw);
        if (!c || !raw.includes('/')) return { ok: false, reason: 'not a valid CIDR range' };
        const value = `${c.address}/${c.prefix}`;
        return { ok: true, asset_type: 'cidr', value, exposure: isPrivateAddress(c.address) ? 'internal' : 'internet' };
    }
    const t = parseTarget(raw);
    if (!t) return { ok: false, reason: 'not an IP address or hostname' };
    if (t.type === 'ip') {
        if (type && type !== 'ip') return { ok: false, reason: 'an IP address must have type ip' };
        return { ok: true, asset_type: 'ip', value: t.value, exposure: isPrivateAddress(t.value) ? 'internal' : 'internet' };
    }
    if (type === 'ip') return { ok: false, reason: 'not an IP address' };
    return { ok: true, asset_type: type === 'domain' ? 'domain' : type === 'host' ? 'host' : (t.value.split('.').length <= 2 ? 'domain' : 'host'), value: t.value, exposure: 'unknown' };
}

/** Imports (or, with dryRun, previews) rows into the organisation's inventory. Never touches scope. */
export async function importRows(org: string, by: string, rows: ImportRow[], source: 'manual' | 'csv', dryRun: boolean): Promise<{ results: RowResult[]; counts: Record<string, number> }> {
    const supabase = getSupabase()!;
    const scopes = await scopesForAuthorisation(org);
    const results: RowResult[] = [];
    const seen = new Set<string>();
    const valid: { i: number; r: ImportRow; n: { asset_type: string; value: string; exposure: string } }[] = [];
    rows.slice(0, MAX_IMPORT_ROWS).forEach((r, i) => {
        const n = normaliseRow(r);
        if (!n.ok) { results.push({ row: i + 1, value: String(r.value ?? '').slice(0, 253), type: null, status: 'invalid', reason: n.reason }); return; }
        const crit = (r.criticality ?? '').trim().toLowerCase();
        if (crit && !CRIT.includes(crit)) { results.push({ row: i + 1, value: n.value, type: n.asset_type, status: 'invalid', reason: 'criticality must be low, medium, high or critical' }); return; }
        const key = `${n.asset_type}:${n.value}`;
        if (seen.has(key)) { results.push({ row: i + 1, value: n.value, type: n.asset_type, status: 'duplicate', reason: 'listed earlier in this import' }); return; }
        seen.add(key);
        valid.push({ i, r, n });
    });
    // Existing assets, by (type, value), in chunks.
    const existing = new Map<string, { id: string; discovery_sources: string[] | null; owner: string | null; criticality: string }>();
    for (const type of [...new Set(valid.map((v) => v.n.asset_type))]) {
        const vals = valid.filter((v) => v.n.asset_type === type).map((v) => v.n.value);
        for (let k = 0; k < vals.length; k += 200) {
            const { data } = await supabase.from('vms_assets').select('id, value, asset_type, discovery_sources, owner, criticality').eq('org_id', org).eq('asset_type', type).in('value', vals.slice(k, k + 200));
            for (const a of data ?? []) existing.set(`${a.asset_type}:${a.value}`, a as never);
        }
    }
    const now = new Date().toISOString();
    for (const { i, r, n } of valid) {
        const auth = authorisationFor(n.asset_type === 'cidr' ? null : n.value, scopes.active, scopes.pending);
        const owner = (r.owner ?? '').trim().slice(0, 120) || null;
        const crit = (r.criticality ?? '').trim().toLowerCase() || null;
        const ex = existing.get(`${n.asset_type}:${n.value}`);
        if (ex) {
            if (!dryRun) {
                const patch: Record<string, unknown> = {};
                if (!(ex.discovery_sources ?? []).includes(source)) patch.discovery_sources = [...(ex.discovery_sources ?? []), source];
                if (owner && owner !== ex.owner) patch.owner = owner;
                if (crit && crit !== ex.criticality) patch.criticality = crit;
                if (Object.keys(patch).length) await supabase.from('vms_assets').update(patch).eq('id', ex.id).eq('org_id', org);
            }
            results.push({ row: i + 1, value: n.value, type: n.asset_type, status: 'existing', asset_id: ex.id, authorisation: auth });
            continue;
        }
        if (dryRun) { results.push({ row: i + 1, value: n.value, type: n.asset_type, status: 'new', authorisation: auth }); continue; }
        const ins = await supabase.from('vms_assets').insert({
            org_id: org, asset_type: n.asset_type, value: n.value, hostnames: n.asset_type === 'host' || n.asset_type === 'domain' ? [n.value] : [],
            ips: n.asset_type === 'ip' ? [n.value] : [], exposure: n.exposure, owner, criticality: crit ?? 'medium', discovery_sources: [source], first_seen: now, last_seen: now, status: 'active',
        }).select('id').single();
        if (ins.error || !ins.data) {
            results.push({ row: i + 1, value: n.value, type: n.asset_type, status: /duplicate|23505/.test(ins.error?.message ?? '') ? 'existing' : 'invalid', reason: /duplicate|23505/.test(ins.error?.message ?? '') ? undefined : 'could not be stored' });
            continue;
        }
        await supabase.from('vms_asset_events').insert({ org_id: org, asset_id: ins.data.id, event: 'asset_new', details: { value: n.value, source, imported_by: by, authorisation: auth.status } });
        results.push({ row: i + 1, value: n.value, type: n.asset_type, status: 'new', asset_id: ins.data.id, authorisation: auth });
    }
    results.sort((a, b) => a.row - b.row);
    const counts: Record<string, number> = { new: 0, existing: 0, duplicate: 0, invalid: 0, authorised: 0, not_authorised: 0, pending_approval: 0 };
    for (const r of results) { counts[r.status]++; if (r.authorisation && r.status !== 'invalid' && r.status !== 'duplicate') counts[r.authorisation.status] = (counts[r.authorisation.status] ?? 0) + 1; }
    return { results, counts };
}

// ── Wazuh by group ────────────────────────────────────────────────────────────────────────────
export interface WazuhDeps { agentsForGroup?: (g: string) => Promise<WazuhAgent[]>; addresses?: (id: string) => Promise<{ address: string }[]> }
const agentsOf = (deps: WazuhDeps) => deps.agentsForGroup ?? ((g: string) => getAgentsForGroup(g, { strict: true }));

/** The groups mapped to this organisation (never another organisation's). */
export async function orgGroups(org: string): Promise<string[]> {
    const { data, error } = await getSupabase()!.from('wazuh_group_org_map').select('wazuh_group').eq('org_id', org);
    if (error) throw new Error(error.message);
    return [...new Set((data ?? []).map((r) => r.wazuh_group as string))].sort();
}

export interface AgentPreview {
    agent_id: string; name: string; registered_ip: string | null; addresses: string[]; os: string | null; status: string; last_keepalive: string | null; groups: string[];
    importable: boolean; reason: string | null; existing_asset_id: string | null; authorisation: Authorisation;
}

/** The group's agents, as they would be imported. `discover` reads each agent's interface addresses. */
export async function previewGroup(org: string, group: string, discover: boolean, deps: WazuhDeps = {}): Promise<{ ok: true; agents: AgentPreview[] } | { ok: false; status: number; error: string }> {
    const supabase = getSupabase()!;
    if (!(await orgGroups(org)).includes(group)) return { ok: false, status: 404, error: 'That Wazuh group is not mapped to this organisation' };
    let agents: WazuhAgent[];
    try { agents = await agentsOf(deps)(group); } catch (err) { return { ok: false, status: 503, error: `Wazuh could not be read: ${err instanceof Error ? err.message : String(err)}`.slice(0, 300) }; }
    // Every other group these agents belong to, and the organisations those map to.
    const allGroups = [...new Set(agents.flatMap((a) => a.group ?? []))];
    const { data: maps } = allGroups.length ? await supabase.from('wazuh_group_org_map').select('wazuh_group, org_id').in('wazuh_group', allGroups) : { data: [] };
    const orgsOfGroup = new Map<string, Set<string>>();
    for (const m of maps ?? []) { const s = orgsOfGroup.get(m.wazuh_group) ?? new Set<string>(); s.add(m.org_id); orgsOfGroup.set(m.wazuh_group, s); }
    const ids = agents.map((a) => a.id).filter(Boolean);
    const { data: existingRows } = ids.length ? await supabase.from('vms_assets').select('id, wazuh_agent_id, value').eq('org_id', org).eq('asset_type', 'endpoint').in('wazuh_agent_id', ids) : { data: [] };
    const existing = new Map((existingRows ?? []).map((r) => [r.wazuh_agent_id as string, r.id as string]));
    const scopes = await scopesForAuthorisation(org);
    const addr = deps.addresses ?? getAgentAddresses;
    const out: AgentPreview[] = [];
    for (const a of agents.slice(0, 500)) {
        const orgs = new Set((a.group ?? []).flatMap((g) => [...(orgsOfGroup.get(g) ?? [])]));
        const ambiguous = orgs.size > 1 || (orgs.size === 1 && !orgs.has(org));
        let addresses: string[] = [];
        if (discover && a.id && a.id !== '000') { try { addresses = (await addr(a.id)).map((x) => x.address).slice(0, 32); } catch { addresses = []; } }
        const reason = a.id === '000' ? 'the Wazuh manager is not an endpoint' : ambiguous ? 'its Wazuh groups belong to more than one organisation' : null;
        out.push({
            agent_id: a.id, name: a.name, registered_ip: a.ip && isIP(a.ip) ? a.ip : null, addresses: [...new Set([...(a.ip && isIP(a.ip) ? [a.ip] : []), ...addresses])], os: a.os ?? null,
            status: a.status, last_keepalive: a.lastKeepAlive ?? null, groups: a.group ?? [], importable: !reason, reason,
            existing_asset_id: existing.get(a.id) ?? null, authorisation: authorisationFor(a.ip && isIP(a.ip) ? a.ip : null, scopes.active, scopes.pending),
        });
    }
    return { ok: true, agents: out };
}

/** Imports the chosen agents of a group as endpoints (re-read from Wazuh; nothing trusted from the client). */
export async function importGroup(org: string, by: string, group: string, agentIds: string[], discover: boolean, deps: WazuhDeps = {}):
    Promise<{ ok: true; imported: number; updated: number; skipped: { agent_id: string; reason: string }[] } | { ok: false; status: number; error: string }> {
    const p = await previewGroup(org, group, discover, deps);
    if (!p.ok) return p;
    const supabase = getSupabase()!;
    const want = new Set(agentIds);
    const skipped: { agent_id: string; reason: string }[] = [];
    for (const id of want) if (!p.agents.some((a) => a.agent_id === id)) skipped.push({ agent_id: id, reason: 'not an agent of this group' });
    let imported = 0, updated = 0;
    const now = new Date().toISOString();
    for (const a of p.agents.filter((x) => want.has(x.agent_id))) {
        if (!a.importable) { skipped.push({ agent_id: a.agent_id, reason: a.reason ?? 'not importable' }); continue; }
        const value = a.name.toLowerCase();
        const ip = a.registered_ip;
        const fields: Record<string, unknown> = {
            wazuh_agent_id: a.agent_id, ips: ip ? [ip] : [], exposure: ip ? (isPrivateAddress(ip) ? 'internal' : 'internet') : 'unknown', alive: a.status === 'active',
            last_seen: now, status: 'active', os: a.os, agent_status: a.status, agent_groups: a.groups,
        };
        const ex = a.existing_asset_id ?? (await supabase.from('vms_assets').select('id').eq('org_id', org).eq('asset_type', 'endpoint').eq('value', value).maybeSingle()).data?.id ?? null;
        if (ex) {
            const { data: cur } = await supabase.from('vms_assets').select('discovery_sources').eq('id', ex).eq('org_id', org).maybeSingle();
            const sources = (cur?.discovery_sources as string[] | null) ?? [];
            const u = await supabase.from('vms_assets').update({ ...fields, ...(sources.includes('wazuh') ? {} : { discovery_sources: [...sources, 'wazuh'] }) }).eq('id', ex).eq('org_id', org);
            if (u.error) { skipped.push({ agent_id: a.agent_id, reason: 'could not be stored' }); continue; }
            await supabase.from('vms_asset_events').insert({ org_id: org, asset_id: ex, event: 'asset_changed', details: { source: 'wazuh_import', group, imported_by: by, addresses_seen: a.addresses } });
            updated++;
        } else {
            const ins = await supabase.from('vms_assets').insert({ org_id: org, asset_type: 'endpoint', value, hostnames: [], discovery_sources: ['wazuh'], first_seen: now, ...fields }).select('id').single();
            if (ins.error || !ins.data) { skipped.push({ agent_id: a.agent_id, reason: 'could not be stored' }); continue; }
            await supabase.from('vms_asset_events').insert({ org_id: org, asset_id: ins.data.id, event: 'asset_new', details: { value, source: 'wazuh_import', group, imported_by: by, addresses_seen: a.addresses } });
            imported++;
        }
    }
    // Where each endpoint may now be scanned, given today's scope (never widened by an import).
    void refreshEligibility(org).catch(() => undefined);
    return { ok: true, imported, updated, skipped };
}
