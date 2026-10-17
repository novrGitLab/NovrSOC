// /api/cnii — CNII Watch (phase P9). A sector view over VMS (scope, inventory, findings) and the
// Threat Information System (indicators, matches). CNII keeps no asset or findings store of its
// own: an organisation is classified into a sector (cnii_org_profiles) and everything else is
// that organisation's VMS and Threat Information records. Nothing here reads Wazuh.
// Mounted behind requireAuth in index.ts; each route resolves its permission and organisation
// (lib/permissions.ts). Staff act on another organisation with X-Org-Id, which is audited.
//
// Across organisations (cnii:sector — super_admin, soc_manager, analyst; never client roles):
//   GET  /sectors                    per sector: organisations, assets, open findings (confirmed vs
//                                    unconfirmed), KEV, new indicator matches, scope and collection gaps
//   GET  /sectors/:sector            the same per organisation in one sector
//   GET  /organisations              every organisation with its CNII profile, to classify them
//   POST /lookup { ip }              passive triage of one address: registry holder, a suggested
//                                    sector, indicator matches, which organisation (if any) has it
//                                    in authorised scope. Nothing is stored; the lookup is audited.
//   GET  /legacy                     rows of the pre-P9 cnii_assets table and whether each was imported
// Intake (P17, services/cniiIntake.ts; cnii:sector plus the permission named):
//   POST /intake { value }           submit or re-check a domain or IP: resolve, gather evidence, link to a
//                                    designated CNII organisation only from authorised scope; else a candidate
//   GET  /intake?status              submissions with severity counts and the latest assessment status
//   GET  /intake/:id                 one submission with its assessments, findings (with evidence) and schedules
//   POST /intake/:id/decision        cnii:manage  { decision: confirm|reject, org_id?, note }
//   POST /intake/:id/assess          vms:scan     { targets? } Full Assessment of its in-scope values
//   POST /intake/:id/schedule        vms:scope    { days ≤ 60 } Full Assessment every 48 h until the end date
// P18:
//   POST /intake { values }          bulk: comma/space/newline-separated, up to 25; a result per entry
//   POST /intake/manual              { org_id, sector_id, ip, justification } — registered, unverified,
//                                    authorises nothing (a candidate until a manager confirms it)
//   POST /intake/:id/authorise       cnii:manage + vms:scope  { reference, evidence, expires_days ≤ 90,
//                                    allow_port_scan, allow_vuln_scan, addresses? } — exact scope entries
//                                    (origin cnii; a domain pinned to its approved addresses)
//   POST /intake/:id/authorise/revoke  cnii:manage + vms:scope  { reason }
// One organisation (the caller's, or X-Org-Id for staff):
//   GET  /profile                    cnii:read    sector profile + history, scope, summary
//   PUT  /profile                    cnii:manage  { sector_id, subfield?, designation, designation_reference?, notes? }
//   GET  /inventory                  cnii:read    assets with authorisation status, observations, findings, matches
//   GET  /assets/:id                 cnii:read    one asset with all of that
//   POST /collect { scope_id, targets? }  vms:scan  queues passive collection (VMS passive_osint)
//   POST /legacy/:id/import          cnii:manage  moves a legacy row into this organisation's inventory —
//                                    only when its address is inside the organisation's active scope
// Scope approval, active scans, findings workflow and AI stay on /api/vms, /api/ti and /api/ai.

import { Router, type Response } from 'express';
import { isIP } from 'net';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { CNII_SECTORS, SECTOR_BY_ID } from '../lib/cnii-sectors';
import { classifySector } from '../lib/cnii-classify';
import { coveringScope, parseTarget, type ScopeEntry } from '../lib/vmsScope';
import { queueScan } from './vms';
import { lookupIP, openctiConfigured } from '../lib/opencti';
import { asHolder, ipNetworkInfo } from '../services/ripeStat';
import { storeObservations, type Obs } from '../services/cniiPassive';
import { ingestPassiveClaims } from '../services/vmsFindings';
import { cleanAsHolder } from '../lib/spiderfoot';
import rateLimit from 'express-rate-limit';
import { parseIntake, parseIntakeList, submitIntake, decideIntake, assessIntake, scheduleIntake, intakeResults, registerManual, authoriseIntake, revokeIntakeAuthorisation, isMissingP17, P17_MISSING, SCHEDULE_MAX_DAYS, MAX_BULK, MAX_AUTH_DAYS, type Submission } from '../services/cniiIntake';

const router = Router();
const OPEN = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
const P9_MISSING = 'CNII Watch is not set up yet (run sql/2026-10-17_p9_cnii.sql after the P4–P7 files)';
const missing = (e: { message?: string; code?: string } | null) => !!e && (e.code === '42P01' || e.code === 'PGRST205' || /does not exist|Could not find|schema cache/i.test(e.message ?? ''));
const fail = (res: Response, e: { message?: string; code?: string }) => res.status(missing(e) ? 503 : 502).json({ error: missing(e) ? P9_MISSING : dbErrorMessage(e) });
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const db = () => getSupabase()!;

// ── Shared: per-organisation figures, measured from VMS and Threat Information records ───────
export interface OrgStats {
    assets: number; probable_assets: number; internet_facing: number;
    open_findings: { P1: number; P2: number; P3: number; P4: number };
    confirmed_p1_p2: number; unconfirmed_open: number; kev_open: number; new_matches: number;
    active_scopes: number; passive_only_scopes: number; scope_expires_next: string | null;
    last_collection: { at: string; status: string } | null;
}
const emptyStats = (): OrgStats => ({ assets: 0, probable_assets: 0, internet_facing: 0, open_findings: { P1: 0, P2: 0, P3: 0, P4: 0 }, confirmed_p1_p2: 0, unconfirmed_open: 0, kev_open: 0, new_matches: 0, active_scopes: 0, passive_only_scopes: 0, scope_expires_next: null, last_collection: null });

export async function orgStats(orgIds: string[]): Promise<Record<string, OrgStats>> {
    const out: Record<string, OrgStats> = Object.fromEntries(orgIds.map((o) => [o, emptyStats()]));
    if (!orgIds.length) return out;
    const now = new Date().toISOString();
    const [assets, findings, matches, scopes, runs] = await Promise.all([
        db().from('vms_assets').select('org_id, confidence, exposure').in('org_id', orgIds).eq('status', 'active').limit(50_000),
        db().from('vms_findings').select('org_id, priority, evidence_class, cve_ids').in('org_id', orgIds).in('status', OPEN).limit(50_000),
        db().from('ti_matches').select('org_id').in('org_id', orgIds).eq('status', 'new').limit(50_000),
        db().from('vms_scopes').select('org_id, allow_discovery, expires_at').in('org_id', orgIds).eq('status', 'active').gt('expires_at', now),
        db().from('vms_scan_jobs').select('org_id, finished_at, status').in('org_id', orgIds).eq('kind', 'passive_osint').not('finished_at', 'is', null).order('finished_at', { ascending: false }).limit(5000),
    ]);
    for (const e of [assets.error, findings.error, scopes.error]) if (e) throw e;
    for (const a of assets.data ?? []) {
        const s = out[a.org_id]; if (!s) continue;
        s.assets++;
        if (a.confidence === 'probable') s.probable_assets++;
        if (a.exposure === 'internet') s.internet_facing++;
    }
    const cves = new Set<string>();
    for (const f of findings.data ?? []) for (const c of f.cve_ids ?? []) cves.add(c);
    const kev = new Set<string>();
    const list = [...cves];
    for (let i = 0; i < list.length; i += 200) {
        const { data } = await db().from('cve_intel').select('cve_id').in('cve_id', list.slice(i, i + 200)).eq('kev', true);
        for (const k of data ?? []) kev.add(k.cve_id);
    }
    for (const f of findings.data ?? []) {
        const s = out[f.org_id]; if (!s) continue;
        const p = (f.priority ?? 'P4') as keyof OrgStats['open_findings'];
        if (p in s.open_findings) s.open_findings[p]++;
        const unconfirmed = f.evidence_class === 'version_match' || f.evidence_class === 'intelligence';
        if (unconfirmed) s.unconfirmed_open++;
        else if (p === 'P1' || p === 'P2') s.confirmed_p1_p2++;
        if ((f.cve_ids ?? []).some((c: string) => kev.has(c))) s.kev_open++;
    }
    for (const m of matches.data ?? []) if (out[m.org_id]) out[m.org_id].new_matches++;
    for (const sc of scopes.data ?? []) {
        const s = out[sc.org_id]; if (!s) continue;
        s.active_scopes++;
        if (sc.allow_discovery === false) s.passive_only_scopes++;
        if (!s.scope_expires_next || sc.expires_at < s.scope_expires_next) s.scope_expires_next = sc.expires_at;
    }
    for (const r of runs.data ?? []) {
        const s = out[r.org_id];
        if (s && !s.last_collection) s.last_collection = { at: r.finished_at, status: r.status };
    }
    return out;
}

async function profiles(sector?: string) {
    let q = db().from('cnii_org_profiles').select('*').order('org_id');
    if (sector) q = q.eq('sector_id', sector);
    return q;
}

/** Gaps an analyst must know before trusting the figures. */
function gaps(s: OrgStats): string[] {
    const g: string[] = [];
    if (!s.active_scopes) g.push('no active authorised scope: nothing is monitored');
    if (s.active_scopes && !s.last_collection) g.push('passive collection has never run');
    else if (s.last_collection && Date.now() - Date.parse(s.last_collection.at) > 8 * 86_400_000) g.push('passive collection older than 8 days');
    if (s.last_collection?.status === 'failed') g.push('last passive collection failed');
    if (s.scope_expires_next && Date.parse(s.scope_expires_next) - Date.now() < 14 * 86_400_000) g.push('authorised scope expires within 14 days');
    return g;
}

// ── Across organisations ────────────────────────────────────────────────────────────────────
router.get('/sectors', requirePermission('cnii:sector'), async (_req: AuthRequest, res) => {
    const { data: profs, error } = await profiles();
    if (error) { fail(res, error); return; }
    try {
        const stats = await orgStats((profs ?? []).map((p) => p.org_id));
        res.json({
            sectors: CNII_SECTORS.map((sec) => {
                const orgs = (profs ?? []).filter((p) => p.sector_id === sec.id);
                const t = emptyStats();
                for (const o of orgs) {
                    const s = stats[o.org_id];
                    t.assets += s.assets; t.probable_assets += s.probable_assets; t.internet_facing += s.internet_facing;
                    for (const k of ['P1', 'P2', 'P3', 'P4'] as const) t.open_findings[k] += s.open_findings[k];
                    t.confirmed_p1_p2 += s.confirmed_p1_p2; t.unconfirmed_open += s.unconfirmed_open; t.kev_open += s.kev_open; t.new_matches += s.new_matches;
                }
                return {
                    id: sec.id, organisations: orgs.length, designated: orgs.filter((o) => o.designation === 'designated').length,
                    unmonitored: orgs.filter((o) => !stats[o.org_id].active_scopes).length,
                    with_gaps: orgs.filter((o) => gaps(stats[o.org_id]).length).length,
                    assets: t.assets, probable_assets: t.probable_assets, internet_facing: t.internet_facing, open_findings: t.open_findings,
                    confirmed_p1_p2: t.confirmed_p1_p2, unconfirmed_open: t.unconfirmed_open, kev_open: t.kev_open, new_matches: t.new_matches,
                };
            }),
        });
    } catch (e) { fail(res, e as { message?: string }); }
});

router.get('/sectors/:sector', requirePermission('cnii:sector'), async (req: AuthRequest, res) => {
    if (!SECTOR_BY_ID[req.params.sector]) { res.status(404).json({ error: 'Unknown sector' }); return; }
    const { data: profs, error } = await profiles(req.params.sector);
    if (error) { fail(res, error); return; }
    try {
        const ids = (profs ?? []).map((p) => p.org_id);
        const [stats, orgs] = await Promise.all([orgStats(ids), ids.length ? db().from('organisations').select('slug, name').in('slug', ids) : Promise.resolve({ data: [] as { slug: string; name: string }[] })]);
        const names = new Map((orgs.data ?? []).map((o) => [o.slug, o.name]));
        // Confirmed intake submissions in this sector (P17); absent before that SQL.
        const { data: watch, error: wErr } = await db().from('cnii_submissions').select('id, value, kind, org_id, subfield, basis, ips, updated_at, authorisation').eq('status', 'confirmed').eq('sector_id', req.params.sector).order('updated_at', { ascending: false }).limit(500);
        // Registered by hand for this sector but not verified (P18): listed apart, never as confirmed.
        const { data: reg } = wErr ? { data: null } : await db().from('cnii_submissions').select('id, value, org_id, reason, updated_at').eq('status', 'candidate').eq('basis', 'manual_registration').eq('sector_id', req.params.sector).order('updated_at', { ascending: false }).limit(500);
        res.json({ sector: req.params.sector, organisations: (profs ?? []).map((p) => ({ profile: p, name: names.get(p.org_id) ?? p.org_id, stats: stats[p.org_id], gaps: gaps(stats[p.org_id]) })), watchlist: wErr ? null : watch ?? [], registered: wErr ? null : reg ?? [] });
    } catch (e) { fail(res, e as { message?: string }); }
});

router.get('/organisations', requirePermission('cnii:sector'), async (_req: AuthRequest, res) => {
    const [orgs, profs] = await Promise.all([db().from('organisations').select('slug, name, industry').order('name').limit(2000), profiles()]);
    if (orgs.error) { fail(res, orgs.error); return; }
    if (profs.error) { fail(res, profs.error); return; }
    const byOrg = new Map((profs.data ?? []).map((p) => [p.org_id, p]));
    res.json({ organisations: (orgs.data ?? []).map((o) => ({ slug: o.slug, name: o.name, industry: o.industry ?? null, profile: byOrg.get(o.slug) ?? null })) });
});

router.post('/lookup', requirePermission('cnii:sector'), async (req: AuthRequest, res) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    if (!isIP(ip)) { res.status(400).json({ error: 'Provide one IP address' }); return; }
    const sources: Record<string, string> = {};
    const net = await ipNetworkInfo(ip).catch(() => null);
    sources.ripestat = net ? 'ok' : 'no answer';
    const asn = net?.asns[0] ?? null;
    const holderRaw = asn ? await asHolder(asn).catch(() => null) : null;
    const holder = holderRaw ? cleanAsHolder(holderRaw) : null;
    // The raw holder keeps the AS handle (e.g. "NCC-AS"), which often names the operator.
    const suggestion = classifySector(holder ?? undefined, holderRaw ?? undefined, asn ?? undefined, '');
    const v = ip.toLowerCase();
    const [ind, byValue, byIps] = await Promise.all([
        db().from('ti_indicators').select('id, value, status, max_confidence, malware_families, threat_types, source_count, last_seen').eq('type', 'ip').eq('value', v).maybeSingle(),
        db().from('vms_assets').select('id, org_id, asset_type, value, confidence, status').eq('value', v).limit(20),
        db().from('vms_assets').select('id, org_id, asset_type, value, confidence, status').contains('ips', [v]).limit(20),
    ]);
    const inv = { data: [...new Map([...(byValue.data ?? []), ...(byIps.data ?? [])].map((a) => [a.id, a])).values()] };
    let opencti: unknown = null;
    if (openctiConfigured()) {
        try { opencti = (await lookupIP(ip)).threatIntel; sources.opencti = 'ok'; } catch (e) { sources.opencti = `failed: ${(e as Error).message.slice(0, 120)}`; }
    } else sources.opencti = 'not configured';
    // Which organisation, if any, holds this address in authorised scope.
    const holders: { org_id: string; asset_id: string; authorised: boolean }[] = [];
    for (const a of inv.data ?? []) {
        const { data: sc } = await db().from('vms_scopes').select('*').eq('org_id', a.org_id).eq('status', 'active');
        holders.push({ org_id: a.org_id, asset_id: a.id, authorised: !!coveringScope({ type: 'ip', value: ip.toLowerCase() }, (sc ?? []) as ScopeEntry[], 'passive') });
    }
    logAudit({ user: actor(req), action: 'CNII_LOOKUP', resource: 'ip', resource_id: ip, org_id: requestOrg(req), ip: req.ip ?? 'unknown', result: 'success', details: 'passive triage lookup; nothing stored' });
    res.json({
        ip, network: net, holder, sector_suggestion: suggestion.sectorId ? suggestion : null,
        indicator: ind.data ?? null, in_inventory_of: holders, opencti, sources,
        note: 'A suggestion from public registry data. It does not show who owns the address, and it authorises nothing.',
    });
});

router.get('/legacy', requirePermission('cnii:sector'), async (_req: AuthRequest, res) => {
    const { data, error } = await db().from('cnii_assets').select('id, ip, hostname, owner, org, asn, sector_id, subfield, open_ports, vuln_count, last_seen, added_at, imported_org_id, imported_asset_id, imported_at, imported_by').order('added_at', { ascending: false }).limit(2000);
    if (error) {
        if (missing(error)) { res.json({ available: false, rows: [] }); return; }
        fail(res, error); return;
    }
    res.json({ available: true, rows: data ?? [] });
});

// ── One organisation ────────────────────────────────────────────────────────────────────────
async function scopesOf(org: string): Promise<ScopeEntry[]> {
    const { data, error } = await db().from('vms_scopes').select('*').eq('org_id', org).order('approved_at', { ascending: false });
    if (error) throw error;
    return (data ?? []) as ScopeEntry[];
}

export type AuthorisationStatus = 'authorised' | 'expired' | 'revoked' | 'not_authorised';
/** How an asset is authorised: the scope entry covering it now, or why none does. */
export function authorisation(asset: { asset_type: string; value: string }, scopes: ScopeEntry[], now = Date.now()) {
    const exact = (s: ScopeEntry) => s.value === asset.value;
    const t = asset.asset_type === 'asn' || asset.asset_type === 'cidr' ? null : parseTarget(asset.value);
    const covers = (list: ScopeEntry[]) => (t ? coveringScope(t, list, 'passive', now) : list.find((s) => s.status === 'active' && Date.parse(s.expires_at) > now && exact(s)) ?? null);
    const live = covers(scopes);
    const view = (s: ScopeEntry, status: AuthorisationStatus) => ({
        status, scope_id: s.id, scope: `${s.kind} ${s.value}`, expires_at: s.expires_at,
        passive: status === 'authorised', discovery: status === 'authorised' && s.allow_discovery !== false, ports: status === 'authorised' && s.allow_port_scan, vuln: status === 'authorised' && s.allow_vuln_scan,
    });
    if (live) return view(live, 'authorised');
    // Not covered now: was it ever? Report the entry that used to cover it.
    const revived = scopes.map((s) => ({ ...s, status: 'active' as const, expires_at: new Date(now + 86_400_000).toISOString() }));
    const past = covers(revived);
    if (past) {
        const real = scopes.find((s) => s.id === past.id)!;
        return view(real, real.status === 'revoked' ? 'revoked' : 'expired');
    }
    return { status: 'not_authorised' as const, scope_id: null, scope: null, expires_at: null, passive: false, discovery: false, ports: false, vuln: false };
}

router.get('/profile', requirePermission('cnii:read'), async (req: AuthRequest, res) => {
    const org = requestOrg(req);
    const [p, h, o] = await Promise.all([
        db().from('cnii_org_profiles').select('*').eq('org_id', org).maybeSingle(),
        db().from('cnii_profile_events').select('*').eq('org_id', org).order('at', { ascending: false }).limit(20),
        db().from('organisations').select('slug, name, industry').eq('slug', org).maybeSingle(),
    ]);
    if (p.error) { fail(res, p.error); return; }
    try {
        const [scopes, stats] = await Promise.all([scopesOf(org), orgStats([org])]);
        res.json({ organisation: o.data ?? { slug: org }, profile: p.data ?? null, history: h.data ?? [], scopes, stats: stats[org], gaps: gaps(stats[org]) });
    } catch (e) { fail(res, e as { message?: string }); }
});

const ProfileBody = z.object({
    sector_id: z.string().refine((s) => !!SECTOR_BY_ID[s], 'unknown sector'),
    subfield: z.string().trim().max(120).nullable().optional(),
    designation: z.enum(['designated', 'candidate']),
    designation_reference: z.string().trim().max(300).nullable().optional(),
    notes: z.string().trim().max(2000).nullable().optional(),
}).strict();

router.put('/profile', requirePermission('cnii:manage'), async (req: AuthRequest, res) => {
    const p = ProfileBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Invalid profile: ${p.error.issues[0]?.path.join('.') || ''} ${p.error.issues[0]?.message ?? ''}`.trim() }); return; }
    const b = p.data;
    if (b.subfield && !SECTOR_BY_ID[b.sector_id].subfields.includes(b.subfield)) { res.status(400).json({ error: 'Unknown sub-entity for this sector' }); return; }
    if (b.designation === 'designated' && !b.designation_reference) { res.status(400).json({ error: 'A designated CNII organisation needs the reference that designates it' }); return; }
    const org = requestOrg(req);
    const { data: prev, error: readErr } = await db().from('cnii_org_profiles').select('*').eq('org_id', org).maybeSingle();
    if (readErr) { fail(res, readErr); return; }
    const now = new Date().toISOString();
    const row = { org_id: org, sector_id: b.sector_id, subfield: b.subfield ?? null, designation: b.designation, designation_reference: b.designation_reference ?? null, notes: b.notes ?? null, updated_by: actor(req), updated_at: now, ...(prev ? {} : { created_by: actor(req), created_at: now }) };
    const { data, error } = prev
        ? await db().from('cnii_org_profiles').update(row).eq('org_id', org).select('*').single()
        : await db().from('cnii_org_profiles').insert(row).select('*').single();
    if (error) { fail(res, error); return; }
    const pick = (x: Record<string, unknown> | null) => (x ? { sector_id: x.sector_id, subfield: x.subfield, designation: x.designation, designation_reference: x.designation_reference } : null);
    await db().from('cnii_profile_events').insert({ org_id: org, actor: actor(req), at: now, from_value: pick(prev), to_value: pick(data) });
    logAudit({ user: actor(req), action: prev ? 'CNII_PROFILE_CHANGED' : 'CNII_PROFILE_CREATED', resource: 'cnii_org_profile', resource_id: org, org_id: org, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
        details: `${prev ? `${prev.sector_id}/${prev.designation} -> ` : ''}${b.sector_id}/${b.designation}${b.designation_reference ? ` ref=${b.designation_reference}` : ''}`.slice(0, 200) });
    res.status(prev ? 200 : 201).json({ profile: data });
});

async function assetDetails(org: string, assetIds: string[]) {
    if (!assetIds.length) return { obs: [], findings: [], matches: [] };
    const [obs, findings, matches] = await Promise.all([
        db().from('vms_observations').select('asset_id, kind, confidence').eq('org_id', org).in('asset_id', assetIds).limit(50_000),
        db().from('vms_findings').select('asset_id, priority, evidence_class, status').eq('org_id', org).in('asset_id', assetIds).in('status', OPEN).limit(50_000),
        db().from('ti_matches').select('entity_id, status').eq('org_id', org).eq('entity_type', 'asset').in('entity_id', assetIds).limit(50_000),
    ]);
    return { obs: obs.data ?? [], findings: findings.data ?? [], matches: matches.data ?? [] };
}

router.get('/inventory', requirePermission('cnii:read'), async (req: AuthRequest, res) => {
    const org = requestOrg(req);
    const { data: assets, error } = await db().from('vms_assets').select('*').eq('org_id', org).order('last_seen', { ascending: false }).limit(2000);
    if (error) { fail(res, error); return; }
    try {
        const scopes = await scopesOf(org);
        const d = await assetDetails(org, (assets ?? []).map((a) => a.id));
        res.json({
            assets: (assets ?? []).map((a) => {
                const f = d.findings.filter((x) => x.asset_id === a.id);
                return {
                    ...a, authorisation: authorisation(a, scopes),
                    observations: d.obs.filter((o) => o.asset_id === a.id).reduce<Record<string, number>>((m, o) => ({ ...m, [o.kind]: (m[o.kind] ?? 0) + 1 }), {}),
                    findings: { open: f.length, confirmed: f.filter((x) => x.evidence_class !== 'version_match' && x.evidence_class !== 'intelligence').length, unconfirmed: f.filter((x) => x.evidence_class === 'version_match' || x.evidence_class === 'intelligence').length, p1_p2: f.filter((x) => x.priority === 'P1' || x.priority === 'P2').length },
                    indicator_matches: d.matches.filter((m) => m.entity_id === a.id).length,
                };
            }),
        });
    } catch (e) { fail(res, e as { message?: string }); }
});

router.get('/assets/:id', requirePermission('cnii:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Asset not found' }); return; }
    const org = requestOrg(req);
    const { data: asset, error } = await db().from('vms_assets').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!asset) { res.status(404).json({ error: 'Asset not found' }); return; }
    try {
        const [scopes, obs, findings, matches, services, events] = await Promise.all([
            scopesOf(org),
            db().from('vms_observations').select('*').eq('org_id', org).eq('asset_id', asset.id).order('last_seen', { ascending: false }).limit(500),
            db().from('vms_findings').select('id, title, priority, risk_score, risk_factors, status, evidence_class, source_class, detected_by, cve_ids, port, first_seen, last_seen, due_at, case_id').eq('org_id', org).eq('asset_id', asset.id).order('risk_score', { ascending: false }).limit(500),
            db().from('ti_matches').select('id, status, matched_field, matched_value, first_matched_at, last_matched_at, case_id, ti_indicators(id, type, value, max_confidence, malware_families, threat_types, source_count, status)').eq('org_id', org).eq('entity_type', 'asset').eq('entity_id', asset.id).limit(200),
            db().from('vms_services').select('*').eq('asset_id', asset.id).order('port'),
            db().from('vms_asset_events').select('*').eq('asset_id', asset.id).order('at', { ascending: false }).limit(100),
        ]);
        res.json({ asset, authorisation: authorisation(asset, scopes), observations: obs.data ?? [], findings: findings.data ?? [], indicator_matches: matches.data ?? [], services: services.data ?? [], events: events.data ?? [] });
    } catch (e) { fail(res, e as { message?: string }); }
});

const Collect = z.object({ scope_id: z.string().uuid(), targets: z.array(z.string().max(253)).max(256).optional() }).strict();
router.post('/collect', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    const p = Collect.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { scope_id, targets?: [host, IP, CIDR or AS number inside that scope entry] }' }); return; }
    const r = await queueScan(requestOrg(req), actor(req), { scope_id: p.data.scope_id, kind: 'passive_osint', targets: p.data.targets });
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.status(r.existing ? 200 : 201).json({ job: r.job, existing: r.existing });
});

router.post('/legacy/:id/import', requirePermission('cnii:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Legacy row not found' }); return; }
    const org = requestOrg(req);
    const { data: row, error } = await db().from('cnii_assets').select('*').eq('id', req.params.id).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!row) { res.status(404).json({ error: 'Legacy row not found' }); return; }
    if (row.imported_at) { res.status(409).json({ error: `Already imported into ${row.imported_org_id}` }); return; }
    const { data: profile } = await db().from('cnii_org_profiles').select('sector_id').eq('org_id', org).maybeSingle();
    if (!profile) { res.status(409).json({ error: 'Classify this organisation (CNII profile) before importing into it' }); return; }
    let scopes: ScopeEntry[];
    try { scopes = await scopesOf(org); } catch (e) { fail(res, e as { message?: string }); return; }
    const ip = String(row.ip).toLowerCase();
    const scope = coveringScope({ type: 'ip', value: ip }, scopes, 'passive');
    if (!scope) { res.status(403).json({ error: `${ip} is not inside an active authorised scope of ${org}. Add the scope (with its authorisation reference) first.` }); return; }

    const now = new Date().toISOString();
    const { data: existing } = await db().from('vms_assets').select('id, discovery_sources').eq('org_id', org).eq('asset_type', 'ip').eq('value', ip).maybeSingle();
    let assetId: string;
    if (existing) {
        assetId = existing.id;
        await db().from('vms_assets').update({ discovery_sources: [...new Set([...(existing.discovery_sources ?? []), 'legacy_cnii'])] }).eq('id', assetId);
    } else {
        const ins = await db().from('vms_assets').insert({ org_id: org, asset_type: 'ip', value: ip, ips: [ip], hostnames: row.hostname ? [row.hostname] : [], discovery_sources: ['legacy_cnii'], scope_id: scope.id, confidence: 'confirmed', first_seen: row.added_at ?? now, last_seen: row.last_seen ?? now }).select('id').single();
        if (ins.error) { fail(res, ins.error); return; }
        assetId = ins.data.id;
        await db().from('vms_asset_events').insert({ org_id: org, asset_id: assetId, event: 'asset_new', details: { value: ip, source: 'legacy_cnii' } });
    }
    // What the old scan recorded, as low-confidence observations dated when it was recorded.
    const obs: Obs[] = [];
    if (row.owner || row.org || row.asn) obs.push({ source: 'legacy_cnii', kind: 'registry', key: 'holder', value: { owner: row.owner, org: row.org, asn: row.asn }, confidence: 'low' });
    if (row.hostname) obs.push({ source: 'legacy_cnii', kind: 'dns', key: `name:${row.hostname}`, value: { hostname: row.hostname }, confidence: 'low' });
    for (const port of row.open_ports ?? []) obs.push({ source: 'legacy_cnii', kind: 'service', key: `tcp/${port}`, value: { port, protocol: 'tcp', note: 'from the pre-P9 SpiderFoot scan, which included an active port scan' }, confidence: 'low' });
    const added = await storeObservations(org, assetId, null, obs, row.last_seen ?? now);
    const claims = (Array.isArray(row.vulns) ? row.vulns : []).map((v: { cve: string; cvss: number | null; severity: 'critical' | 'high' | 'medium' | 'low' }) => ({ source: 'legacy_cnii:spiderfoot', cve: v.cve, cvss: v.cvss, severity: v.severity }));
    const f = claims.length ? await ingestPassiveClaims(org, null, { id: assetId, type: 'ip', value: ip }, claims) : { new_findings: 0 };
    await db().from('cnii_assets').update({ imported_org_id: org, imported_asset_id: assetId, imported_at: now, imported_by: actor(req) }).eq('id', row.id);
    logAudit({ user: actor(req), action: 'CNII_LEGACY_IMPORTED', resource: 'cnii_asset', resource_id: row.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${ip} -> asset ${assetId}; ${added} observation(s), ${f.new_findings} unconfirmed finding(s)` });
    res.json({ asset_id: assetId, observations_added: added, findings_new: f.new_findings, sector_mismatch: row.sector_id !== profile.sector_id ? { legacy: row.sector_id, organisation: profile.sector_id } : null });
});

// ── Intake (P17) ────────────────────────────────────────────────────────────────────────────
const intakeLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => (req as AuthRequest).user?.email ?? 'anonymous', message: { error: 'At most 20 submissions a minute' } });
const intakeFail = (res: Response, e: unknown) => {
    const err = e as { message?: string; code?: string };
    if (isMissingP17(err)) { res.status(503).json({ error: P17_MISSING }); return; }
    console.error('[cnii] intake:', err?.message ?? e);
    res.status(502).json({ error: 'The intake could not be completed; see the backend log' });
};
async function loadSubmission(id: string): Promise<Submission | null> {
    const { data, error } = await db().from('cnii_submissions').select('*').eq('id', id).maybeSingle();
    if (error) throw Object.assign(new Error(error.message), { code: error.code });
    return (data as Submission | null) ?? null;
}

router.post('/intake', requirePermission('cnii:sector'), intakeLimiter, async (req: AuthRequest, res) => {
    // Bulk (P18): each entry validated, deduplicated and processed on its own; one failure blocks nothing.
    if (req.body?.values !== undefined) {
        const { entries, too_many } = parseIntakeList(req.body.values);
        if (!entries.length) { res.status(400).json({ error: 'Give one or more domains or IP addresses, separated by commas, spaces or new lines' }); return; }
        const results: Record<string, unknown>[] = [];
        for (const e of entries) {
            if (e.outcome === 'invalid') { results.push({ input: e.input, outcome: 'invalid', error: 'Not a domain name or IP address (no URL, port, wildcard or range)' }); continue; }
            if (e.outcome === 'duplicate') { results.push({ input: e.input, value: e.value, outcome: 'duplicate', error: 'Repeated in this submission' }); continue; }
            try {
                const r = await submitIntake(e.kind!, e.value!, actor(req));
                logAudit({ user: actor(req), action: r.created ? 'CNII_INTAKE_SUBMITTED' : 'CNII_INTAKE_RECHECKED', resource: 'cnii_submission', resource_id: r.submission.id, org_id: r.submission.org_id ?? requestOrg(req), ip: req.ip ?? 'unknown', result: 'success',
                    details: `bulk ${e.kind} ${e.value}: ${r.submission.status}${r.submission.org_id ? ` (${r.submission.org_id})` : ''}`.slice(0, 200) });
                results.push({ input: e.input, value: e.value, outcome: r.submission.status, created: r.created, id: r.submission.id, reason: r.submission.reason });
            } catch (err) {
                if (isMissingP17(err as { code?: string; message?: string })) { res.status(503).json({ error: P17_MISSING }); return; }
                console.error(`[cnii] bulk intake ${e.value}:`, (err as Error).message);
                results.push({ input: e.input, value: e.value, outcome: 'failed', error: 'Could not be checked; try it again' });
            }
        }
        const counts = results.reduce<Record<string, number>>((m, r) => ({ ...m, [String(r.outcome)]: (m[String(r.outcome)] ?? 0) + 1 }), {});
        res.status(200).json({ results, counts, ...(too_many ? { note: `Only the first ${MAX_BULK} entries were processed` } : {}) });
        return;
    }
    const v = parseIntake(req.body?.value);
    if (!v) { res.status(400).json({ error: 'Give one domain name (e.g. portal.example.gov.ng) or one IP address — no URL, port, wildcard or range' }); return; }
    try {
        const r = await submitIntake(v.kind, v.value, actor(req));
        logAudit({ user: actor(req), action: r.created ? 'CNII_INTAKE_SUBMITTED' : 'CNII_INTAKE_RECHECKED', resource: 'cnii_submission', resource_id: r.submission.id, org_id: r.submission.org_id ?? requestOrg(req), ip: req.ip ?? 'unknown', result: 'success',
            details: `${v.kind} ${v.value}: ${r.submission.status}${r.submission.org_id ? ` (${r.submission.org_id})` : ''}; ${r.submission.ips.length} address(es)`.slice(0, 200) });
        res.status(r.created ? 201 : 200).json({ submission: r.submission, created: r.created, link: r.link });
    } catch (e) { intakeFail(res, e); }
});

router.get('/intake', requirePermission('cnii:sector'), async (req: AuthRequest, res) => {
    let q = db().from('cnii_submissions').select('*').order('updated_at', { ascending: false }).limit(500);
    if (typeof req.query.status === 'string' && ['confirmed', 'candidate', 'rejected'].includes(req.query.status)) q = q.eq('status', req.query.status);
    const { data, error } = await q;
    if (error) { intakeFail(res, error); return; }
    const rows = (data ?? []) as Submission[];
    // Per confirmed submission: open findings by severity on its values, and its latest assessment.
    const orgs = [...new Set(rows.filter((r) => r.status === 'confirmed' && r.org_id).map((r) => r.org_id!))];
    const values = [...new Set(rows.flatMap((r) => [r.value, ...(r.ips ?? [])]))];
    const [fs, as] = orgs.length && values.length ? await Promise.all([
        db().from('vms_findings').select('org_id, asset_value, scanner_severity').in('org_id', orgs).in('asset_value', values).in('status', OPEN).limit(20_000),
        db().from('vms_assessments').select('org_id, target, requested_at').in('org_id', orgs).in('target', values).order('requested_at', { ascending: false }).limit(2000),
    ]) : [{ data: [] as { org_id: string; asset_value: string; scanner_severity: string }[] }, { data: [] as { org_id: string; target: string; requested_at: string }[], error: null }];
    res.json({
        submissions: rows.map((r) => {
            const vals = new Set([r.value, ...(r.ips ?? [])]);
            const sev: Record<string, number> = {};
            if (r.status === 'confirmed') for (const f of fs.data ?? []) if (f.org_id === r.org_id && vals.has(f.asset_value)) sev[f.scanner_severity] = (sev[f.scanner_severity] ?? 0) + 1;
            const last = r.status === 'confirmed' ? (as.data ?? []).find((a) => a.org_id === r.org_id && vals.has(a.target)) : undefined;
            return { ...r, open_by_severity: sev, last_assessment_at: last?.requested_at ?? null };
        }),
        assessments_available: !('error' in as && as.error),
    });
});

router.get('/intake/:id', requirePermission('cnii:sector'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Submission not found' }); return; }
    try {
        const s = await loadSubmission(req.params.id);
        if (!s) { res.status(404).json({ error: 'Submission not found' }); return; }
        const [results, org] = await Promise.all([intakeResults(s), s.org_id ? db().from('organisations').select('slug, name').eq('slug', s.org_id).maybeSingle() : Promise.resolve({ data: null })]);
        res.json({ submission: s, organisation: org.data ?? null, ...results });
    } catch (e) { intakeFail(res, e); }
});

const Manual = z.object({ org_id: z.string().trim().min(1).max(100), sector_id: z.string().trim().min(1).max(40), ip: z.string().trim().min(2).max(64), justification: z.string().trim().min(10).max(1000) }).strict();
router.post('/intake/manual', requirePermission('cnii:sector'), intakeLimiter, async (req: AuthRequest, res) => {
    const p = Manual.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { org_id, sector_id, ip, justification (10+ characters: the evidence for this registration) }' }); return; }
    try {
        const r = await registerManual(actor(req), p.data);
        if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
        if (r.registered) logAudit({ user: actor(req), action: 'CNII_ASSET_REGISTERED', resource: 'cnii_submission', resource_id: r.submission.id, org_id: p.data.org_id, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
            details: `${p.data.ip} -> ${p.data.org_id}/${p.data.sector_id} (unverified): ${p.data.justification}`.slice(0, 200) });
        res.status(r.registered ? 201 : 200).json({ submission: r.submission, registered: r.registered, note: r.note });
    } catch (e) { intakeFail(res, e); }
});

const Decision = z.object({ decision: z.enum(['confirm', 'reject']), org_id: z.string().trim().min(1).max(100).optional(), note: z.string().trim().min(5).max(1000) }).strict();
router.post('/intake/:id/decision', requirePermission('cnii:sector'), requirePermission('cnii:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Submission not found' }); return; }
    const p = Decision.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { decision: confirm|reject, org_id? (for confirm), note: the evidence or reason (5+ characters) }' }); return; }
    try {
        const r = await decideIntake(req.params.id, actor(req), p.data);
        if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
        logAudit({ user: actor(req), action: p.data.decision === 'confirm' ? 'CNII_INTAKE_CONFIRMED' : 'CNII_INTAKE_REJECTED', resource: 'cnii_submission', resource_id: req.params.id, org_id: r.submission.org_id ?? requestOrg(req), ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
            details: `${r.submission.value}${p.data.org_id ? ` -> ${p.data.org_id}` : ''}: ${p.data.note}`.slice(0, 200) });
        res.json({ submission: r.submission, link: r.link });
    } catch (e) { intakeFail(res, e); }
});

const Assess = z.object({ targets: z.array(z.string().max(253)).max(10).optional() }).strict();
router.post('/intake/:id/assess', requirePermission('cnii:sector'), requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Submission not found' }); return; }
    const p = Assess.safeParse(req.body ?? {});
    if (!p.success) { res.status(400).json({ error: 'Body may hold targets: [up to 10 of its values]' }); return; }
    try {
        const s = await loadSubmission(req.params.id);
        if (!s) { res.status(404).json({ error: 'Submission not found' }); return; }
        const r = await assessIntake(s, actor(req), req.ip ?? 'unknown', p.data.targets?.map((t) => t.trim().toLowerCase()));
        logAudit({ user: actor(req), action: 'CNII_INTAKE_ASSESSMENT', resource: 'cnii_submission', resource_id: s.id, org_id: s.org_id ?? requestOrg(req), ip: req.ip ?? 'unknown', result: r.results.some((x) => x.ok) ? 'success' : 'failed',
            details: (r.not_assessable ?? r.results.map((x) => `${x.target}=${x.ok ? x.status : 'refused'}`).join(' ')).slice(0, 200) });
        if (r.not_assessable) { res.status(409).json({ error: r.not_assessable, results: r.results }); return; }
        res.json(r);
    } catch (e) { intakeFail(res, e); }
});

const Schedule = z.object({ days: z.number().int().min(1).max(SCHEDULE_MAX_DAYS) }).strict();
router.post('/intake/:id/schedule', requirePermission('cnii:sector'), requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Submission not found' }); return; }
    const p = Schedule.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { days: 1..${SCHEDULE_MAX_DAYS} }` }); return; }
    try {
        const s = await loadSubmission(req.params.id);
        if (!s) { res.status(404).json({ error: 'Submission not found' }); return; }
        if (s.status !== 'confirmed' || !s.org_id) { res.status(409).json({ error: 'Only a confirmed submission can be scheduled' }); return; }
        const r = await scheduleIntake(s, actor(req), p.data.days);
        if (!r.schedules.length) { res.status(409).json({ error: 'No value of this submission is inside its organisation\'s active authorised scope' }); return; }
        logAudit({ user: actor(req), action: 'CNII_INTAKE_SCHEDULED', resource: 'cnii_submission', resource_id: s.id, org_id: s.org_id, ip: req.ip ?? 'unknown', result: r.schedules.some((x) => x.schedule_id) ? 'success' : 'failed',
            details: `every ${r.interval_hours} h until ${r.ends_at}: ${r.schedules.map((x) => `${x.target}=${x.error ? 'refused' : x.existing ? 'existing' : 'created'}`).join(' ')}`.slice(0, 200) });
        res.json(r);
    } catch (e) { intakeFail(res, e); }
});

const Authorise = z.object({
    reference: z.string().trim().min(3).max(200), evidence: z.string().trim().min(10).max(1500), expires_days: z.number().int().min(1).max(MAX_AUTH_DAYS),
    allow_port_scan: z.boolean(), allow_vuln_scan: z.boolean(), addresses: z.array(z.string().max(64)).max(16).optional(),
}).strict();
router.post('/intake/:id/authorise', requirePermission('cnii:sector'), requirePermission('cnii:manage'), requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Submission not found' }); return; }
    const p = Authorise.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { reference, evidence (10+ characters), expires_days: 1..${MAX_AUTH_DAYS}, allow_port_scan, allow_vuln_scan, addresses? }` }); return; }
    try {
        const s = await loadSubmission(req.params.id);
        if (!s) { res.status(404).json({ error: 'Submission not found' }); return; }
        const r = await authoriseIntake(s, actor(req), p.data);
        if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
        logAudit({ user: actor(req), action: 'CNII_SCAN_AUTHORISED', resource: 'cnii_submission', resource_id: s.id, org_id: s.org_id!, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
            details: `${r.results.map((x) => `${x.target}=${x.outcome}`).join(' ')}; ports=${p.data.allow_port_scan} vuln=${p.data.allow_vuln_scan} until ${r.authorisation.expires_at} ref=${p.data.reference}`.slice(0, 200) });
        res.json(r);
    } catch (e) { intakeFail(res, e); }
});

router.post('/intake/:id/authorise/revoke', requirePermission('cnii:sector'), requirePermission('cnii:manage'), requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Submission not found' }); return; }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
    if (reason.length < 5 || reason.length > 500) { res.status(400).json({ error: 'Body must be { reason (5+ characters) }' }); return; }
    try {
        const s = await loadSubmission(req.params.id);
        if (!s) { res.status(404).json({ error: 'Submission not found' }); return; }
        const r = await revokeIntakeAuthorisation(s, actor(req), reason);
        if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
        logAudit({ user: actor(req), action: 'CNII_SCAN_AUTHORISATION_REVOKED', resource: 'cnii_submission', resource_id: s.id, org_id: s.org_id ?? requestOrg(req), ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: `${r.revoked.join(', ') || 'nothing active'}: ${reason}`.slice(0, 200) });
        res.json(r);
    } catch (e) { intakeFail(res, e); }
});

export default router;
