// /api/ti — Threat Information System (phase P6). Behind requireAuth; intel:read / intel:manage.
//
//   GET   /overview                         counts, freshness, feed health, this org's new matches
//   GET   /feeds                            feed health and the last runs (fetched/new/updated/duplicates/invalid/errors)
//   POST  /feeds/:id/run                    soc_manager / super_admin: run one feed now
//   GET   /indicators?type&q&status&matched list / search
//   GET   /indicators/:id                   with provenance, this org's matches and feedback
//   POST  /indicators/:id/feedback          { verdict, note? }   intel:manage — this org's verdict, kept with history
//   GET   /matches?status                   this org's matches, with what they matched
//   PATCH /matches/:id { status }           reviewed | dismissed
//   POST  /matches/:id/case                 cases:write — open a case (or return the linked one), keeping the reference
//   GET   /kev?days=30                      recent KEV additions, and whether this org has an open finding for each
// Threat Intelligence V1 (phase P25):
//   GET   /indicators?page&page_size&sort&dir&type&status&feed&tlp&hosted=NG&matched&q   paged list with total
//   GET   /indicators/:id/related           pivots: same malware family, same source event, same host
//   GET   /reports?days&country&actor&q     source reports (MISP events) as the source tagged them
//   GET   /actors                           reference library (public reporting) + actors sources named
//   GET   /map?days&sector                  Nigeria map layers (services/tiMap.ts)
//   GET   /vulnerabilities?days&q&page      KEV with NVD/EPSS and this org's open findings; advisories
//   GET   /sources                          feed health, NVD/EPSS freshness, MISP, AI, exchange
//   POST  /sources/misp/check               managers: read-only MISP capability check
//   GET   /exchange/clients                 managers: TAXII clients (never secrets)
//   POST  /exchange/clients                 managers: { name, collections[], max_tlp } → secret shown once
//   POST  /exchange/clients/:id/revoke      managers
//   GET   /export/stix?collection&ceiling&added_after   intel:manage — STIX 2.1 bundle download
//   POST  /analyst/ask { question }         grounded answer from stored intelligence (AI)
//
// Everything a feed said is shown as the source said it; analyst verdicts are separate records.
// Viewers in client roles (executive, portal) never see TLP:AMBER+STRICT or TLP:RED source records.

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requireRole } from '../middleware/auth';
import { requirePermission } from '../lib/permissions';
import { requestOrg, isStaffRole } from '../lib/resolveOrg';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid, createCase, addTimeline } from '../services/cases';
import { logAudit } from '../lib/audit';
import { runFeed, FEED_STALE_HOURS, feedConfigured, normalizeIndicator, isRunnableFeed, RETIRED_FEEDS, type IndicatorType } from '../services/threatInfo';
import { TLP_ORDER, isTlp, isCeiling, COLLECTIONS, collectionById, exportBlockReason, type Tlp } from '../services/tiPolicy';
import { exchangePage } from '../services/tiExchange';
import { bundle, malwareGraph, type BuiltIndicator } from '../services/tiStix';
import { nigeriaMap } from '../services/tiMap';
import { getMISPCapabilities, isMISPConfigured, type MISPCapabilities } from '../services/misp';
import { aiHealth, generate } from '../services/ai';
import { buildQuestion, questionTask, questionSubject, QUESTION_SCHEMA } from '../services/aiPurposesTi';
import { NIGERIAN_ACTORS, GLOBAL_ACTORS } from '../services/threatActors';
import { hashSecret, newClientCredentials, clearTaxiiAuthCache } from './taxii';

const router = Router();
const P6_MISSING = 'The Threat Information System is not set up yet (run sql/2026-10-15_p6_threat_info.sql)';
const missing = (e: { message?: string } | null) => !!e && /ti_/.test(e.message ?? '') && /does not exist|Could not find/i.test(e.message ?? '');
const fail = (res: import('express').Response, e: { message?: string }) => res.status(missing(e) ? 503 : 502).json({ error: missing(e) ? P6_MISSING : dbErrorMessage(e) });
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const TYPES: IndicatorType[] = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve'];
/** The most restrictive marking this viewer may see: staff everything, client roles up to AMBER. */
const viewerCeiling = (req: AuthRequest): Tlp => (isStaffRole(req.user?.role) ? 'red' : 'amber');
const mayView = (tlp: unknown, ceiling: Tlp) => TLP_ORDER.indexOf(isTlp(tlp) ? tlp : 'amber') <= TLP_ORDER.indexOf(ceiling);
const P25_MISSING = 'Threat Intelligence V1 is not set up yet (run sql/2026-10-30_p25_ti_v1.sql)';
const missingP25 = (e: { message?: string } | null) => !!e && /ti_reports|ti_indicator_geo|ti_taxii_clients|stix_uuid|tlp|updated_at|created_at/.test(e.message ?? '') && /does not exist|Could not find|column/i.test(e.message ?? '');
const failP25 = (res: import('express').Response, e: { message?: string }) => res.status(missingP25(e) || missing(e) ? 503 : 502).json({ error: missingP25(e) ? P25_MISSING : missing(e) ? P6_MISSING : dbErrorMessage(e) });
const num = (v: unknown, dflt: number, min: number, max: number) => { const n = Number(v); return Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), min), max) : dflt; };

router.get('/overview', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const day = new Date(Date.now() - 86_400_000).toISOString();
    const count = (q: PromiseLike<{ count: number | null; error: { message: string } | null }>) => q;
    const [feeds, active, newDay, matchesNew, matchesTotal] = await Promise.all([
        supabase.from('ti_feeds').select('*').order('id'),
        count(supabase.from('ti_indicators').select('id', { count: 'exact', head: true }).eq('status', 'active')),
        count(supabase.from('ti_indicators').select('id', { count: 'exact', head: true }).gte('first_seen', day)),
        count(supabase.from('ti_matches').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('status', 'new')),
        count(supabase.from('ti_matches').select('id', { count: 'exact', head: true }).eq('org_id', org)),
    ]);
    if (feeds.error) { fail(res, feeds.error); return; }
    const byType: Record<string, number> = {};
    await Promise.all(TYPES.map(async (t) => {
        const { count: c } = await supabase.from('ti_indicators').select('id', { count: 'exact', head: true }).eq('status', 'active').eq('type', t);
        byType[t] = c ?? 0;
    }));
    res.json({
        indicators: { active: active.count ?? 0, new_last_24h: newDay.count ?? 0, by_type: byType },
        matches: { new: matchesNew.count ?? 0, total: matchesTotal.count ?? 0 },
        feeds: (feeds.data ?? []).map((f) => ({
            ...f,
            stale: !f.last_success_at || Date.now() - Date.parse(f.last_success_at) > (FEED_STALE_HOURS[f.id] ?? 24) * 3_600_000,
            failing: !!f.last_error,
            configured: feedConfigured(f.id),
        })),
    });
});

router.get('/feeds', requirePermission('intel:read'), async (_req, res) => {
    const supabase = getSupabase()!;
    const { data: feeds, error } = await supabase.from('ti_feeds').select('*').order('id');
    if (error) { fail(res, error); return; }
    const { data: runs } = await supabase.from('ti_feed_runs').select('*').order('started_at', { ascending: false }).limit(60);
    res.json({ feeds: feeds ?? [], runs: runs ?? [] });
});

router.post('/feeds/:id/run', requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    if (!isRunnableFeed(req.params.id)) { res.status(404).json({ error: RETIRED_FEEDS.has(req.params.id) ? 'This feed is retired' : 'Unknown feed' }); return; }
    if (!feedConfigured(req.params.id)) { res.status(409).json({ error: 'This feed is not configured' }); return; }
    const r = await runFeed(req.params.id);
    logAudit({ user: actor(req), action: 'TI_FEED_RUN', resource: 'ti_feed', resource_id: req.params.id, ip: req.ip ?? 'unknown', result: r.status === 'ok' ? 'success' : 'failed', details: r.error ?? JSON.stringify(r.counts) });
    res.status(r.status === 'ok' ? 200 : 502).json(r);
});

/**
 * An indicator's merged labels may come from a record this viewer may not see; for client-role
 * viewers they are blanked on any indicator with such a record (staff see everything).
 */
async function hideRestrictedLabels(req: AuthRequest, rows: Record<string, unknown>[]): Promise<Record<string, unknown>[]> {
    const ceiling = viewerCeiling(req);
    if (ceiling === 'red' || !rows.length) return rows;
    const { data } = await getSupabase()!.from('ti_indicator_sources').select('indicator_id, tlp').in('indicator_id', rows.map((r) => r.id as string));
    const restricted = new Set((data ?? []).filter((s) => !mayView(s.tlp, ceiling)).map((s) => s.indicator_id as string));
    return rows.map((r) => (restricted.has(r.id as string) ? { ...r, tags: [], malware_families: [], threat_types: [], mitre_techniques: [], labels_hidden: true } : r));
}

const SORTS = new Set(['last_seen', 'first_seen', 'source_count', 'max_confidence', 'created_at']);
router.get('/indicators', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const q = req.query;
    const supabase = getSupabase()!;
    const pageSize = num(q.page_size, 50, 1, 200);
    const page = num(q.page, 1, 1, 10_000);
    const sort = typeof q.sort === 'string' && SORTS.has(q.sort) ? q.sort : 'last_seen';
    const ascending = q.dir === 'asc';
    // Joins used as filters: a source feed / marking, Nigeria hosting.
    const feed = typeof q.feed === 'string' && /^[a-z_]{2,40}$/.test(q.feed) ? q.feed : null;
    const tlp = isTlp(q.tlp) ? q.tlp : null;
    const hosted = q.hosted === 'NG';
    const embeds = [feed || tlp ? 'ti_indicator_sources!inner(feed_id, tlp)' : null, hosted ? 'ti_indicator_geo!inner(country_code, region, precision)' : null].filter(Boolean).join(', ');
    let query = supabase.from('ti_indicators').select(`id, type, value, first_seen, last_seen, valid_until, status, max_confidence, tags, malware_families, threat_types, mitre_techniques, source_count${embeds ? `, ${embeds}` : ''}`, { count: 'exact' });
    if (typeof q.type === 'string' && (TYPES as string[]).includes(q.type)) query = query.eq('type', q.type);
    if (q.status === 'active' || q.status === 'expired') query = query.eq('status', q.status);
    if (feed) query = query.eq('ti_indicator_sources.feed_id', feed);
    if (tlp) query = query.eq('ti_indicator_sources.tlp', tlp);
    if (hosted) query = query.eq('ti_indicator_geo.country_code', 'NG');
    if (typeof q.q === 'string' && q.q.trim()) {
        const text = q.q.trim();
        // An exact indicator (any type) or a malware family / tag.
        const exact = TYPES.map((t) => normalizeIndicator(t, text)).filter((v): v is string => !!v);
        if (exact.length) query = query.in('value', [...new Set(exact)]);
        else if (/^[\w .-]{2,80}$/.test(text)) query = query.or(`malware_families.cs.{"${text}"},tags.cs.{"${text}"}`);
        else { res.status(400).json({ error: 'Search for an indicator value, or a malware family or tag' }); return; }
    }
    if (q.matched === 'true') {
        const { data: m } = await supabase.from('ti_matches').select('indicator_id').eq('org_id', requestOrg(req)).limit(5000);
        const ids = [...new Set((m ?? []).map((x) => x.indicator_id as string))];
        if (!ids.length) { res.json({ indicators: [], total: 0, page, page_size: pageSize }); return; }
        query = query.in('id', ids.slice(0, 1000));
    }
    const { data, error, count } = await query.order(sort, { ascending, nullsFirst: false }).order('id').range((page - 1) * pageSize, page * pageSize - 1);
    if (error) { failP25(res, error); return; }
    let rows = ((data ?? []) as unknown as Record<string, unknown>[]).map((r) => { const { ti_indicator_sources: _s, ti_indicator_geo: _g, ...rest } = r; return rest; });
    rows = await hideRestrictedLabels(req, rows);
    res.json({ indicators: rows, total: count ?? rows.length, page, page_size: pageSize });
});

router.get('/indicators/:id', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: ind, error } = await supabase.from('ti_indicators').select('*').eq('id', req.params.id).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!ind) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const [sources, matches, feedback, geo] = await Promise.all([
        supabase.from('ti_indicator_sources').select('*, ti_feeds(name)').eq('indicator_id', ind.id).order('last_seen', { ascending: false }).limit(50),
        supabase.from('ti_matches').select('*').eq('indicator_id', ind.id).eq('org_id', org).order('last_matched_at', { ascending: false }).limit(100),
        supabase.from('ti_feedback').select('*').eq('indicator_id', ind.id).eq('org_id', org).order('at', { ascending: false }).limit(50),
        supabase.from('ti_indicator_geo').select('country_code, country, region, city, asn, as_org, method, provider, precision, looked_up_at').eq('indicator_id', ind.id).maybeSingle(),
    ]);
    const ceiling = viewerCeiling(req);
    const all = sources.data ?? [];
    const shown = all.filter((s) => mayView(s.tlp, ceiling)).map((s) => ({ ...s, export: { clear: exportBlockReason({ tlp: isTlp(s.tlp) ? s.tlp : 'amber', distribution: s.distribution ?? null }, 'clear'), green: exportBlockReason({ tlp: isTlp(s.tlp) ? s.tlp : 'amber', distribution: s.distribution ?? null }, 'green') } }));
    const hidden = all.length - shown.length;
    const indicator = hidden ? { ...ind, tags: [], malware_families: [], threat_types: [], mitre_techniques: [], labels_hidden: true } : ind;
    res.json({ indicator, sources: shown, sources_hidden: hidden, matches: matches.data ?? [], feedback: feedback.data ?? [], location: geo.error ? null : geo.data ?? null });
});

const Feedback = z.object({ verdict: z.enum(['confirmed_malicious', 'suspicious', 'benign', 'false_positive']), note: z.string().trim().max(2000).optional() }).strict();
router.post('/indicators/:id/feedback', requirePermission('intel:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const p = Feedback.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { verdict: confirmed_malicious|suspicious|benign|false_positive, note? }' }); return; }
    if ((p.data.verdict === 'benign' || p.data.verdict === 'false_positive') && !p.data.note) { res.status(400).json({ error: 'Say why it is benign or a false positive' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: ind } = await supabase.from('ti_indicators').select('id, type, value').eq('id', req.params.id).maybeSingle();
    if (!ind) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const { data, error } = await supabase.from('ti_feedback').insert({ org_id: org, indicator_id: ind.id, verdict: p.data.verdict, note: p.data.note ?? null, actor: actor(req) }).select('*').single();
    if (error) { fail(res, error); return; }
    logAudit({ user: actor(req), action: 'TI_VERDICT', resource: 'ti_indicator', resource_id: ind.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${ind.type} ${ind.value}: ${p.data.verdict}`.slice(0, 200) });
    res.status(201).json({ feedback: data });
});

router.get('/matches', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    let q = getSupabase()!.from('ti_matches').select('*, ti_indicators(type, value, max_confidence, malware_families, threat_types, source_count, status)').eq('org_id', requestOrg(req));
    if (typeof req.query.status === 'string' && ['new', 'reviewed', 'promoted', 'dismissed'].includes(req.query.status)) q = q.eq('status', req.query.status);
    const { data, error } = await q.order('last_matched_at', { ascending: false }).limit(500);
    if (error) { fail(res, error); return; }
    res.json({ matches: data ?? [] });
});

router.patch('/matches/:id', requirePermission('intel:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Match not found' }); return; }
    const status = req.body?.status;
    if (status !== 'reviewed' && status !== 'dismissed') { res.status(400).json({ error: "status must be 'reviewed' or 'dismissed'" }); return; }
    const { data, error } = await getSupabase()!.from('ti_matches').update({ status, reviewed_by: actor(req) }).eq('id', req.params.id).eq('org_id', requestOrg(req)).neq('status', 'promoted').select('*').maybeSingle();
    if (error) { fail(res, error); return; }
    if (!data) { res.status(404).json({ error: 'Match not found (or already promoted to a case)' }); return; }
    res.json({ match: data });
});

router.post('/matches/:id/case', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Match not found' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: m } = await supabase.from('ti_matches').select('*, ti_indicators(*)').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!m) { res.status(404).json({ error: 'Match not found' }); return; }
    const ind = m.ti_indicators as { id: string; type: string; value: string; malware_families: string[]; threat_types: string[]; max_confidence: number | null; source_count: number };
    const { data: srcs } = await supabase.from('ti_indicator_sources').select('feed_id, source_ref').eq('indicator_id', ind.id).limit(10);
    const r = await createCase({
        org_id: org, source: 'intel', source_id: m.id, severity: 'high',
        title: `Threat intelligence match: ${ind.type} ${ind.value.slice(0, 120)}`,
        description: `Indicator ${ind.type} ${ind.value} (listed by ${ind.source_count} source record(s): ${(srcs ?? []).map((s) => `${s.feed_id}#${s.source_ref}`).join(', ')}) `
            + `matched ${m.entity_type} ${m.entity_id} on ${m.matched_field}. Source-reported labels: ${[...(ind.malware_families ?? []), ...(ind.threat_types ?? [])].join(', ') || 'none'}. `
            + `Source-stated confidence: ${ind.max_confidence ?? 'not stated'}. Threat intelligence record: ${ind.id}.`,
        source_ip: ind.type === 'ip' ? ind.value : null, tags: ['threat-intel', ind.type],
    }, actor(req));
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    await supabase.from('ti_matches').update({ status: 'promoted', case_id: r.case.id, reviewed_by: actor(req) }).eq('id', m.id);
    if (r.created) await addTimeline(r.case.id, actor(req), `Opened from threat intelligence match (indicator ${ind.id})`);
    logAudit({ user: actor(req), action: 'TI_MATCH_PROMOTED', resource: 'ti_match', resource_id: m.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `case ${r.case.case_number}` });
    res.status(r.created ? 201 : 200).json({ created: r.created, case: { id: r.case.id, case_number: r.case.case_number } });
});

router.get('/kev', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const days = Math.min(Math.max(Number(req.query.days) || 30, 1), 365);
    const supabase = getSupabase()!;
    const since = new Date(Date.now() - days * 86_400_000).toISOString();
    const { data, error } = await supabase.from('ti_indicators').select('id, value, first_seen').eq('type', 'cve').gte('first_seen', since).order('first_seen', { ascending: false }).limit(500);
    if (error) { fail(res, error); return; }
    const ids = (data ?? []).map((d) => d.id);
    const cves = (data ?? []).map((d) => d.value);
    const [srcs, findings] = await Promise.all([
        ids.length ? supabase.from('ti_indicator_sources').select('indicator_id, context').eq('feed_id', 'cisa_kev').in('indicator_id', ids) : Promise.resolve({ data: [] as { indicator_id: string; context: unknown }[] }),
        cves.length ? supabase.from('vms_findings').select('id, cve_ids, asset_value, status').eq('org_id', requestOrg(req)).overlaps('cve_ids', cves).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']) : Promise.resolve({ data: [] as { id: string; cve_ids: string[]; asset_value: string }[] }),
    ]);
    const ctx = new Map((srcs.data ?? []).map((s) => [s.indicator_id, s.context]));
    res.json({
        kev: (data ?? []).map((d) => ({ cve: d.value, added: d.first_seen, context: ctx.get(d.id) ?? null, your_open_findings: (findings.data ?? []).filter((f) => (f.cve_ids ?? []).includes(d.value)).map((f) => ({ id: f.id, asset: f.asset_value })) })),
    });
});

// ── Threat Intelligence V1 (phase P25) ───────────────────────────────────────────────────────

router.get('/indicators/:id/related', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const supabase = getSupabase()!;
    const ceiling = viewerCeiling(req);
    const { data: ind } = await supabase.from('ti_indicators').select('id, type, value').eq('id', req.params.id).maybeSingle();
    if (!ind) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const { data: srcs } = await supabase.from('ti_indicator_sources').select('feed_id, tlp, context').eq('indicator_id', ind.id).limit(50);
    const shared = (srcs ?? []).filter((s) => mayView(s.tlp, ceiling));
    const ctx = (s: { context: unknown }) => (s.context ?? {}) as Record<string, unknown>;
    const malware = [...new Set(shared.map((s) => ctx(s).malware).filter((m): m is string => typeof m === 'string'))].slice(0, 5);
    const events = [...new Set(shared.map((s) => ctx(s).event_uuid).filter((e): e is string => typeof e === 'string'))].slice(0, 5);
    const host = ind.type === 'url' ? (() => { try { return new URL(ind.value).hostname.toLowerCase(); } catch { return null; } })() : null;
    const out: { indicator_id: string; type: string; value: string; status: string; last_seen: string; link: string; source: string }[] = [];
    const add = (rows: { indicator_id?: string; id?: string; feed_id?: string; tlp?: string; ti_indicators?: unknown }[] | null, link: string) => {
        for (const r of rows ?? []) {
            if (r.tlp !== undefined && !mayView(r.tlp, ceiling)) continue;
            const i = (r.ti_indicators ?? r) as { id: string; type: string; value: string; status: string; last_seen: string };
            if (!i?.id || i.id === ind.id || out.some((o) => o.indicator_id === i.id)) continue;
            out.push({ indicator_id: i.id, type: i.type, value: i.value, status: i.status, last_seen: i.last_seen, link, source: r.feed_id ?? 'platform' });
        }
    };
    for (const m of malware) {
        const { data } = await supabase.from('ti_indicators').select('id, type, value, status, last_seen').contains('malware_families', [m]).neq('id', ind.id).order('last_seen', { ascending: false }).limit(25);
        add(data, `Same malware family named by a source: ${m}`);
    }
    for (const e of events) {
        const { data } = await supabase.from('ti_indicator_sources').select('feed_id, tlp, ti_indicators(id, type, value, status, last_seen)').eq('context->>event_uuid', e).limit(50);
        add(data as never, 'Listed in the same MISP event');
    }
    if (host) {
        const { data } = await supabase.from('ti_indicators').select('id, type, value, status, last_seen').eq('type', 'domain').eq('value', host).limit(1);
        add(data, 'The domain this URL is hosted on');
        const { data: urls } = await supabase.from('ti_indicators').select('id, type, value, status, last_seen').eq('type', 'url').ilike('value', `%://${host}/%`).neq('id', ind.id).limit(25);
        add(urls, 'Another URL on the same host');
    }
    if (ind.type === 'domain') {
        const { data: urls } = await supabase.from('ti_indicators').select('id, type, value, status, last_seen').eq('type', 'url').ilike('value', `%://${ind.value}/%`).limit(25);
        add(urls, 'A URL hosted on this domain');
    }
    let reports: unknown[] = [];
    if (events.length) {
        const { data } = await supabase.from('ti_reports').select('id, title, published_at, tlp, actors, malware, target_countries, target_sectors').in('source_ref', events);
        reports = (data ?? []).filter((r) => mayView(r.tlp, ceiling));
    }
    res.json({ related: out.slice(0, 100), reports });
});

router.get('/reports', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const days = num(req.query.days, 30, 1, 365);
    const ceiling = viewerCeiling(req);
    let q = getSupabase()!.from('ti_reports').select('id, feed_id, source_ref, title, published_at, source_updated_at, tlp, threat_level, tags, target_countries, target_sectors, actors, malware, attack_patterns, attribute_count').gte('published_at', new Date(Date.now() - days * 86_400_000).toISOString());
    if (typeof req.query.country === 'string' && /^[A-Z]{2}$/.test(req.query.country)) q = q.contains('target_countries', [req.query.country]);
    if (typeof req.query.actor === 'string' && req.query.actor.trim()) q = q.contains('actors', [req.query.actor.trim().slice(0, 120)]);
    if (typeof req.query.q === 'string' && /^[\w .:-]{2,80}$/.test(req.query.q.trim())) q = q.ilike('title', `%${req.query.q.trim()}%`);
    const { data, error } = await q.order('published_at', { ascending: false }).limit(500);
    if (error) { failP25(res, error); return; }
    const visible = (data ?? []).filter((r) => mayView(r.tlp, ceiling));
    res.json({ reports: visible, hidden: (data ?? []).length - visible.length });
});

router.get('/actors', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const ceiling = viewerCeiling(req);
    const library = [...NIGERIAN_ACTORS.map((a) => ({ ...a, focus: 'nigeria' as const })), ...GLOBAL_ACTORS.map((a) => ({ ...a, focus: 'global' as const }))];
    const { data, error } = await getSupabase()!.from('ti_reports').select('id, title, published_at, tlp, actors, target_countries').gte('published_at', new Date(Date.now() - 365 * 86_400_000).toISOString()).order('published_at', { ascending: false }).limit(2000);
    const reports = error ? [] : (data ?? []).filter((r) => mayView(r.tlp, ceiling) && (r.actors ?? []).length);
    const key = (s: string) => s.trim().toLowerCase();
    const mentions = new Map<string, { name: string; count: number; last: string | null; nigeria: number; reports: { id: string; title: string; published_at: string | null }[] }>();
    for (const r of reports) for (const name of r.actors as string[]) {
        const m = mentions.get(key(name)) ?? { name, count: 0, last: null, nigeria: 0, reports: [] };
        m.count++;
        if (!m.last || (r.published_at && r.published_at > m.last)) m.last = r.published_at;
        if ((r.target_countries ?? []).includes('NG')) m.nigeria++;
        if (m.reports.length < 10) m.reports.push({ id: r.id, title: r.title, published_at: r.published_at });
        mentions.set(key(name), m);
    }
    const claimed = new Set<string>();
    const actors = library.map((a) => {
        const names = [a.name, ...(a.aliases ?? [])].map(key);
        const hits = names.map((n) => mentions.get(n)).filter((m): m is NonNullable<typeof m> => !!m);
        names.forEach((n) => claimed.add(n));
        return {
            id: a.id, name: a.name, aliases: a.aliases, focus: a.focus, origin: a.origin, motivation: a.motivation, targeted_sectors: a.targeted_sectors, targeted_regions: a.targeted_regions,
            techniques: a.mitre_techniques, description: a.description, damage: a.damage, known_incidents: a.known_incidents, reference: a.reference, reference_url: a.reference_url,
            library_confidence: a.confidence, last_active: a.last_active,
            source_mentions: { count: hits.reduce((s, h) => s + h.count, 0), nigeria_targeting: hits.reduce((s, h) => s + h.nigeria, 0), last: hits.map((h) => h.last).filter(Boolean).sort().pop() ?? null, reports: hits.flatMap((h) => h.reports).slice(0, 10) },
        };
    });
    const unprofiled = [...mentions.entries()].filter(([k]) => !claimed.has(k)).map(([, m]) => m).sort((a, b) => b.count - a.count).slice(0, 100);
    res.json({
        actors, source_named: unprofiled,
        notes: [
            'Library profiles summarise public reporting by the named publisher; they are reference material, not NovrSOC telemetry.',
            'Source mentions are MISP events that attached a threat-actor tag — the source\'s attribution, not the platform\'s.',
        ],
    });
});

router.get('/map', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    try {
        const sector = typeof req.query.sector === 'string' && /^[\w &/-]{2,60}$/.test(req.query.sector) ? req.query.sector : null;
        res.json(await nigeriaMap({ org: requestOrg(req), days: num(req.query.days, 30, 1, 365), sector, viewerCeiling: viewerCeiling(req) }));
    } catch (err) { failP25(res, { message: err instanceof Error ? err.message : String(err) }); }
});

router.get('/vulnerabilities', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase()!;
    const days = num(req.query.days, 0, 0, 3650); // 0 = the whole catalogue
    const pageSize = num(req.query.page_size, 50, 1, 200);
    const page = num(req.query.page, 1, 1, 1000);
    let iq = supabase.from('ti_indicators').select('id, value, first_seen, created_at').eq('type', 'cve');
    if (days) iq = iq.gte('first_seen', new Date(Date.now() - days * 86_400_000).toISOString());
    const { data: cves, error } = await iq.order('first_seen', { ascending: false }).limit(5000);
    if (error) { fail(res, error); return; }
    const ids = (cves ?? []).map((c) => c.id as string);
    const kevCtx = new Map<string, Record<string, unknown>>();
    for (let i = 0; i < ids.length; i += 300) {
        const { data } = await supabase.from('ti_indicator_sources').select('indicator_id, context').eq('feed_id', 'cisa_kev').in('indicator_id', ids.slice(i, i + 300));
        for (const s of data ?? []) kevCtx.set(s.indicator_id as string, (s.context ?? {}) as Record<string, unknown>);
    }
    let rows = (cves ?? []).filter((c) => kevCtx.has(c.id as string)).map((c) => ({ id: c.id as string, cve: c.value as string, added: c.first_seen as string, kev: kevCtx.get(c.id as string)! }));
    const text = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase().slice(0, 80) : '';
    if (text) rows = rows.filter((r) => r.cve.toLowerCase().includes(text) || ['vendor', 'product', 'name'].some((k) => String(r.kev[k] ?? '').toLowerCase().includes(text)));
    if (req.query.ransomware === 'known') rows = rows.filter((r) => String(r.kev.ransomware ?? '').toLowerCase() === 'known');
    const total = rows.length;
    const pageRows = rows.slice((page - 1) * pageSize, page * pageSize);
    const cveIds = pageRows.map((r) => r.cve);
    const [intel, findings, advisories] = await Promise.all([
        cveIds.length ? supabase.from('cve_intel').select('cve_id, description, cvss_score, cvss_version, epss_score, epss_percentile, nvd_fetched_at, epss_fetched_at').in('cve_id', cveIds) : Promise.resolve({ data: [] as Record<string, unknown>[] }),
        cveIds.length ? supabase.from('vms_findings').select('id, cve_ids, asset_value, priority, status').eq('org_id', requestOrg(req)).overlaps('cve_ids', cveIds).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']).limit(2000) : Promise.resolve({ data: [] as Record<string, unknown>[] }),
        page === 1 ? supabase.from('nigeria_advisories').select('advisory_id, source, title, severity, threat_type, tags, source_url, published_at').order('published_at', { ascending: false }).limit(50) : Promise.resolve({ data: null }),
    ]);
    const byCve = new Map((intel.data ?? []).map((x) => [x.cve_id as string, x]));
    res.json({
        total, page, page_size: pageSize,
        vulnerabilities: pageRows.map((r) => {
            const f = (findings.data ?? []).filter((x) => ((x.cve_ids as string[]) ?? []).includes(r.cve));
            return { ...r, nvd: byCve.get(r.cve) ?? null, your_open_findings: f.length, your_assets: [...new Set(f.map((x) => x.asset_value as string))].slice(0, 10) };
        }),
        advisories: advisories.data ? (advisories.data as { tags?: string[] }[]).filter((a) => !(a.tags ?? []).includes('demo-data')) : null,
    });
});

// The last MISP capability check, kept in memory (run on demand only).
let lastMispCheck: MISPCapabilities | null = null;

router.get('/sources', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase()!;
    const [feeds, runs, nvd, epss, tlps, clients, ai] = await Promise.all([
        supabase.from('ti_feeds').select('*').order('id'),
        supabase.from('ti_feed_runs').select('*').order('started_at', { ascending: false }).limit(80),
        supabase.from('cve_intel').select('nvd_fetched_at').not('nvd_fetched_at', 'is', null).order('nvd_fetched_at', { ascending: false }).limit(1),
        supabase.from('cve_intel').select('epss_fetched_at').not('epss_fetched_at', 'is', null).order('epss_fetched_at', { ascending: false }).limit(1),
        Promise.all((['clear', 'green', 'amber', 'amber+strict', 'red'] as Tlp[]).map(async (t) => [t, (await supabase.from('ti_indicator_sources').select('id', { count: 'exact', head: true }).eq('tlp', t)).count ?? 0] as const)),
        isStaffRole(req.user?.role) ? supabase.from('ti_taxii_clients').select('id', { count: 'exact', head: true }).is('revoked_at', null) : Promise.resolve({ count: null }),
        aiHealth('ti_question'),
    ]);
    if (feeds.error) { fail(res, feeds.error); return; }
    const cveCount = await supabase.from('cve_intel').select('cve_id', { count: 'exact', head: true });
    const host = `${req.protocol}://${req.get('host')}`;
    res.json({
        feeds: (feeds.data ?? []).map((f) => ({
            ...f,
            retired: RETIRED_FEEDS.has(f.id),
            configured: feedConfigured(f.id),
            stale: !f.last_success_at || Date.now() - Date.parse(f.last_success_at) > (FEED_STALE_HOURS[f.id] ?? 24) * 3_600_000,
            failing: !!f.last_error,
        })),
        runs: runs.data ?? [],
        enrichment: {
            nvd: { last_fetch: nvd.data?.[0]?.nvd_fetched_at ?? null, configured_key: !!process.env.NVD_API_KEY, cves_tracked: cveCount.count ?? 0 },
            epss: { last_fetch: epss.data?.[0]?.epss_fetched_at ?? null },
        },
        misp: { configured: isMISPConfigured(), writes_enabled: process.env.MISP_WRITE_ENABLED === 'true', last_check: lastMispCheck },
        ai,
        sharing: { source_records_by_tlp: Object.fromEntries(tlps) },
        exchange: {
            taxii_discovery: `${host}/taxii2/`, api_root: `${host}/taxii2/api1/`,
            collections: COLLECTIONS.map((c) => ({ id: c.id, alias: c.alias, title: c.title, description: c.description })),
            active_clients: clients.count,
        },
    });
});

router.post('/sources/misp/check', requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    lastMispCheck = await getMISPCapabilities();
    logAudit({ user: actor(req), action: 'TI_MISP_CHECK', resource: 'misp', ip: req.ip ?? 'unknown', result: lastMispCheck.reachable ? 'success' : 'failed', details: `version ${lastMispCheck.version ?? '?'}, write ${lastMispCheck.key_can_write}, stix2 ${lastMispCheck.stix2_export}` });
    res.json({ misp: lastMispCheck });
});

const CLIENT_COLS = 'id, name, key_id, collections, max_tlp, enabled, created_by, created_at, last_used_at, revoked_at';
router.get('/exchange/clients', requireRole('super_admin', 'soc_manager'), async (_req, res) => {
    const { data, error } = await getSupabase()!.from('ti_taxii_clients').select(CLIENT_COLS).order('created_at', { ascending: false });
    if (error) { failP25(res, error); return; }
    res.json({ clients: data ?? [] });
});

const NewClient = z.object({
    name: z.string().trim().min(2).max(120),
    collections: z.array(z.string()).min(1).max(COLLECTIONS.length),
    max_tlp: z.enum(['clear', 'green', 'amber']).default('clear'),
}).strict();
router.post('/exchange/clients', requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    const p = NewClient.safeParse(req.body);
    if (!p.success || p.data.collections.some((c) => !collectionById(c))) { res.status(400).json({ error: `Body must be { name, collections: [${COLLECTIONS.map((c) => c.id).join(' | ')}], max_tlp: clear|green|amber }` }); return; }
    const cred = newClientCredentials();
    const { data, error } = await getSupabase()!.from('ti_taxii_clients').insert({
        name: p.data.name, key_id: cred.key_id, secret_hash: hashSecret(cred.secret), collections: [...new Set(p.data.collections)], max_tlp: p.data.max_tlp, created_by: actor(req),
    }).select(CLIENT_COLS).single();
    if (error) { failP25(res, error); return; }
    logAudit({ user: actor(req), action: 'TAXII_CLIENT_CREATED', resource: 'taxii_client', resource_id: data.id, ip: req.ip ?? 'unknown', result: 'success', details: `${p.data.name}: ${p.data.collections.length} collection(s), max TLP:${p.data.max_tlp.toUpperCase()}` });
    // The secret exists only in this response.
    res.status(201).json({ client: data, credentials: { username: cred.key_id, password: cred.secret }, note: 'Store the password now: it is not shown again.' });
});

router.post('/exchange/clients/:id/revoke', requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Client not found' }); return; }
    const { data, error } = await getSupabase()!.from('ti_taxii_clients').update({ enabled: false, revoked_at: new Date().toISOString() }).eq('id', req.params.id).is('revoked_at', null).select(CLIENT_COLS).maybeSingle();
    if (error) { failP25(res, error); return; }
    if (!data) { res.status(404).json({ error: 'Client not found (or already revoked)' }); return; }
    clearTaxiiAuthCache();
    logAudit({ user: actor(req), action: 'TAXII_CLIENT_REVOKED', resource: 'taxii_client', resource_id: data.id, ip: req.ip ?? 'unknown', result: 'success', details: data.name });
    res.json({ client: data });
});

router.get('/export/stix', requirePermission('intel:manage'), async (req: AuthRequest, res) => {
    const c = typeof req.query.collection === 'string' ? (collectionById(req.query.collection) ?? COLLECTIONS.find((x) => x.alias === req.query.collection) ?? null) : null;
    if (!c) { res.status(400).json({ error: `collection must be one of ${COLLECTIONS.map((x) => x.alias).join(', ')}` }); return; }
    const ceiling = isCeiling(req.query.ceiling) ? req.query.ceiling : 'clear';
    const addedAfter = typeof req.query.added_after === 'string' && Number.isFinite(Date.parse(req.query.added_after)) ? new Date(req.query.added_after).toISOString() : null;
    try {
        const page = await exchangePage({ content: c.content, ceiling, addedAfter, limit: 5000 });
        const objects = page.items.map((i) => i.object);
        const graph = c.content === 'indicators' ? malwareGraph(page.items.map((i) => i.built).filter((b): b is BuiltIndicator => !!b)) : [];
        const b = bundle([...objects, ...graph]);
        logAudit({ user: actor(req), action: 'TI_STIX_EXPORT', resource: 'stix_bundle', resource_id: c.alias, org_id: requestOrg(req), ip: req.ip ?? 'unknown', result: 'success', details: `${objects.length} object(s), ceiling TLP:${ceiling.toUpperCase()}${page.more ? ', truncated at 5000' : ''}` });
        res.setHeader('Content-Disposition', `attachment; filename="novrsoc-${c.alias}-${ceiling}-${new Date().toISOString().slice(0, 10)}.json"`);
        res.setHeader('X-NovrSOC-Truncated', page.more ? 'true' : 'false');
        res.type('application/stix+json;version=2.1').send(JSON.stringify(b));
    } catch (err) { failP25(res, { message: err instanceof Error ? err.message : String(err) }); }
});

const askLimiter = rateLimit({ windowMs: 60_000, max: 10, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => (req as AuthRequest).user?.sub ?? 'anonymous', message: { error: 'Too many questions — wait a minute' } });
router.post('/analyst/ask', requirePermission('intel:read'), askLimiter, async (req: AuthRequest, res) => {
    const question = typeof req.body?.question === 'string' ? req.body.question.trim() : '';
    if (question.length < 3 || question.length > 1000) { res.status(400).json({ error: 'Ask a question of 3 to 1000 characters' }); return; }
    const org = requestOrg(req);
    const ctx = await buildQuestion(org, question);
    const r = await generate({
        purpose: 'ti_question', orgId: org, actor: actor(req), subjectType: 'ti_question', subjectId: questionSubject(question),
        sourceRefs: ctx.refs, records: ctx.records, task: questionTask(question), schema: QUESTION_SCHEMA, maxTokens: 6000,
    });
    if (!r.ok) { res.status(r.status).json({ error: r.error, unavailable: r.unavailable }); return; }
    logAudit({ user: actor(req), action: 'AI_GENERATED', resource: 'ti_question', resource_id: r.artifact.id ?? 'unsaved', org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${ctx.refs.length} record(s)` });
    res.json({ question, artifact: r.artifact });
});

export default router;
