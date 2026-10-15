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
//
// Everything a feed said is shown as the source said it; analyst verdicts are separate records.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requireRole } from '../middleware/auth';
import { requirePermission } from '../lib/permissions';
import { requestOrg } from '../lib/resolveOrg';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid, createCase, addTimeline } from '../services/cases';
import { logAudit } from '../lib/audit';
import { runFeed, FEEDS, FEED_STALE_HOURS, normalizeIndicator, type IndicatorType } from '../services/threatInfo';

const router = Router();
const P6_MISSING = 'The Threat Information System is not set up yet (run sql/2026-10-15_p6_threat_info.sql)';
const missing = (e: { message?: string } | null) => !!e && /ti_/.test(e.message ?? '') && /does not exist|Could not find/i.test(e.message ?? '');
const fail = (res: import('express').Response, e: { message?: string }) => res.status(missing(e) ? 503 : 502).json({ error: missing(e) ? P6_MISSING : dbErrorMessage(e) });
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const TYPES: IndicatorType[] = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve'];

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
    if (!FEEDS[req.params.id]) { res.status(404).json({ error: 'Unknown feed' }); return; }
    const r = await runFeed(req.params.id);
    logAudit({ user: actor(req), action: 'TI_FEED_RUN', resource: 'ti_feed', resource_id: req.params.id, ip: req.ip ?? 'unknown', result: r.status === 'ok' ? 'success' : 'failed', details: r.error ?? JSON.stringify(r.counts) });
    res.status(r.status === 'ok' ? 200 : 502).json(r);
});

router.get('/indicators', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    const q = req.query;
    let query = getSupabase()!.from('ti_indicators').select('*');
    if (typeof q.type === 'string' && (TYPES as string[]).includes(q.type)) query = query.eq('type', q.type);
    if (q.status === 'active' || q.status === 'expired') query = query.eq('status', q.status);
    if (typeof q.q === 'string' && q.q.trim()) {
        const text = q.q.trim();
        // An exact indicator (any type) or a malware family / tag.
        const exact = TYPES.map((t) => normalizeIndicator(t, text)).filter((v): v is string => !!v);
        if (exact.length) query = query.in('value', [...new Set(exact)]);
        else if (/^[\w .-]{2,80}$/.test(text)) query = query.or(`malware_families.cs.{"${text}"},tags.cs.{"${text}"}`);
        else { res.status(400).json({ error: 'Search for an indicator value, or a malware family or tag' }); return; }
    }
    const { data, error } = await query.order('last_seen', { ascending: false }).limit(500);
    if (error) { fail(res, error); return; }
    let rows = data ?? [];
    if (q.matched === 'true') {
        const { data: m } = await getSupabase()!.from('ti_matches').select('indicator_id').eq('org_id', requestOrg(req)).limit(5000);
        const ids = new Set((m ?? []).map((x) => x.indicator_id));
        rows = rows.filter((r) => ids.has(r.id));
    }
    res.json({ indicators: rows });
});

router.get('/indicators/:id', requirePermission('intel:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: ind, error } = await supabase.from('ti_indicators').select('*').eq('id', req.params.id).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!ind) { res.status(404).json({ error: 'Indicator not found' }); return; }
    const [sources, matches, feedback] = await Promise.all([
        supabase.from('ti_indicator_sources').select('*, ti_feeds(name)').eq('indicator_id', ind.id).order('last_seen', { ascending: false }).limit(50),
        supabase.from('ti_matches').select('*').eq('indicator_id', ind.id).eq('org_id', org).order('last_matched_at', { ascending: false }).limit(100),
        supabase.from('ti_feedback').select('*').eq('indicator_id', ind.id).eq('org_id', org).order('at', { ascending: false }).limit(50),
    ]);
    res.json({ indicator: ind, sources: sources.data ?? [], matches: matches.data ?? [], feedback: feedback.data ?? [] });
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

export default router;
