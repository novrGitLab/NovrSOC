import { Router } from 'express';
import { timingSafeEqual } from 'crypto';
import type { AuthRequest } from '../middleware/auth';
import { requireAuth } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { enrichIOC } from '../services/iocEnrichment';
import { DEFAULT_ORG_ID, startOfTodayWAT, dbErrorMessage } from '../services/cases';

// SOAR reporting + the enrichment endpoint the SOAR engine (infra/soar/soar.py) calls.
//
// Reporting routes are requireAuth'd individually. POST /enrich is instead authenticated by a
// shared secret: the engine runs on the Wazuh manager with no user session. It exists because
// the engine can't use /api/public/scan — that route is capped at 10 requests an hour per IP,
// and the engine sends one request per level 7+ alert.

const router = Router();
const orgOf = (req: AuthRequest) => req.user?.org_id || DEFAULT_ORG_ID;

// GET /api/soar/stats
router.get('/stats', requireAuth, async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Case store not configured' }); return; }
    const orgId = orgOf(req);
    const today = startOfTodayWAT().toISOString();

    const base = () => supabase.from('cases').select('id', { count: 'exact', head: true }).eq('org_id', orgId);
    const n = async (q: PromiseLike<{ count: number | null; error: unknown }>) => {
        const { count, error } = await q;
        if (error) throw error;
        return count ?? 0;
    };

    try {
        const [total, resolved, autoClosed, tier1, tier2, tier3, createdToday, autoClosedToday, openCases, escalatedOpen, containment, lastCase] = await Promise.all([
            n(base()),
            n(base().eq('status', 'resolved')),
            n(base().eq('auto_closed', true)),
            n(base().eq('tier', 1)),
            n(base().eq('tier', 2)),
            n(base().eq('tier', 3)),
            n(base().gte('created_at', today)),
            n(base().eq('auto_closed', true).gte('resolved_at', today)),
            n(base().neq('status', 'resolved')),
            n(base().neq('status', 'resolved').eq('escalated', true)),
            n(base().eq('containment_done', true)),
            supabase.from('cases').select('created_at').eq('org_id', orgId).eq('source', 'wazuh').order('created_at', { ascending: false }).limit(1).maybeSingle(),
        ]);

        // "Engine active" is measured, not assumed: the engine is the only writer of
        // source='wazuh' cases, so a recent one is evidence it's running. A quiet network can
        // look inactive — the page shows the timestamp so a reader can judge.
        const lastEngineCaseAt = (lastCase.data as { created_at?: string } | null)?.created_at ?? null;
        const engineActive = lastEngineCaseAt !== null && Date.now() - Date.parse(lastEngineCaseAt) < 24 * 60 * 60 * 1000;

        res.json({
            total, resolved, auto_closed: autoClosed, tier1, tier2, tier3,
            auto_rate: resolved > 0 ? Math.round((autoClosed / resolved) * 100) : 0,
            containment_done: containment,
            cases_created_today: createdToday,
            auto_resolved_today: autoClosedToday,
            open_cases: openCases,
            escalated_open: escalatedOpen,
            engine_active: engineActive,
            last_engine_case_at: lastEngineCaseAt,
        });
    } catch (err) {
        console.error('[soar] stats failed:', dbErrorMessage(err));
        res.status(502).json({ error: `Could not load SOAR stats: ${dbErrorMessage(err)}` });
    }
});

interface SoarLogRow { case_id: string | null; tier: number; action: string; result: string | null; executed_at: string }
interface TimelineRow { case_id: string; action: string; created_at: string }

// GET /api/soar/cases?tier=1|2|3&since=<ISO>&limit=
//
// Cases for one tier, each annotated with what the engine actually did, derived from soar_log
// and the case timeline rather than inferred from the tier. A tier-3 case whose isolation was
// skipped shows as not isolated, with the logged reason.
router.get('/cases', requireAuth, async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Case store not configured' }); return; }
    const tier = Number(req.query.tier);
    if (![1, 2, 3].includes(tier)) { res.status(400).json({ error: 'tier must be 1, 2 or 3' }); return; }
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
    const since = typeof req.query.since === 'string' && !Number.isNaN(Date.parse(req.query.since)) ? new Date(req.query.since).toISOString() : null;

    let q = supabase
        .from('cases')
        .select('id, case_number, title, agent_name, source_ip, severity, status, created_at, resolved_at, assigned_to, auto_closed, containment_done, escalated', { count: 'exact' })
        .eq('org_id', orgOf(req))
        .eq('tier', tier)
        .order('created_at', { ascending: false })
        .limit(limit);
    if (since) q = q.gte('created_at', since);

    const { data: cases, error, count } = await q;
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    const ids = (cases ?? []).map((c) => c.id);
    if (ids.length === 0) { res.json({ cases: [], total: count ?? 0 }); return; }

    const [logRes, tlRes] = await Promise.all([
        supabase.from('soar_log').select('case_id, tier, action, result, executed_at').in('case_id', ids),
        supabase.from('case_timeline').select('case_id, action, created_at').in('case_id', ids).eq('automated', true),
    ]);
    const logs = (logRes.data ?? []) as SoarLogRow[];
    const timeline = (tlRes.data ?? []) as TimelineRow[];

    // An action is "done" only on an explicit SUCCESS/REQUESTED result; anything else carries its
    // logged result through so the page can show why (SKIPPED — not configured, FAILED: 401…).
    const outcome = (caseId: string, prefix: string) => {
        const entry = logs.filter((l) => l.case_id === caseId && l.action.startsWith(prefix)).sort((a, b) => b.executed_at.localeCompare(a.executed_at))[0];
        if (!entry) return { done: false, detail: null as string | null };
        const r = entry.result ?? '';
        return { done: r.startsWith('SUCCESS') || r.startsWith('REQUESTED'), detail: r };
    };

    res.json({
        total: count ?? ids.length,
        cases: (cases ?? []).map((c) => {
            const tl = timeline.filter((t) => t.case_id === c.id);
            const closeEntry = tl.find((t) => t.action.startsWith('Case auto-closed'));
            return {
                ...c,
                ip_blocked: outcome(c.id, 'Block IP'),
                agent_isolated: outcome(c.id, 'Isolate agent'),
                slack_sent: tl.some((t) => t.action.startsWith('Slack notification sent')),
                ciso_notified: tl.some((t) => t.action.startsWith('CISO escalation email sent')),
                enriched: tl.some((t) => t.action.startsWith('IOC enriched')),
                close_reason: closeEntry ? closeEntry.action.replace(/^Case auto-closed:\s*/, '') : null,
            };
        }),
    });
});

// GET /api/soar/log?limit= — most recent engine actions, newest first.
router.get('/log', requireAuth, async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Case store not configured' }); return; }
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const { data, error } = await supabase
        .from('soar_log')
        .select('id, case_id, tier, action, result, executed_at, cases!inner(case_number, title, severity, org_id)')
        .eq('cases.org_id', orgOf(req))
        .order('executed_at', { ascending: false })
        .limit(limit);
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ entries: data ?? [] });
});

// POST /api/soar/enrich { ip } — X-NovrSOC-SOAR-Token: $SOAR_ENGINE_TOKEN
//
// Fails closed: with SOAR_ENGINE_TOKEN unset, every call is refused. Header compared in
// constant time; same shape as routes/emailProxy.ts's mail-host check.
router.post('/enrich', async (req, res) => {
    const expected = process.env.SOAR_ENGINE_TOKEN ?? '';
    const presented = Buffer.from(req.get('x-novrsoc-soar-token') ?? '');
    const wanted = Buffer.from(expected);
    if (!expected || presented.length !== wanted.length || !timingSafeEqual(presented, wanted)) {
        res.status(401).json({ error: 'Unauthorised', detail: expected ? 'Invalid or missing SOAR token.' : 'SOAR_ENGINE_TOKEN is not set on the backend.' });
        return;
    }

    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-f:]+$/i.test(ip)) {
        res.status(400).json({ error: 'ip must be an IPv4 or IPv6 address' });
        return;
    }

    try {
        const result = await enrichIOC(ip, 'ip');
        res.json({ ip, verdict: result.verdict, risk_score: result.risk_score });
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'enrichment failed' });
    }
});

export default router;
