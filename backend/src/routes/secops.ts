import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { createCase } from '../services/cases';
import { sendBroadcastEmail } from '../services/email';
import { getSupabase } from '../services/geoEnrichment';

const router = Router();

// Mirrors frontend/src/lib/mockTeam.ts's MOCK_TEAM analyst emails — duplicated here because
// this backend has no per-user account table to query yet (see that file's own header comment,
// and routes/auth.ts's single shared DEV_ADMIN_EMAIL bypass). Swap for a real query once one
// exists; until then, keep both lists in sync by hand.
const ANALYST_EMAILS = ['rayne@cybernovr.com', 'karl@cybernovr.com'];

// POST /api/secops/broadcast — Security Ops Management's "Team Communication" tab. Email is the
// only team channel. `success` reflects whether the email actually went.
router.post('/broadcast', async (req: AuthRequest, res) => {
    const { message } = req.body as { message?: string };
    if (!message?.trim()) {
        res.status(400).json({ error: 'message required' });
        return;
    }
    const from = req.user?.email || 'NovrSOC Analyst';

    try {
        await sendBroadcastEmail({ to: ANALYST_EMAILS, from, message: message.trim() });
        res.json({ success: true, results: { email: 'sent' } });
    } catch (err) {
        res.status(502).json({ success: false, results: { email: `failed: ${err instanceof Error ? err.message : String(err)}` } });
    }
});

// POST /api/secops/hunting/escalate — Threat Hunting's "Add to Threats" action. Two writes:
// the IOC goes into the shared threat-intel cache (ioc_enrichments, the same table
// routes/cti.ts's manual lookup already caches into — confirmed live against the real table:
// its actual columns are ioc_value/ioc_type/risk_score/tags/org_id/source/first_seen/last_seen,
// no separate "verdict" column, so the malicious classification rides on risk_score + tags
// instead), and a case is opened for analyst follow-up. source_id is the IOC, so hunting the
// same IP twice returns the existing case rather than opening a second one.
router.post('/hunting/escalate', async (req: AuthRequest, res) => {
    const { ioc_value, ioc_type, finding, source_alert_id } = req.body as {
        ioc_value?: string; ioc_type?: string; finding?: string; source_alert_id?: string;
    };
    if (!ioc_value || !ioc_type || !finding) {
        res.status(400).json({ error: 'ioc_value, ioc_type, and finding are required' });
        return;
    }

    let iocSaved = false;
    const supabase = getSupabase();
    if (supabase) {
        const { error } = await supabase.from('ioc_enrichments').upsert(
            {
                ioc_value,
                ioc_type,
                risk_score: 85,
                tags: ['threat-hunt', 'analyst-confirmed'],
                org_id: req.user?.org_id ?? null,
                source: 'threat_hunt',
                last_seen: new Date().toISOString(),
            },
            { onConflict: 'ioc_value' },
        );
        iocSaved = !error;
        if (error) console.error('[secops/hunting/escalate] ioc_enrichments upsert failed:', error.message);
    }

    const result = await createCase({
        title: `Threat Hunt Finding: ${ioc_value}`,
        description: `${finding}${source_alert_id ? `\n\nSource alert: ${source_alert_id}` : ''}`,
        severity: 'high',
        source: 'threat_hunt',
        source_id: `${ioc_type}:${ioc_value}`,
        source_ip: ioc_type === 'ip' ? ioc_value : null,
        org_id: req.user?.org_id,
        tags: ['threat-hunt', 'manual'],
    }, req.user?.email || 'analyst');

    if (!result.ok) {
        res.status(result.status).json({ error: result.error, ioc_saved: iocSaved });
        return;
    }

    res.json({ success: true, case_id: result.case.id, case_number: result.case.case_number, created: result.created, ioc_saved: iocSaved });
});

export default router;
