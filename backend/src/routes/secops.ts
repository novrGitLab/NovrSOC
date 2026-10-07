import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { createCase } from '../services/cases';
import { sendBroadcastEmail } from '../services/email';
import { blockAddress, isolateEndpoint, type LoggedResult } from '../services/responseActions';
import { logAudit } from '../lib/audit';
import { getSupabase } from '../services/geoEnrichment';
import { enrichIOC, configuredSources, type IOCType } from '../services/iocEnrichment';
import { isPrivateAddress } from '../services/emailsec/safeFetch';

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

// POST /api/secops/hunting/escalate — Threat Hunting's "Add to Threats" action. Two steps:
//   1. The IOC is enriched with the same pipeline as IOC Lookup (services/iocEnrichment.ts) and the
//      real result is cached in ioc_enrichments (same table routes/cti.ts writes). When no
//      enrichment source is configured for the IOC type, the IP is private, or enrichment fails,
//      nothing is written:
//      an unscored row would read as "clean" (risk_score is NOT NULL DEFAULT 0). The response
//      says why in `ioc_note`.
//   2. A case is opened for analyst follow-up. source_id is the IOC, so hunting the same IP twice
//      returns the existing case rather than opening a second one.
const HUNT_IOC_TYPES: IOCType[] = ['ip', 'domain', 'hash', 'url'];

router.post('/hunting/escalate', async (req: AuthRequest, res) => {
    const { ioc_value, ioc_type, finding, source_alert_id } = req.body as {
        ioc_value?: string; ioc_type?: string; finding?: string; source_alert_id?: string;
    };
    if (!ioc_value || !ioc_type || !finding) {
        res.status(400).json({ error: 'ioc_value, ioc_type, and finding are required' });
        return;
    }

    let iocSaved = false;
    let iocNote: string | null = null;
    let enrichment: { verdict: string; risk_score: number; sources: string[] } | null = null;
    const supabase = getSupabase();
    const type = HUNT_IOC_TYPES.includes(ioc_type as IOCType) ? (ioc_type as IOCType) : null;
    const sources = type ? configuredSources(type) : [];

    if (!type) {
        iocNote = `IOC type "${ioc_type}" cannot be enriched — not added to the IOC cache.`;
    } else if (type === 'ip' && isPrivateAddress(ioc_value)) {
        // Internal addresses are never sent to external intelligence services (same rule as
        // IOC Lookup and the case enrich_iocs task).
        iocNote = 'Private/internal IP — not sent to external threat-intelligence sources and not added to the IOC cache.';
    } else if (sources.length === 0) {
        iocNote = 'IOC enrichment is unavailable (no threat-intelligence keys configured for this IOC type) — not added to the IOC cache.';
    } else if (!supabase) {
        iocNote = 'Database not configured — the IOC was not cached.';
    } else {
        try {
            const result = await enrichIOC(ioc_value, type);
            enrichment = { verdict: result.verdict, risk_score: result.risk_score, sources };
            const { error } = await supabase.from('ioc_enrichments').upsert(
                {
                    ioc_value,
                    ioc_type: type,
                    risk_score: result.risk_score,
                    tags: [...new Set([...result.tags, 'threat-hunt', 'analyst-confirmed'])],
                    org_id: req.user?.org_id ?? null,
                    source: 'threat_hunt',
                    last_seen: new Date().toISOString(),
                },
                { onConflict: 'ioc_value' },
            );
            iocSaved = !error;
            if (error) {
                console.error('[secops/hunting/escalate] ioc_enrichments upsert failed:', error.message);
                iocNote = 'Enriched, but the IOC could not be cached.';
            }
        } catch (err) {
            console.error('[secops/hunting/escalate] enrichment failed:', err instanceof Error ? err.message : err);
            iocNote = 'IOC enrichment failed — not added to the IOC cache.';
        }
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
        res.status(result.status).json({ error: result.error, ioc_saved: iocSaved, ioc_note: iocNote, enrichment });
        return;
    }

    res.json({ success: true, case_id: result.case.id, case_number: result.case.case_number, created: result.created, ioc_saved: iocSaved, ioc_note: iocNote, enrichment });
});

// Playbook step execution (Playbooks page → automated steps). These run the same real actions
// as a case's Execute button, without a case. success is true only when the remote system
// accepted the action; a "not connected" action comes back as outcome 'skipped' with the reason.
function sendActionResult(req: AuthRequest, res: import('express').Response, action: string, target: string, r: LoggedResult) {
    logAudit({
        user: req.user?.email ?? 'unknown', action: 'PLAYBOOK_ACTION', resource: action, resource_id: target,
        ip: req.ip ?? 'unknown', result: r.outcome === 'success' ? 'success' : 'failed',
        details: `${action} ${target}: ${r.outcome} — ${r.message}`.slice(0, 200), severity: r.outcome === 'success' ? 'warning' : 'info',
    });
    res.status(r.outcome === 'failed' ? 502 : 200).json({
        success: r.outcome === 'success', outcome: r.outcome, message: r.message, action_id: r.action_id,
    });
}

// POST /api/secops/actions/isolate { endpoint_id, reason? } — endpoint_id is the Wazuh agent id.
router.post('/actions/isolate', async (req: AuthRequest, res) => {
    const endpointId = typeof req.body?.endpoint_id === 'string' ? req.body.endpoint_id.trim() : '';
    if (!endpointId) { res.status(400).json({ success: false, error: 'endpoint_id is required' }); return; }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : undefined;
    sendActionResult(req, res, 'isolate', endpointId, await isolateEndpoint(endpointId, { reason, agentName: req.body?.endpoint_name ?? null }));
});

// POST /api/secops/actions/block-ip { ip, reason }
router.post('/actions/block-ip', async (req: AuthRequest, res) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
    if (!ip) { res.status(400).json({ success: false, error: 'ip is required' }); return; }
    if (!reason) { res.status(400).json({ success: false, error: 'reason is required — it is recorded with the block' }); return; }
    sendActionResult(req, res, 'block-ip', ip, await blockAddress(ip, { reason }));
});

export default router;
