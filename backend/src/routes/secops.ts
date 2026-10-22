import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { createCase } from '../services/cases';
import { sendBroadcastEmail } from '../services/email';
import { requestApproval } from '../services/responseApprovals';
import { getSupabase } from '../services/geoEnrichment';
import { enrichIOC, configuredSources, type IOCType } from '../services/iocEnrichment';
import { isPrivateAddress } from '../services/emailsec/safeFetch';
import { requirePermission, requestOrg } from '../lib/permissions';
import { requireScope, ownsAgent, padAgentId } from '../lib/orgScope';

const router = Router();

// Mirrors frontend/src/lib/mockTeam.ts's MOCK_TEAM analyst emails — duplicated here because
// this backend has no per-user account table to query yet (see that file's own header comment,
// and routes/auth.ts's single shared DEV_ADMIN_EMAIL bypass). Swap for a real query once one
// exists; until then, keep both lists in sync by hand.
const ANALYST_EMAILS = ['rayne@cybernovr.com', 'karl@cybernovr.com'];

// POST /api/secops/broadcast — Security Ops Management's "Team Communication" tab. Email is the
// only team channel. `success` reflects whether the email actually went.
router.post('/broadcast', requirePermission('handover:write'), async (req: AuthRequest, res) => {
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
//   1. A case is opened for analyst follow-up. source_id is the IOC, so hunting the same IP twice
//      returns the existing case rather than opening a second one. If the case cannot be opened,
//      the request fails and no enrichment is attempted.
//   2. The IOC is then enriched with the same pipeline as IOC Lookup (services/iocEnrichment.ts),
//      each source capped at HUNT_ENRICH_TIMEOUT_MS, and the real result is cached in
//      ioc_enrichments (same table routes/cti.ts writes). Enrichment never fails the request:
//      the case already exists. When no source is configured for the IOC type, the IP is
//      private, every source timed out, or enrichment fails, nothing is written: an unscored row
//      would read as "clean" (risk_score is NOT NULL DEFAULT 0). The response says why in
//      `ioc_note`.
const HUNT_IOC_TYPES: IOCType[] = ['ip', 'domain', 'hash', 'url'];
const HUNT_ENRICH_TIMEOUT_MS = 5000;

router.post('/hunting/escalate', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    const { ioc_value, ioc_type, finding, source_alert_id } = req.body as {
        ioc_value?: string; ioc_type?: string; finding?: string; source_alert_id?: string;
    };
    if (!ioc_value || !ioc_type || !finding) {
        res.status(400).json({ error: 'ioc_value, ioc_type, and finding are required' });
        return;
    }

    const result = await createCase({
        title: `Threat Hunt Finding: ${ioc_value}`,
        description: `${finding}${source_alert_id ? `\n\nSource alert: ${source_alert_id}` : ''}`,
        severity: 'high',
        source: 'threat_hunt',
        source_id: `${ioc_type}:${ioc_value}`,
        source_ip: ioc_type === 'ip' ? ioc_value : null,
        org_id: requestOrg(req),
        tags: ['threat-hunt', 'manual'],
    }, req.user?.email || 'analyst');

    if (!result.ok) {
        res.status(result.status).json({
            error: result.error, ioc_saved: false,
            ioc_note: 'IOC enrichment not attempted — the case could not be opened.', enrichment: null,
        });
        return;
    }

    let iocSaved = false;
    let iocNote: string | null = null;
    let enrichment: { verdict: string; risk_score: number; sources: string[]; timed_out: string[] } | null = null;
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
            const enriched = await enrichIOC(ioc_value, type, { timeoutMs: HUNT_ENRICH_TIMEOUT_MS });
            const timedOut = enriched.timed_out ?? [];
            const answered = sources.filter((s) => !timedOut.includes(s));
            if (answered.length === 0) {
                iocNote = `IOC enrichment timed out (${HUNT_ENRICH_TIMEOUT_MS / 1000}s per source) — not added to the IOC cache.`;
            } else {
                enrichment = { verdict: enriched.verdict, risk_score: enriched.risk_score, sources: answered, timed_out: timedOut };
                // ioc_enrichments is one shared row per IOC value. org_id records the organisation
                // that first added it and is never overwritten: insert-if-absent with the caller's
                // org, then refresh the enrichment fields only.
                const fields = {
                    ioc_type: type,
                    risk_score: enriched.risk_score,
                    tags: [...new Set([...enriched.tags, 'threat-hunt', 'analyst-confirmed'])],
                    source: 'threat_hunt',
                    last_seen: new Date().toISOString(),
                };
                const inserted = await supabase.from('ioc_enrichments').upsert(
                    { ioc_value, ...fields, org_id: requestOrg(req) },
                    { onConflict: 'ioc_value', ignoreDuplicates: true },
                );
                const { error } = inserted.error ? inserted : await supabase.from('ioc_enrichments').update(fields).eq('ioc_value', ioc_value);
                iocSaved = !error;
                if (error) {
                    console.error('[secops/hunting/escalate] ioc_enrichments upsert failed:', error.message);
                    iocNote = 'Enriched, but the IOC could not be cached.';
                } else if (timedOut.length > 0) {
                    iocNote = `Enriched without ${timedOut.join(', ')} (timed out after ${HUNT_ENRICH_TIMEOUT_MS / 1000}s).`;
                }
            }
        } catch (err) {
            console.error('[secops/hunting/escalate] enrichment failed:', err instanceof Error ? err.message : err);
            iocNote = 'IOC enrichment failed — not added to the IOC cache.';
        }
    }

    res.json({ success: true, case_id: result.case.id, case_number: result.case.case_number, created: result.created, ioc_saved: iocSaved, ioc_note: iocNote, enrichment });
});

// Isolate and block are consequential: they are requested here and run only once a SOC manager
// approves them (services/responseApprovals.ts, /api/response-approvals). 202 = waiting.
async function sendApprovalRequest(req: AuthRequest, res: import('express').Response, action: 'isolate_agent' | 'block_ip', target: string, label: string | null, reason: string) {
    const r = await requestApproval({ org_id: requestOrg(req), action, target, target_label: label, reason, source: 'playbook', requested_by: req.user?.email ?? 'unknown' });
    if (!r.ok) { res.status(r.status).json({ success: false, outcome: 'failed', message: r.error }); return; }
    res.status(202).json({
        success: false, outcome: 'pending_approval', approval_id: r.value.approval.id,
        message: r.value.existing ? 'Already waiting for approval' : 'Sent for approval — a SOC manager must approve it before it runs',
    });
}

// POST /api/secops/actions/isolate { endpoint_id, reason? } — endpoint_id is the Wazuh agent id.
router.post('/actions/isolate', requirePermission('response:contain'), async (req: AuthRequest, res) => {
    const endpointId = typeof req.body?.endpoint_id === 'string' ? req.body.endpoint_id.trim() : '';
    if (!endpointId) { res.status(400).json({ success: false, error: 'endpoint_id is required' }); return; }
    // Only an agent the organisation owns (lib/orgScope.ts) — the approval would otherwise run
    // active response on another organisation's endpoint. Unknown and foreign agents look alike.
    const scope = await requireScope(req, res);
    if (!scope) return;
    if (!ownsAgent(scope, endpointId)) { res.status(404).json({ success: false, error: 'Endpoint not found in this organisation' }); return; }
    const reason = typeof req.body?.reason === 'string' && req.body.reason.trim() ? req.body.reason.trim() : `Isolate agent ${endpointId} (playbook)`;
    await sendApprovalRequest(req, res, 'isolate_agent', padAgentId(endpointId), typeof req.body?.endpoint_name === 'string' ? req.body.endpoint_name : null, reason);
});

// POST /api/secops/actions/block-ip { ip, reason }
router.post('/actions/block-ip', requirePermission('response:contain'), async (req: AuthRequest, res) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
    if (!ip) { res.status(400).json({ success: false, error: 'ip is required' }); return; }
    if (!reason) { res.status(400).json({ success: false, error: 'reason is required — it is recorded with the block' }); return; }
    await sendApprovalRequest(req, res, 'block_ip', ip, null, reason);
});

export default router;
