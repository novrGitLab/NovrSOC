// /api/response-approvals — pending and decided consequential response actions (phase P3).
//   GET  /?status=pending        response:contain (anyone who can request one can see the queue)
//   POST /:id/approve { note? }  response:approve — runs the action; the result is what happened
//   POST /:id/reject  { note? }  response:approve
//   POST /:id/cancel             the requester, or a manager
// Everything is scoped to the caller's organisation (requestOrg).

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg, hasPermission } from '../lib/permissions';
import { isUuid } from '../services/cases';
import { listApprovals, decideApproval, cancelApproval, type ApprovalRow } from '../services/responseApprovals';

const router = Router();
const STATUSES: ApprovalRow['status'][] = ['pending', 'approved', 'rejected', 'executed', 'failed', 'skipped', 'cancelled'];
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const note = (req: AuthRequest) => (typeof req.body?.note === 'string' && req.body.note.trim() ? req.body.note.trim() : null);

router.get('/', requirePermission('response:contain'), async (req: AuthRequest, res) => {
    const s = typeof req.query.status === 'string' ? req.query.status : undefined;
    if (s && !STATUSES.includes(s as ApprovalRow['status'])) { res.status(400).json({ error: `status must be one of ${STATUSES.join(', ')}` }); return; }
    const r = await listApprovals(requestOrg(req), s as ApprovalRow['status'] | undefined);
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.json({ approvals: r.value });
});

for (const [path, approve] of [['approve', true], ['reject', false]] as const) {
    router.post(`/:id/${path}`, requirePermission('response:approve'), async (req: AuthRequest, res) => {
        if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Approval request not found' }); return; }
        const r = await decideApproval(req.params.id, requestOrg(req), actor(req), approve, note(req));
        if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
        res.json({ approval: r.value });
    });
}

router.post('/:id/cancel', requirePermission('response:contain'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Approval request not found' }); return; }
    const r = await cancelApproval(req.params.id, requestOrg(req), actor(req), hasPermission(req.user?.role, 'response:approve'));
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.json({ approval: r.value });
});

export default router;
