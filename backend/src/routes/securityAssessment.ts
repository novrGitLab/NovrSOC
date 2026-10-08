import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requireRole } from '../middleware/auth';
import {
    orgMetrics, activeOrgs, SLA_TARGET_HOURS, SLA_SECURE_THRESHOLD, type OrgMetrics,
} from '../services/securityAssessment';
import { requireOrg, requestOrg } from '../lib/permissions';
import { isStaffRole } from '../lib/resolveOrg';

// Security Assessment — posture computed from real cases (services/securityAssessment.ts).
// Mounted behind requireAuth at /api/admin/security-assessment and /api/client/security-assessment.

export const adminRouter = Router();
export const clientRouter = Router();

const definitions = {
    sla_target_hours: SLA_TARGET_HOURS,
    sla_secure_threshold_pct: SLA_SECURE_THRESHOLD,
    detection_time: 'Not tracked — needs the time the underlying event occurred, which the pipeline does not record.',
};

// GET /api/admin/security-assessment/overview — every active client organisation.
adminRouter.get('/overview', requireRole('super_admin', 'soc_manager', 'executive'), async (_req, res) => {
    try {
        const orgs = await activeOrgs();
        const rows: OrgMetrics[] = [];
        for (const o of orgs) rows.push(await orgMetrics(o.slug, o.name));

        const withSla = rows.filter((r) => r.sla_rate !== null);
        const resolvedTotal = withSla.reduce((s, r) => s + r.resolved_30d, 0);
        const closeWeighted = rows.filter((r) => r.close_time_hrs !== null);
        const closeTotal = closeWeighted.reduce((s, r) => s + r.resolved_30d, 0);

        // All-client monthly SLA, weighted by cases resolved in each month.
        const monthly = rows[0]?.monthly.map((m, i) => {
            const pts = rows.map((r) => r.monthly[i]).filter((p) => p.sla_rate !== null);
            const n = pts.reduce((s, p) => s + p.resolved, 0);
            return { month: m.month, resolved: n, sla_rate: n > 0 ? Math.round((pts.reduce((s, p) => s + (p.sla_rate as number) * p.resolved, 0) / n) * 10) / 10 : null };
        }) ?? [];

        res.json({
            summary: {
                active_clients: orgs.length,
                avg_detection_time_hrs: null,
                avg_close_time_hrs: closeTotal > 0 ? Math.round((closeWeighted.reduce((s, r) => s + (r.close_time_hrs as number) * r.resolved_30d, 0) / closeTotal) * 10) / 10 : null,
                open_cases: rows.reduce((s, r) => s + r.open_cases, 0),
                sla_rate: resolvedTotal > 0 ? Math.round((withSla.reduce((s, r) => s + (r.sla_rate as number) * r.resolved_30d, 0) / resolvedTotal) * 10) / 10 : null,
                clients_below_sla: withSla.filter((r) => (r.sla_rate as number) < SLA_SECURE_THRESHOLD).length,
            },
            clients: rows.map(({ last_closed: _lc, ...r }) => r),
            monthly,
            definitions,
            generated_at: new Date().toISOString(),
        });
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'Could not compute the assessment' });
    }
});

// GET /api/client/security-assessment — one organisation's report card. The organisation comes
// from lib/resolveOrg.ts: the token's org, or for staff (super_admin, soc_manager, analyst)
// another existing org named in the X-Org-Id header (audited). Client roles always get their own
// and only see it in `orgs`. A token without an org is 403; there is no fallback organisation.
// Portal tokens can't be verified by this backend yet, so client-portal users get a 401 and the
// page explains why.
clientRouter.get('/', requireOrg, async (req: AuthRequest, res) => {
    try {
        const orgs = await activeOrgs();
        const wanted = requestOrg(req);
        const staff = isStaffRole(req.user?.role);
        const org = orgs.find((o) => o.slug === wanted);
        if (!org) { res.status(404).json({ error: 'Organisation not found or not active' }); return; }
        const metrics = await orgMetrics(org.slug, org.name);
        res.json({
            ...metrics,
            engagement: {
                score: null,
                components: [
                    { key: 'portal_logins', label: 'Portal logins this week', max: 30, value: null, reason: 'Not tracked yet — client portal sign-in is not connected (APP_API_BASE_URL unset).' },
                    { key: 'recommendations', label: 'Recommendations acknowledged', max: 40, value: null, reason: 'Not tracked yet — NovrSOC has no recommendations workflow to acknowledge.' },
                    { key: 'client_response', label: 'Cases responded to within 2 hrs', max: 30, value: null, reason: 'Not tracked yet — client replies on cases are not recorded.' },
                ],
            },
            orgs: (staff ? orgs : orgs.filter((o) => o.slug === wanted)).map((o) => ({ slug: o.slug, name: o.name })),
            definitions,
            generated_at: new Date().toISOString(),
        });
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'Could not compute the report card' });
    }
});
