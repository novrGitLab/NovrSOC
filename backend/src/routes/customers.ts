import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';

const router = Router();

// Was a proxy to APP_API_BASE_URL (138.197.188.132) — that host is unreachable from Railway
// (see PRODUCTION_NOTES.md's Known Issues #1), so this always 502'd in production. Now backed
// by the `organisations` table directly (same table routes/organisations.ts's CRUD lives on).
//
// Response shape is kept identical to what this route already returned from the dead proxy
// (customers: [{ id, name, industry, status, agentsTotal, activeIncidents, wazuhGroup }], plus
// domain/plan now added) — GeneralDashboard.tsx's Onboarded Clients widget and ExecutiveReport.tsx
// both still read this exact shape, and both already treat agentsTotal/activeIncidents as
// fallback defaults only (the dashboard widget overwrites them with a live per-org Wazuh lookup
// the moment its own effect runs) — so 0 here is honest, not a regression, and nothing needed to
// change in either of those two files. `id` changes from a fake sequential number to the org's
// real UUID; both call sites only ever use it as an opaque React/Record key, never arithmetically.
router.get('/', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.json({ customers: [], total: 0, source: 'unconfigured' });
        return;
    }

    try {
        const isAdmin = req.user?.role === 'super_admin';
        let query = supabase.from('organisations').select('*').order('created_at', { ascending: false });
        if (!isAdmin && req.user?.org_id) query = query.eq('slug', req.user.org_id);

        const { data, error } = await query;
        if (error) throw error;

        const customers = (data || []).map((org: Record<string, unknown>) => ({
            id: org.id,
            name: org.name,
            domain: org.domain ?? null,
            industry: org.industry ?? null,
            plan: org.plan ?? 'starter',
            // `status` is a new column (see sql/2026-09-organisations-onboarding.sql) — falls
            // back to the pre-existing `is_active` boolean for any row read before that
            // migration runs, so this never renders blank.
            status: org.status ?? (org.is_active ? 'active' : 'suspended'),
            agentsTotal: 0,
            activeIncidents: 0,
            wazuhGroup: org.wazuh_group ?? null,
            // Drives the dashboard's "Complete Setup" prompt — an org that was created but never
            // taken through the onboarding wizard has no Wazuh group or contacts, so its widgets
            // silently show nothing until someone finishes it.
            setupComplete: !!org.setup_complete,
        }));

        res.json({ customers, total: customers.length, source: 'supabase' });
    } catch (err) {
        console.error('[customers] List error:', err);
        res.status(500).json({ customers: [], total: 0, error: 'Failed to load customers' });
    }
});

export default router;
