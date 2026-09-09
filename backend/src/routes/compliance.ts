import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';

const router = Router();

// Now Supabase-backed. Was a proxy to APP_API_BASE_URL (138.197.188.132), which is unreachable
// from Railway, so every request here fell through to a hardcoded zero-state.
//
// The real tables (column shapes verified live on 2026-09-08) are NOT the per-framework score
// table this route's shape implies:
//   compliance_frameworks   id uuid, name text, description text, total_controls int, is_active bool
//   compliance_assessments  id uuid, org_id uuid, framework_id uuid, control_id text NOT NULL,
//                           control_name text, status text, evidence_url text, notes text,
//                           assessed_by uuid, assessed_at timestamptz, next_review timestamptz
//
// Assessments are PER CONTROL, so a framework's score is derived (compliant controls ÷ that
// framework's total_controls), never stored. There is no `score`/`controls_assessed` column.
//
// Two id-space mismatches this route has to bridge, because the frontend can't be renumbered
// without breaking its routes:
//   * The 5 framework sub-pages (app/admin/compliance/*/page.tsx) hardcode integer frameworkIds
//     1-5, and ComplianceDashboard keys its colours/slugs off `shortName`. So the static list
//     below stays the canonical UI list and each entry is matched to its database row by name.
//     compliance_frameworks holds NDPR, ISO27001, PCI-DSS, NIST CSF and SOC2 (verified live);
//     CBN, NCC and SWIFT CSP have no row, so they report an honest zero rather than inventing
//     one. SOC2 exists in the database but has no UI page yet, so nothing maps to it.
//   * org_id is a uuid here, but the JWT carries an org *slug* ('cybernovr') and the frontend
//     sends a hardcoded `orgId=1`. resolveOrgUuid() below maps whatever it gets onto a real uuid.
//
// Response stays a top-level ARRAY on GET / and GET /controls — GeneralDashboard,
// ComplianceDashboard, ComplianceFramework, CustomerDetail and ExecutiveReport all do
// `Array.isArray(data) ? data : []`, so wrapping it in an object would blank all five.

// Static reference metadata. `dbName` is how this framework is spelled in compliance_frameworks
// (null = no database row exists for it yet).
export const COMPLIANCE_FRAMEWORKS: {
    id: number; name: string; shortName: string; description: string; totalControls: number; dbName: string | null;
}[] = [
    { id: 1, name: 'Nigeria Data Protection Act', shortName: 'NDPA', description: 'Nigerian data protection regulation', totalControls: 20, dbName: 'NDPR' },
    { id: 2, name: 'CBN Cybersecurity Framework', shortName: 'CBN', description: 'Central Bank of Nigeria cybersecurity requirements', totalControls: 25, dbName: null },
    { id: 3, name: 'NCC Cybersecurity Regulations', shortName: 'NCC', description: 'Nigerian Communications Commission security rules', totalControls: 20, dbName: null },
    { id: 4, name: 'ISO/IEC 27001:2022', shortName: 'ISO 27001', description: 'International information security management', totalControls: 30, dbName: 'ISO27001' },
    { id: 5, name: 'PCI DSS v4.0', shortName: 'PCI-DSS', description: 'Payment card industry data security standard', totalControls: 25, dbName: 'PCI-DSS' },
    { id: 6, name: 'NIST Cybersecurity Framework', shortName: 'NIST CSF', description: 'NIST cybersecurity framework', totalControls: 23, dbName: 'NIST CSF' },
    { id: 7, name: 'SWIFT Customer Security Programme', shortName: 'SWIFT CSP', description: 'SWIFT financial messaging security', totalControls: 22, dbName: null },
];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Statuses that count as "this control is satisfied". Everything else (not_assessed,
// non_compliant, in_progress…) counts as assessed-but-not-compliant.
const COMPLIANT_STATUSES = new Set(['compliant', 'pass', 'passed', 'met']);

type Supa = NonNullable<ReturnType<typeof getSupabase>>;

// slug -> uuid, cached for the process. Org slugs don't change without a redeploy-worthy event.
const orgUuidCache = new Map<string, string>();

// The JWT carries an org slug, the frontend sends a hardcoded orgId=1, and the table wants a
// uuid. Try each candidate in priority order and return the first that resolves to a real org.
async function resolveOrgUuid(supabase: Supa, req: AuthRequest, requested: string | null): Promise<string | null> {
    const candidates: string[] = [];
    // A super_admin may explicitly inspect another org; everyone else is pinned to their own.
    if (requested && req.user?.role === 'super_admin') candidates.push(requested);
    if (req.user?.org_id) candidates.push(req.user.org_id);

    for (const candidate of candidates) {
        if (UUID_RE.test(candidate)) return candidate;
        const cached = orgUuidCache.get(candidate);
        if (cached) return cached;
        const { data } = await supabase.from('organisations').select('id').eq('slug', candidate).maybeSingle();
        const id = (data as { id?: string } | null)?.id;
        if (id) {
            orgUuidCache.set(candidate, id);
            return id;
        }
    }
    return null;
}

interface FrameworkRow { id: string; name: string; total_controls: number | null }
interface AssessmentRow {
    id: string; framework_id: string | null; control_id: string; control_name: string | null;
    status: string | null; evidence_url: string | null; notes: string | null; assessed_at: string | null;
    next_review: string | null;
}

// GET /api/compliance — one entry per static framework, with real assessed/compliant counts
// wherever a matching database framework exists.
router.get('/', async (req: AuthRequest, res) => {
    const requested = typeof req.query.orgId === 'string' ? req.query.orgId : null;
    const supabase = getSupabase();

    // Honest zero-state shape, reused whenever the data isn't reachable.
    const zeroState = () => COMPLIANCE_FRAMEWORKS.map((f) => ({
        id: f.id, name: f.name, shortName: f.shortName, description: f.description,
        totalControls: f.totalControls, assessed: 0, compliant: 0, score: 0,
    }));

    if (!supabase) {
        res.json(zeroState());
        return;
    }

    try {
        const orgUuid = await resolveOrgUuid(supabase, req, requested);
        if (!orgUuid) {
            res.json(zeroState());
            return;
        }

        const [{ data: fwData }, { data: asData }] = await Promise.all([
            supabase.from('compliance_frameworks').select('id, name, total_controls'),
            supabase.from('compliance_assessments').select('framework_id, status').eq('org_id', orgUuid),
        ]);

        const frameworksByName = new Map((fwData as FrameworkRow[] | null ?? []).map((f) => [f.name, f]));

        // Tally assessed/compliant per framework uuid in one pass.
        const tally = new Map<string, { assessed: number; compliant: number }>();
        for (const a of (asData as Pick<AssessmentRow, 'framework_id' | 'status'>[] | null) ?? []) {
            if (!a.framework_id) continue;
            const entry = tally.get(a.framework_id) ?? { assessed: 0, compliant: 0 };
            entry.assessed += 1;
            if (a.status && COMPLIANT_STATUSES.has(a.status.toLowerCase())) entry.compliant += 1;
            tally.set(a.framework_id, entry);
        }

        const frameworks = COMPLIANCE_FRAMEWORKS.map((f) => {
            const dbRow = f.dbName ? frameworksByName.get(f.dbName) : undefined;
            const counts = dbRow ? tally.get(dbRow.id) : undefined;
            // Prefer the database's own control count when it has one — it's the authority on
            // how many controls the framework actually has.
            const totalControls = dbRow?.total_controls ?? f.totalControls;
            const assessed = counts?.assessed ?? 0;
            const compliant = counts?.compliant ?? 0;
            return {
                id: f.id,
                name: f.name,
                shortName: f.shortName,
                description: f.description,
                totalControls,
                assessed,
                compliant,
                score: totalControls > 0 ? Math.round((compliant / totalControls) * 100) : 0,
            };
        });

        res.json(frameworks);
    } catch (err) {
        console.error('[compliance] GET failed:', err instanceof Error ? err.message : err);
        res.json(zeroState());
    }
});

// GET /api/compliance/controls?frameworkId=<1-7>&orgId= — the org's assessed controls for one
// framework. Empty array (not an error) when that framework has no database row yet.
router.get('/controls', async (req: AuthRequest, res) => {
    const frameworkId = typeof req.query.frameworkId === 'string' ? req.query.frameworkId : null;
    const requested = typeof req.query.orgId === 'string' ? req.query.orgId : null;
    if (!frameworkId) {
        res.status(400).json({ error: 'frameworkId is required' });
        return;
    }

    const supabase = getSupabase();
    if (!supabase) {
        res.json([]);
        return;
    }

    try {
        const staticFw = COMPLIANCE_FRAMEWORKS.find((f) => String(f.id) === frameworkId);
        if (!staticFw?.dbName) {
            res.json([]);
            return;
        }

        const orgUuid = await resolveOrgUuid(supabase, req, requested);
        if (!orgUuid) {
            res.json([]);
            return;
        }

        const { data: fwRow } = await supabase
            .from('compliance_frameworks').select('id').eq('name', staticFw.dbName).maybeSingle();
        const fwUuid = (fwRow as { id?: string } | null)?.id;
        if (!fwUuid) {
            res.json([]);
            return;
        }

        const { data, error } = await supabase
            .from('compliance_assessments')
            .select('id, control_id, control_name, status, evidence_url, notes, assessed_at, next_review')
            .eq('org_id', orgUuid)
            .eq('framework_id', fwUuid)
            .order('control_id', { ascending: true });
        if (error) throw error;

        res.json(data ?? []);
    } catch (err) {
        console.error('[compliance] controls failed:', err instanceof Error ? err.message : err);
        res.json([]);
    }
});

// POST /api/compliance — record one control assessment.
//
// No upsert: (org_id, framework_id, control_id) has no unique constraint on this table, so a
// real .upsert() would 42P10 (same limitation routes/playbooks.ts documents for its own table).
// Update-then-insert-if-absent instead.
router.post('/', async (req: AuthRequest, res) => {
    const body = req.body as {
        orgId?: number | string; frameworkId?: number | string; controlId?: string;
        controlName?: string; status?: string; notes?: string; evidenceUrl?: string; nextReview?: string;
    };

    const controlId = body.controlId != null ? String(body.controlId) : '';
    if (!body.frameworkId || !controlId || !body.status) {
        res.status(400).json({ error: 'frameworkId, controlId, and status are required' });
        return;
    }

    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Supabase not configured' });
        return;
    }

    try {
        const staticFw = COMPLIANCE_FRAMEWORKS.find((f) => String(f.id) === String(body.frameworkId));
        if (!staticFw?.dbName) {
            res.status(400).json({ error: 'That framework has no compliance_frameworks row yet — cannot record an assessment against it.' });
            return;
        }

        const orgUuid = await resolveOrgUuid(supabase, req, body.orgId != null ? String(body.orgId) : null);
        if (!orgUuid) {
            res.status(400).json({ error: 'Could not resolve an organisation for this request' });
            return;
        }

        const { data: fwRow } = await supabase
            .from('compliance_frameworks').select('id').eq('name', staticFw.dbName).maybeSingle();
        const fwUuid = (fwRow as { id?: string } | null)?.id;
        if (!fwUuid) {
            res.status(400).json({ error: `Framework ${staticFw.dbName} is not present in compliance_frameworks` });
            return;
        }

        const patch = {
            control_name: body.controlName ?? null,
            status: body.status,
            notes: body.notes ?? null,
            evidence_url: body.evidenceUrl ?? null,
            assessed_at: new Date().toISOString(),
            next_review: body.nextReview ?? null,
        };

        const { data: updated, error: updateError } = await supabase
            .from('compliance_assessments')
            .update(patch)
            .eq('org_id', orgUuid).eq('framework_id', fwUuid).eq('control_id', controlId)
            .select();
        if (updateError) throw updateError;

        if (updated && updated.length > 0) {
            res.json({ success: true, assessment: updated[0] });
            return;
        }

        const { data: inserted, error: insertError } = await supabase
            .from('compliance_assessments')
            .insert({ org_id: orgUuid, framework_id: fwUuid, control_id: controlId, ...patch })
            .select()
            .single();
        if (insertError) throw insertError;

        res.status(201).json({ success: true, assessment: inserted });
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error('[compliance] POST failed:', message);
        res.status(502).json({ error: 'Failed to save assessment', detail: message });
    }
});

export default router;
