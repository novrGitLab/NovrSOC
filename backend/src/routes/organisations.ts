import { Router } from 'express';
import { getSupabase } from '../services/geoEnrichment';
import { requireRole, type AuthRequest } from '../middleware/auth';

// Org onboarding wizard — POST /api/organisations/:id/setup persists the 4-step form
// (written by frontend/src/components/features/OnboardingWizard.tsx). Backed by Supabase's `org_setup`
// table when configured, falling back to the original in-memory store (gone on restart) when
// it isn't or a call to it fails — matches this codebase's established pattern for optional
// Supabase-backed persistence (see services/geoEnrichment.ts's getSupabase()).
//
// Schema note: `org_setup`'s real columns (confirmed live against the actual table) are
// org_id, compliance_frameworks, contacts, wazuh_group, initial_scores, setup_complete,
// updated_at, created_at — there is NO column for the wizard's step-1 "basic info" (name/
// industry/plan). That step's values are accepted and echoed back within a single request/
// response cycle so the wizard UI keeps working, but they are NOT persisted across reloads
// when Supabase is the active backend (the in-memory fallback path still keeps them, since it
// has nowhere better to put them either, but it doesn't survive a restart anyway). Add a
// basic_info column (or a name/industry/plan set of columns) to persist that step for real.

const router = Router();

interface ComplianceFrameworkSelection {
    framework: string;
    enabled: boolean;
    initialScore: number;
}
interface OrgContacts {
    cisoName: string;
    cisoEmail: string;
    itDirectorEmail: string;
    onCallPhone: string;
}
interface OrgSetup {
    orgId: string;
    basicInfo: { name: string; industry: string; plan: string };
    frameworks: ComplianceFrameworkSelection[];
    contacts: OrgContacts;
    wazuhGroup: string;
    setup_complete: boolean;
    updated_at: string;
}

// In-memory fallback — used when Supabase isn't configured, or a read/write to it fails.
const setupStore = new Map<string, OrgSetup>();

function emptySetup(orgId: string): OrgSetup {
    return {
        orgId,
        basicInfo: { name: '', industry: '', plan: '' },
        frameworks: [],
        contacts: { cisoName: '', cisoEmail: '', itDirectorEmail: '', onCallPhone: '' },
        wazuhGroup: '',
        setup_complete: false,
        updated_at: new Date().toISOString(),
    };
}

// Maps a Supabase org_setup row onto the OrgSetup shape the frontend wizard actually reads.
// `basic_info` doesn't exist as a column (see the file header) — those fields come back empty,
// same as a brand-new org would look via the in-memory path.
//
// compliance_frameworks is confirmed live to be an array column that round-trips each element
// as a JSON-encoded string, not a native object — `["{\"framework\":...}"]`, not
// `[{"framework":...}]` — so each entry needs an explicit JSON.parse, not a plain cast.
function rowToOrgSetup(orgId: string, row: Record<string, unknown>): OrgSetup {
    const frameworks = Array.isArray(row.compliance_frameworks)
        ? row.compliance_frameworks.map((f) => {
            if (typeof f !== 'string') return f as ComplianceFrameworkSelection;
            try {
                return JSON.parse(f) as ComplianceFrameworkSelection;
            } catch {
                return null;
            }
        }).filter((f): f is ComplianceFrameworkSelection => f !== null)
        : [];

    return {
        orgId,
        basicInfo: { name: '', industry: '', plan: '' },
        frameworks,
        contacts: (row.contacts as OrgContacts) ?? { cisoName: '', cisoEmail: '', itDirectorEmail: '', onCallPhone: '' },
        wazuhGroup: typeof row.wazuh_group === 'string' ? row.wazuh_group : '',
        setup_complete: !!row.setup_complete,
        updated_at: typeof row.updated_at === 'string' ? row.updated_at : new Date().toISOString(),
    };
}

// GET /api/organisations/:id/setup — read back whatever's saved so far, so the wizard can
// resume instead of always starting blank.
//
// Explicit route-level role check added alongside the new CRUD routes below — this router
// used to be mounted with `requireRole('super_admin')` in index.ts, so every route here was
// implicitly super_admin-only. That mount is now just `requireAuth` (the new routes below need
// per-route role variation), so this check preserves this route's original protection level —
// widened to also admit soc_manager, matching the rest of this file's org-management routes.
router.get('/:id/setup', requireRole('super_admin', 'soc_manager'), async (req, res) => {
    const { id } = req.params;
    const supabase = getSupabase();

    if (supabase) {
        const { data, error } = await supabase.from('org_setup').select('*').eq('org_id', id).maybeSingle();
        if (!error) {
            res.json(data ? rowToOrgSetup(id, data) : emptySetup(id));
            return;
        }
        console.error('[organisations] Supabase read failed, falling back to in-memory:', error.message);
    }

    res.json(setupStore.get(id) ?? emptySetup(id));
});

// POST /api/organisations/:id/setup — same widened-but-still-gated protection as the GET above.
router.post('/:id/setup', requireRole('super_admin', 'soc_manager'), async (req, res) => {
    const { id } = req.params;
    const body = req.body as Partial<Omit<OrgSetup, 'orgId' | 'setup_complete' | 'updated_at'>>;

    const basicInfo = body.basicInfo ?? { name: '', industry: '', plan: '' };
    const frameworks = body.frameworks ?? [];
    const contacts = body.contacts ?? { cisoName: '', cisoEmail: '', itDirectorEmail: '', onCallPhone: '' };
    const wazuhGroup = body.wazuhGroup ?? '';
    const updated_at = new Date().toISOString();

    const supabase = getSupabase();
    if (supabase) {
        const row = {
            compliance_frameworks: frameworks,
            contacts,
            wazuh_group: wazuhGroup,
            // The dedicated column this table actually has for scores — derived from each
            // enabled framework's initialScore rather than duplicating the whole frameworks
            // array a second time.
            initial_scores: Object.fromEntries(frameworks.map((f) => [f.framework, f.initialScore])),
            setup_complete: true,
            updated_at,
        };

        // `org_id` has no unique/exclusion constraint on this table (confirmed live —
        // .upsert(..., { onConflict: 'org_id' }) 42P10s: "no unique or exclusion constraint
        // matching the ON CONFLICT specification"), so a real upsert isn't available here.
        // Select-then-update-or-insert instead.
        const { data: existing, error: selectError } = await supabase.from('org_setup').select('id').eq('org_id', id).maybeSingle();
        const { error } = selectError
            ? { error: selectError }
            : existing
                ? await supabase.from('org_setup').update(row).eq('org_id', id)
                : await supabase.from('org_setup').insert({ org_id: id, ...row });

        if (!error) {
            res.json({ success: true, source: 'supabase', setup_complete: true });
            return;
        }
        console.error('[organisations] Supabase write failed, falling back to in-memory:', error.message);
    }

    setupStore.set(id, { orgId: id, basicInfo, frameworks, contacts, wazuhGroup, setup_complete: true, updated_at });
    res.json({ success: true, source: 'memory', setup_complete: true, warning: supabase ? 'Supabase write failed — see server logs' : undefined });
});

// ── ORGANISATION CRUD + TEAM MANAGEMENT ──────────────────────────────
//
// Backed by the `organisations` table — this table already existed before this pass (id, name,
// slug, plan, industry, country, is_active, created_at, updated_at; one real row, the Cybernovr
// tenant, id 00000000-0000-0000-0000-000000000001) with none of the columns these routes need
// (domain, status, address, logo_url, wazuh_group, contact_*, ciso_*, setup_complete). Those are
// additive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` — see sql/2026-09-organisations-onboarding.sql
// — never a DROP/replace, so the existing row and its columns are untouched.
//
// Org identity used for tenant scoping is the SLUG, not this table's UUID `id` — deliberately.
// Every org-scoped table already live in this codebase (playbooks.org_id, org-cti's fallback in
// routes/orgCTI.ts) stores/reads the STRING 'cybernovr', not this row's UUID. A super_admin's own
// token, and every other role's, therefore carries the slug as `org_id` (see routes/auth.ts) —
// switching that to the UUID here would silently stop matching every existing playbook and
// org-cti record for the one real tenant that exists today. New orgs created via this router get
// their own unique slug the same way, so they stay consistent with that existing convention.
function slugify(name: string): string {
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

interface PlatformUserRow {
    id: string;
    org_id: string;
    email: string;
    name: string | null;
    role: string;
    status: string;
    last_login: string | null;
    avatar_url: string | null;
    created_at: string;
    updated_at: string;
}

// GET /api/organisations — list all orgs (super_admin only)
router.get('/', requireRole('super_admin'), async (_req, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Database not configured' });
        return;
    }
    try {
        const { data, error } = await supabase.from('organisations').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.json({ organisations: data || [], total: data?.length || 0 });
    } catch (err) {
        console.error('[organisations] List error:', err);
        res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to list organisations' });
    }
});

// GET /api/organisations/:id — single org. super_admin can look up any org by its UUID id;
// everyone else can only ever see their own org, resolved from their token's slug — the :id URL
// param is ignored for them rather than trusted (the same "don't trust a client-supplied org
// identifier" rule routes/compliance.ts already applies).
router.get('/:id', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Database not configured' });
        return;
    }
    const isAdmin = req.user?.role === 'super_admin';
    const lookupField = isAdmin ? 'id' : 'slug';
    const lookupValue = isAdmin ? req.params.id : req.user?.org_id;
    if (!lookupValue) {
        res.status(400).json({ error: 'No organisation to look up' });
        return;
    }
    try {
        const { data, error } = await supabase.from('organisations').select('*').eq(lookupField, lookupValue).single();
        if (error || !data) {
            res.status(404).json({ error: 'Organisation not found' });
            return;
        }
        res.json(data);
    } catch (err) {
        console.error('[organisations] Get error:', err);
        res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to load organisation' });
    }
});

// POST /api/organisations — create new org (super_admin only) — Step 1 of the onboarding wizard.
router.post('/', requireRole('super_admin'), async (req, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Database not configured' });
        return;
    }
    const {
        name, domain, industry, plan,
        contact_name, contact_email, contact_phone,
        ciso_name, ciso_email, address, country,
    } = req.body ?? {};

    if (!name || typeof name !== 'string' || !name.trim()) {
        res.status(400).json({ error: 'name required' });
        return;
    }

    const baseSlug = slugify(name);
    if (!baseSlug) {
        res.status(400).json({ error: 'name must contain at least one letter or digit' });
        return;
    }

    try {
        // Slugs are unique — a second "Zenith Bank" becomes zenith-bank-2, not a 409. Bounded
        // retry (not an infinite loop) so a Supabase outage mid-loop can't hang the request.
        let slug = baseSlug;
        for (let suffix = 2; suffix <= 21; suffix++) {
            const { data: clash } = await supabase.from('organisations').select('id').eq('slug', slug).maybeSingle();
            if (!clash) break;
            slug = `${baseSlug}-${suffix}`;
        }

        const row: Record<string, unknown> = {
            name: name.trim(),
            slug,
            domain: domain || null,
            industry: industry || null,
            plan: plan || 'starter',
            status: 'active',
            is_active: true,
            contact_name: contact_name || null,
            contact_email: contact_email || null,
            contact_phone: contact_phone || null,
            ciso_name: ciso_name || null,
            ciso_email: ciso_email || null,
            address: address || null,
            country: country || 'Nigeria',
            setup_complete: false,
        };

        let { data, error } = await supabase.from('organisations').insert(row).select().single();

        // Confirmed live (2026-09-05): this table pre-dates the `domain` column and
        // ALTER TABLE ... ADD COLUMN IF NOT EXISTS domain TEXT (sql/2026-09-organisations-
        // onboarding.sql) hasn't been run against it yet — PostgREST rejects the whole insert
        // with PGRST204 rather than just dropping the one unknown key. Retry once without
        // `domain` so org creation still works today; the org just won't have a domain on file
        // until that migration runs, same as `logo_url` etc. already don't for the existing
        // Cybernovr row.
        if (error?.code === 'PGRST204' && error.message.includes("'domain'")) {
            console.warn("[organisations] 'domain' column missing — retrying insert without it. Run sql/2026-09-organisations-onboarding.sql.");
            const { domain: _domain, ...rowWithoutDomain } = row;
            ({ data, error } = await supabase.from('organisations').insert(rowWithoutDomain).select().single());
        }

        if (error) throw error;
        res.status(201).json(data);
    } catch (err) {
        console.error('[organisations] Create error:', err);
        res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to create organisation' });
    }
});

// PATCH /api/organisations/:id — update org (super_admin, soc_manager)
router.patch('/:id', requireRole('super_admin', 'soc_manager'), async (req, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Database not configured' });
        return;
    }
    // Never let the request body overwrite the primary key or the slug identity fields wholesale
    // — slug changes would silently orphan every org-scoped record keyed by the old one.
    const { id: _id, slug: _slug, created_at: _createdAt, ...patch } = req.body ?? {};
    try {
        const { data, error } = await supabase
            .from('organisations')
            .update({ ...patch, updated_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .select()
            .single();
        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error('[organisations] Update error:', err);
        res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to update organisation' });
    }
});

// Resolves which org a caller may act on for the /users routes below — same rule as GET /:id.
function resolveOrgIdForUsers(req: AuthRequest, requestedId: string): { field: 'id' | 'slug'; value: string } | null {
    if (req.user?.role === 'super_admin') return { field: 'id', value: requestedId };
    if (!req.user?.org_id) return null;
    return { field: 'slug', value: req.user.org_id };
}

// GET /api/organisations/:id/users — org users. Same non-admin-can-only-see-own-org rule as
// GET /:id above — this wasn't in the original spec for this route, but leaving it open would
// let any authenticated user list another tenant's staff (names + emails) by guessing an id,
// which is exactly the class of bug routes/compliance.ts's header comment already documents
// fixing for a different route.
router.get('/:id/users', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Database not configured' });
        return;
    }
    const resolved = resolveOrgIdForUsers(req, req.params.id);
    if (!resolved) {
        res.status(401).json({ error: 'Unauthorised' });
        return;
    }
    try {
        let orgUuid = resolved.value;
        if (resolved.field === 'slug') {
            const { data: org } = await supabase.from('organisations').select('id').eq('slug', resolved.value).maybeSingle();
            if (!org) {
                res.json({ users: [] });
                return;
            }
            orgUuid = org.id;
        }
        const { data, error } = await supabase.from('platform_users').select('*').eq('org_id', orgUuid).order('created_at');
        if (error) throw error;
        res.json({ users: (data || []) as PlatformUserRow[] });
    } catch (err) {
        console.error('[organisations] List users error:', err);
        res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to list users' });
    }
});

// POST /api/organisations/:id/users — add user to org (super_admin, soc_manager; soc_manager
// restricted to their own org by resolveOrgIdForUsers above)
router.post('/:id/users', requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Database not configured' });
        return;
    }
    const resolved = resolveOrgIdForUsers(req, req.params.id);
    if (!resolved) {
        res.status(401).json({ error: 'Unauthorised' });
        return;
    }

    const { email, name, role } = req.body ?? {};
    const validRoles = ['soc_manager', 'analyst', 'executive', 'portal_user'];
    if (!email || typeof email !== 'string') {
        res.status(400).json({ error: 'email required' });
        return;
    }
    if (!validRoles.includes(role)) {
        res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
        return;
    }

    try {
        let orgUuid = resolved.value;
        if (resolved.field === 'slug') {
            const { data: org, error: orgErr } = await supabase.from('organisations').select('id').eq('slug', resolved.value).maybeSingle();
            if (orgErr || !org) {
                res.status(404).json({ error: 'Organisation not found' });
                return;
            }
            orgUuid = org.id;
        }

        const { data, error } = await supabase
            .from('platform_users')
            .insert({ org_id: orgUuid, email: email.trim().toLowerCase(), name: name || null, role, status: 'active' })
            .select()
            .single();

        if (error) throw error;
        // TODO: send a welcome email via services/email.ts once there's a real per-user login
        // flow for them to land on — today only the single DEV_ADMIN_EMAIL/PASSWORD bypass can
        // actually sign in (see routes/auth.ts), so a welcome email would link somewhere a new
        // team member still couldn't use.
        res.status(201).json(data);
    } catch (err) {
        console.error('[organisations] Add user error:', err);
        res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to add user' });
    }
});

export default router;
