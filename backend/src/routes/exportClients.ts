// /api/admin/export-clients — machine credentials for the vendor export API (phase X1).
// Mounted behind requireAuth + requireRole('super_admin') in index.ts. Every change is audited.
//
//   GET    /                 list (never a token or its hash)
//   POST   /                 { name, org_ids[], allowed_cidrs[], redaction_profile? } -> client + token (shown once)
//   POST   /:id/rotate       new token (shown once); the old one stops working immediately
//   POST   /:id/disable | /:id/enable
//   PATCH  /:id              { name?, allowed_cidrs? } — same validation as create (phase X2)
//   GET    /:id/access-log   recent export_access_log rows for this client (phase X2)
//
// Tokens are 32 random bytes (base64url, "nsx_" prefix so secret scanners can spot them). Only the
// SHA-256 hex digest is stored; the plaintext exists in exactly one HTTP response.

import { Router, type Response } from 'express';
import { randomBytes, createHash } from 'crypto';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { parseCidr } from '../lib/cidr';
import { REDACTION_PROFILES } from '../lib/redact';

const router = Router();

export const PUBLIC_COLUMNS = 'id, name, org_ids, allowed_cidrs, enabled, redaction_profile, created_at, rotated_at, last_used_at';

export function newToken(): { token: string; hash: string } {
    const token = `nsx_${randomBytes(32).toString('base64url')}`;
    return { token, hash: hashToken(token) };
}
export const hashToken = (token: string) => createHash('sha256').update(token, 'utf8').digest('hex');

const CreateBody = z.object({
    name: z.string().trim().min(1).max(100),
    org_ids: z.array(z.string().trim().min(1).max(128)).min(1).max(50),
    allowed_cidrs: z.array(z.string().trim().min(1).max(64)).min(1).max(50),
    redaction_profile: z.enum(REDACTION_PROFILES).optional(),
});

// Only name and allowed_cidrs can change after creation; org scope, profile and the token can't
// (rotate replaces the token). Unknown fields are refused rather than ignored.
const PatchBody = z.object({
    name: CreateBody.shape.name.optional(),
    allowed_cidrs: CreateBody.shape.allowed_cidrs.optional(),
}).strict().refine((b) => b.name !== undefined || b.allowed_cidrs !== undefined, { message: 'nothing to update' });

/** Unique, trimmed CIDRs, or the list of invalid ones (/0 is invalid). */
function checkCidrs(input: string[]): { ok: true; cidrs: string[] } | { ok: false; bad: string[] } {
    const cidrs = [...new Set(input)];
    const bad = cidrs.filter((c) => !parseCidr(c));
    return bad.length ? { ok: false, bad } : { ok: true, cidrs };
}

function noStore(res: Response): boolean {
    if (getSupabase()) return false;
    res.status(503).json({ error: 'Database not configured' });
    return true;
}

function audit(req: AuthRequest, action: string, id: string, details: string) {
    logAudit({
        user: req.user?.email ?? 'unknown', action, resource: 'export_client', resource_id: id,
        ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: details.slice(0, 200),
    });
}

router.get('/', async (_req, res) => {
    if (noStore(res)) return;
    const { data, error } = await getSupabase()!.from('export_clients').select(PUBLIC_COLUMNS).order('created_at', { ascending: false });
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ clients: data ?? [] });
});

router.post('/', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const parsed = CreateBody.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: `Body must be { name, org_ids: [≥1 slug], allowed_cidrs: [≥1 CIDR], redaction_profile?: ${REDACTION_PROFILES.join(' | ')} }` });
        return;
    }
    const { name, redaction_profile } = parsed.data;
    const orgIds = [...new Set(parsed.data.org_ids)];
    const checked = checkCidrs(parsed.data.allowed_cidrs);
    if (!checked.ok) { res.status(400).json({ error: `Invalid CIDR (or /0): ${checked.bad.join(', ')}` }); return; }
    const cidrs = checked.cidrs;

    const supabase = getSupabase()!;
    const { data: orgs, error: orgErr } = await supabase.from('organisations').select('slug').in('slug', orgIds);
    if (orgErr) { res.status(502).json({ error: dbErrorMessage(orgErr) }); return; }
    const known = new Set((orgs ?? []).map((o) => o.slug as string));
    const unknown = orgIds.filter((o) => !known.has(o));
    if (unknown.length) { res.status(400).json({ error: `Unknown organisation: ${unknown.join(', ')}` }); return; }

    const { token, hash } = newToken();
    const { data, error } = await supabase.from('export_clients')
        .insert({ name, token_hash: hash, org_ids: orgIds, allowed_cidrs: cidrs, enabled: true, redaction_profile: redaction_profile ?? 'standard' })
        .select(PUBLIC_COLUMNS).single();
    if (error || !data) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    const client = data as unknown as { id: string };
    audit(req, 'EXPORT_CLIENT_CREATED', client.id, `${name}: orgs ${orgIds.join(',')} cidrs ${cidrs.join(',')}`);
    res.status(201).json({ client, token, note: 'Store this token now — it is not shown again.' });
});

async function setFields(req: AuthRequest, res: Response, fields: Record<string, unknown>, action: string, details: string, token?: string) {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Export client not found' }); return; }
    const { data, error } = await getSupabase()!.from('export_clients').update(fields).eq('id', id).select(PUBLIC_COLUMNS).maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Export client not found' }); return; }
    audit(req, action, id, details);
    res.json(token ? { client: data, token, note: 'Store this token now — it is not shown again. The previous token no longer works.' } : { client: data });
}

router.post('/:id/rotate', (req: AuthRequest, res) => {
    const { token, hash } = newToken();
    void setFields(req, res, { token_hash: hash, rotated_at: new Date().toISOString() }, 'EXPORT_CLIENT_ROTATED', 'token rotated', token);
});
router.post('/:id/disable', (req: AuthRequest, res) => { void setFields(req, res, { enabled: false }, 'EXPORT_CLIENT_DISABLED', 'disabled'); });
router.post('/:id/enable', (req: AuthRequest, res) => { void setFields(req, res, { enabled: true }, 'EXPORT_CLIENT_ENABLED', 'enabled'); });

router.patch('/:id', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Export client not found' }); return; }
    const parsed = PatchBody.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: 'Body must be { name?, allowed_cidrs?: [≥1 CIDR] } with at least one of them; nothing else can be changed' });
        return;
    }
    const fields: Record<string, unknown> = {};
    const changes: string[] = [];
    if (parsed.data.name !== undefined) { fields.name = parsed.data.name; changes.push(`name=${parsed.data.name}`); }
    if (parsed.data.allowed_cidrs !== undefined) {
        const checked = checkCidrs(parsed.data.allowed_cidrs);
        if (!checked.ok) { res.status(400).json({ error: `Invalid CIDR (or /0): ${checked.bad.join(', ')}` }); return; }
        fields.allowed_cidrs = checked.cidrs;
        changes.push(`cidrs=${checked.cidrs.join(',')}`);
    }
    await setFields(req, res, fields, 'EXPORT_CLIENT_UPDATED', changes.join(' '));
});

// GET /:id/access-log?limit=20 (max 100) — newest first. No payloads exist to return.
router.get('/:id/access-log', async (req, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Export client not found' }); return; }
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const { data, error } = await getSupabase()!.from('export_access_log')
        .select('at, source_ip, org_ids, row_count, cursor_from, cursor_to, status_code')
        .eq('client_id', id).order('at', { ascending: false }).limit(limit);
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ entries: data ?? [] });
});

export default router;
