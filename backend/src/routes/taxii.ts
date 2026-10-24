// TAXII 2.1 server (phase P25) — read-only exchange of the platform's shared threat intelligence,
// per OASIS TAXII Version 2.1 (2021). Mounted at /taxii2/ outside the user-session API.
//
//   GET  /taxii2/                                             discovery
//   GET  /taxii2/api1/                                        API root
//   GET  /taxii2/api1/status/:id/                             404 (nothing is ever written)
//   GET  /taxii2/api1/collections/                            the collections this client may read
//   GET  /taxii2/api1/collections/:id/                        one collection
//   GET  /taxii2/api1/collections/:id/objects/                envelope; added_after, limit, next, match[id|type|version|spec_version]
//   GET  /taxii2/api1/collections/:id/objects/:object_id/     envelope with that object
//   GET  /taxii2/api1/collections/:id/objects/:object_id/versions/
//   GET  /taxii2/api1/collections/:id/manifest/
//   POST|DELETE …objects…                                     403: no collection is writable
//
// Authentication: HTTP Basic — username is a client's key_id, password its secret (shown once
// when a manager creates the client; stored as a scrypt hash in ti_taxii_clients). Every endpoint
// requires it. A client sees only the collections listed on it (others are 404, so they cannot be
// enumerated) and never anything above its max_tlp; the sharing policy (services/tiPolicy.ts)
// applies on top. Collections hold shared intelligence only — never organisation data.
// Responses use the TAXII media type; an Accept header that rules it out gets 406.

import { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { scryptSync, randomBytes, timingSafeEqual, createHash } from 'crypto';
import { getSupabase } from '../services/geoEnrichment';
import { COLLECTIONS, collectionById, isCeiling, type CollectionDef, type ExportCeiling } from '../services/tiPolicy';
import { exchangePage, encodeCursor, decodeCursor } from '../services/tiExchange';
import { logAudit } from '../lib/audit';

export const TAXII_MEDIA = 'application/taxii+json;version=2.1';
export const STIX_MEDIA = 'application/stix+json;version=2.1';
const MAX_LIMIT = 1000;
const DEFAULT_LIMIT = 100;

// ── Client secrets ───────────────────────────────────────────────────────────────────────────
export function hashSecret(secret: string): string {
    const salt = randomBytes(16);
    return `scrypt$${salt.toString('base64url')}$${scryptSync(secret, salt, 32).toString('base64url')}`;
}
export function verifySecret(secret: string, stored: string): boolean {
    const [scheme, salt, hash] = stored.split('$');
    if (scheme !== 'scrypt' || !salt || !hash) return false;
    const want = Buffer.from(hash, 'base64url');
    const got = scryptSync(secret, Buffer.from(salt, 'base64url'), want.length);
    return want.length === got.length && timingSafeEqual(want, got);
}
export function newClientCredentials(): { key_id: string; secret: string } {
    return { key_id: `taxii_${randomBytes(9).toString('base64url')}`, secret: randomBytes(32).toString('base64url') };
}

interface TaxiiClient { id: string; name: string; key_id: string; collections: string[]; max_tlp: ExportCeiling }
type TaxiiRequest = Request & { taxiiClient?: TaxiiClient };

// Verified credentials are remembered briefly so scrypt does not run on every request.
const verified = new Map<string, { client: TaxiiClient; until: number }>();
export function clearTaxiiAuthCache(): void { verified.clear(); }

// The body goes out as a Buffer so Express leaves the media type exactly as the spec writes it
// (a string body would get "; charset=utf-8" inserted before the version parameter).
function write(res: Response, status: number, body: unknown) {
    res.status(status).setHeader('Content-Type', TAXII_MEDIA);
    res.end(Buffer.from(JSON.stringify(body), 'utf8'));
}
function taxiiError(res: Response, status: number, title: string, description?: string) {
    write(res, status, { title, ...(description ? { description } : {}), http_status: String(status) });
}
function send(res: Response, body: unknown, headers: Record<string, string> = {}) {
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    write(res, 200, body);
}

/** Accept must allow the TAXII 2.1 media type (or be absent / a wildcard). */
export function acceptsTaxii(accept: string | undefined): boolean {
    if (!accept || !accept.trim()) return true;
    return accept.split(',').some((part) => {
        const [type, ...params] = part.trim().toLowerCase().split(';').map((s) => s.trim());
        if (type === '*/*' || type === 'application/*') return true;
        if (type !== 'application/taxii+json') return false;
        const version = params.find((p) => p.startsWith('version='));
        return !version || version === 'version=2.1';
    });
}

async function authenticate(req: TaxiiRequest, res: Response, next: NextFunction) {
    const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(req.get('authorization') ?? '');
    const decoded = m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
    const sep = decoded.indexOf(':');
    const keyId = sep > 0 ? decoded.slice(0, sep) : '';
    const secret = sep > 0 ? decoded.slice(sep + 1) : '';
    const deny = () => { res.setHeader('WWW-Authenticate', 'Basic realm="NovrSOC TAXII", charset="UTF-8"'); taxiiError(res, 401, 'Authentication required', 'Use the client key id and secret issued for this TAXII client.'); };
    if (!keyId || !secret || keyId.length > 64 || secret.length > 256) { deny(); return; }
    const cacheKey = createHash('sha256').update(`${keyId}\0${secret}`).digest('hex');
    const hit = verified.get(cacheKey);
    if (hit && hit.until > Date.now()) { req.taxiiClient = hit.client; next(); return; }
    const supabase = getSupabase();
    if (!supabase) { taxiiError(res, 503, 'Service unavailable', 'The exchange is not configured.'); return; }
    const { data, error } = await supabase.from('ti_taxii_clients').select('id, name, key_id, secret_hash, collections, max_tlp, enabled, revoked_at').eq('key_id', keyId).maybeSingle();
    if (error) { taxiiError(res, 503, 'Service unavailable', /ti_taxii_clients/.test(error.message) ? 'The exchange is not set up yet.' : 'Try again later.'); return; }
    if (!data || !data.enabled || data.revoked_at || !verifySecret(secret, data.secret_hash as string)) {
        logAudit({ user: `taxii:${keyId.slice(0, 64)}`, action: 'TAXII_AUTH_FAILED', resource: 'taxii', ip: req.ip ?? 'unknown', result: 'failed', severity: 'warning' });
        deny();
        return;
    }
    const client: TaxiiClient = { id: data.id as string, name: data.name as string, key_id: keyId, collections: (data.collections as string[]) ?? [], max_tlp: isCeiling(data.max_tlp) ? data.max_tlp : 'clear' };
    verified.set(cacheKey, { client, until: Date.now() + 60_000 });
    void supabase.from('ti_taxii_clients').update({ last_used_at: new Date().toISOString() }).eq('id', client.id).then(() => undefined);
    req.taxiiClient = client;
    next();
}

const root = (req: Request) => `${req.protocol}://${req.get('host')}${req.baseUrl}`;
const collectionResource = (c: CollectionDef) => ({ id: c.id, title: c.title, description: c.description, alias: c.alias, can_read: true, can_write: false, media_types: [STIX_MEDIA] });
const visible = (req: TaxiiRequest) => COLLECTIONS.filter((c) => req.taxiiClient!.collections.includes(c.id));

function collectionOr404(req: TaxiiRequest, res: Response): CollectionDef | null {
    const c = collectionById(req.params.id);
    if (!c || !req.taxiiClient!.collections.includes(c.id)) { taxiiError(res, 404, 'Collection not found'); return null; }
    return c;
}

/** match[type]: the object types a collection holds. */
const CONTENT_TYPE: Record<CollectionDef['content'], string> = { indicators: 'indicator', vulnerabilities: 'vulnerability' };
const UUID_PART = /^(indicator|vulnerability)--([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

interface Parsed { addedAfter: string | null; limit: number; cursor: ReturnType<typeof decodeCursor>; uuids: string[] | null; version: string | null; empty: boolean }
/** The spec's filters, or a 400 already sent (null). `empty` = the filters exclude this collection's content. */
function parseFilters(req: Request, res: Response, c: CollectionDef, objectId?: string): Parsed | null {
    // Read the raw query: Express's parser would turn match[type]=x into a nested object.
    const q = new URLSearchParams(req.originalUrl.split('?')[1] ?? '');
    const one = (k: string) => q.get(k);
    const list = (k: string) => { const v = one(k); return v ? v.split(',').map((s) => s.trim()).filter(Boolean) : null; };
    let addedAfter: string | null = null;
    const aa = one('added_after');
    if (aa) {
        if (!Number.isFinite(Date.parse(aa))) { taxiiError(res, 400, 'Invalid added_after', 'added_after must be an RFC 3339 timestamp.'); return null; }
        addedAfter = new Date(aa).toISOString();
    }
    const rawLimit = one('limit');
    const limit = rawLimit === null ? DEFAULT_LIMIT : Number(rawLimit);
    if (!Number.isInteger(limit) || limit < 1) { taxiiError(res, 400, 'Invalid limit', 'limit must be a positive integer.'); return null; }
    const nextParam = one('next');
    const cursor = nextParam ? decodeCursor(nextParam) : null;
    if (nextParam && !cursor) { taxiiError(res, 400, 'Invalid next', 'next must be a value this server returned.'); return null; }
    let empty = false;
    const ids = objectId ? [objectId] : list('match[id]');
    let uuids: string[] | null = null;
    if (ids) {
        uuids = [];
        for (const id of ids) { const m = UUID_PART.exec(id); if (m && m[1].toLowerCase() === CONTENT_TYPE[c.content]) uuids.push(m[2].toLowerCase()); }
        if (!uuids.length) empty = true;
    }
    const types = list('match[type]');
    if (types && !types.includes(CONTENT_TYPE[c.content])) empty = true;
    const specs = list('match[spec_version]');
    if (specs && !specs.includes('2.1')) empty = true;
    let version: string | null = null;
    const versions = list('match[version]');
    if (versions && !versions.some((v) => v === 'last' || v === 'first' || v === 'all')) {
        const ts = versions.find((v) => Number.isFinite(Date.parse(v)));
        if (!ts) { taxiiError(res, 400, 'Invalid match[version]', 'Use last, first, all or an RFC 3339 timestamp.'); return null; }
        version = new Date(ts).toISOString();
    }
    return { addedAfter, limit: Math.min(limit, MAX_LIMIT), cursor, uuids, version, empty };
}

function dateHeaders(items: { date_added: string }[]): Record<string, string> {
    if (!items.length) return {};
    const ds = items.map((i) => i.date_added).sort();
    return { 'X-TAXII-Date-Added-First': ds[0], 'X-TAXII-Date-Added-Last': ds[ds.length - 1] };
}

const router = Router();
router.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false, handler: (_req, res) => taxiiError(res, 429, 'Too many requests', 'Slow down and retry.') }));
router.use((req, res, next) => {
    if (!acceptsTaxii(req.get('accept'))) { taxiiError(res, 406, 'Not acceptable', `This server returns ${TAXII_MEDIA}.`); return; }
    next();
});
router.use(authenticate);

router.get('/', (req, res) => {
    send(res, { title: 'NovrSOC TAXII 2.1', description: 'Read-only exchange of shared threat intelligence collected by NovrSOC.', default: `${root(req)}/api1/`, api_roots: [`${root(req)}/api1/`] });
});
router.get('/api1/', (_req, res) => {
    send(res, { title: 'NovrSOC threat intelligence', description: 'Collections of shared indicators and known exploited vulnerabilities.', versions: [TAXII_MEDIA], max_content_length: 10_485_760 });
});
router.get('/api1/status/:id/', (_req, res) => taxiiError(res, 404, 'Status not found', 'This server accepts no writes, so it has no status resources.'));
router.get('/api1/collections/', (req: TaxiiRequest, res) => {
    const cols = visible(req).map(collectionResource);
    send(res, cols.length ? { collections: cols } : {});
});
router.get('/api1/collections/:id/', (req: TaxiiRequest, res) => {
    const c = collectionOr404(req, res);
    if (c) send(res, collectionResource(c));
});

async function objects(req: TaxiiRequest, res: Response, mode: 'objects' | 'manifest' | 'object' | 'versions') {
    const c = collectionOr404(req, res);
    if (!c) return;
    const f = parseFilters(req, res, c, mode === 'object' || mode === 'versions' ? req.params.object_id : undefined);
    if (!f) return;
    if (f.empty) {
        if (mode === 'object' || mode === 'versions') { taxiiError(res, 404, 'Object not found'); return; }
        send(res, mode === 'manifest' ? { more: false } : { more: false });
        return;
    }
    try {
        const page = await exchangePage({ content: c.content, ceiling: req.taxiiClient!.max_tlp, addedAfter: f.addedAfter, cursor: f.cursor, limit: f.limit, stixUuids: f.uuids, version: f.version });
        if ((mode === 'object' || mode === 'versions') && !page.items.length) { taxiiError(res, 404, 'Object not found'); return; }
        const headers = dateHeaders(page.items);
        const paging = { more: page.more, ...(page.more && page.next ? { next: encodeCursor(page.next) } : {}) };
        if (mode === 'manifest') send(res, { ...paging, ...(page.items.length ? { objects: page.items.map((i) => ({ id: i.object.id, date_added: i.date_added, version: i.version, media_type: STIX_MEDIA })) } : {}) }, headers);
        else if (mode === 'versions') send(res, { ...paging, versions: page.items.map((i) => i.version) }, headers);
        else send(res, { ...paging, ...(page.items.length ? { objects: page.items.map((i) => i.object) } : {}) }, headers);
    } catch (err) {
        console.error('[taxii] page failed:', err instanceof Error ? err.message.slice(0, 200) : err);
        taxiiError(res, 503, 'Service unavailable', 'The collection could not be read. Try again later.');
    }
}
router.get('/api1/collections/:id/objects/', (req, res) => objects(req, res, 'objects'));
router.get('/api1/collections/:id/manifest/', (req, res) => objects(req, res, 'manifest'));
router.get('/api1/collections/:id/objects/:object_id/', (req, res) => objects(req, res, 'object'));
router.get('/api1/collections/:id/objects/:object_id/versions/', (req, res) => objects(req, res, 'versions'));
const readOnly = (_req: Request, res: Response) => taxiiError(res, 403, 'Collection is read-only', 'This server does not accept objects.');
router.post('/api1/collections/:id/objects/', readOnly);
router.delete('/api1/collections/:id/objects/:object_id/', readOnly);

export default router;
