// Read-only MISP connectivity check with the backend's own MISP client (phase P26). Proves the
// configured MISP_URL — a Cloudflare Tunnel (named or Quick), a gateway, or MISP itself — works
// with this client: valid TLS without disabling checks, no redirects, JSON answers, the key
// accepted and read-only, and one page of the incremental attribute search.
//
//   cd backend && npm run misp:check            (uses MISP_URL / MISP_API_KEY / MISP_CA_CERT /
//                                                MISP_CF_ACCESS_CLIENT_ID / _SECRET from the env)
//
// Prints no key, token or header. Sends only GET /servers/getVersion, GET /users/view/me and
// POST restSearch (limit 1). Exit code 0 = compatible, 1 = not.
import 'dotenv/config';
import { getMISPCapabilities, isMISPConfigured, mispAttributeSearch, mispEventSearch } from '../services/misp';
import { parsePin } from '../lib/pinnedTls';

async function main() {
    const url = (process.env.MISP_URL ?? '').trim();
    let host = '(unset)';
    try { host = new URL(url.replace(/^http:\/\//, 'https://')).host; } catch { /* reported below */ }
    console.log(`MISP host: ${host}`);
    console.log(`Quick Tunnel: ${/\.trycloudflare\.com$/i.test(host) ? 'yes — its hostname changes whenever cloudflared restarts; update MISP_URL each time' : 'no'}`);
    console.log(`Pinned certificate (MISP_CA_CERT): ${parsePin(process.env.MISP_CA_CERT) ? 'SET' : 'not set'}`);
    console.log(`Cloudflare Access service token: ${process.env.MISP_CF_ACCESS_CLIENT_ID && process.env.MISP_CF_ACCESS_CLIENT_SECRET ? 'set' : 'not set'}`);
    if (!isMISPConfigured()) { console.log('FAIL: MISP_URL and MISP_API_KEY must be set'); process.exit(1); }
    if (parsePin(process.env.MISP_CA_CERT) && /trycloudflare\.com$|cloudflare/i.test(host)) {
        console.log('WARNING: a pinned certificate trusts only that certificate; a Cloudflare hostname presents Cloudflare\'s. Leave MISP_CA_CERT empty for a tunnel.');
    }
    let ok = true;
    const cap = await getMISPCapabilities();
    console.log(`Reachable: ${cap.reachable} · version: ${cap.version ?? 'unknown'} · key can write: ${cap.key_can_write === null ? 'unknown' : cap.key_can_write} · STIX 2 export: ${cap.stix2_export}`);
    for (const e of cap.errors) console.log(`  · ${e}`);
    if (!cap.reachable) ok = false;
    if (cap.key_can_write === true) { console.log('FAIL: the key can write — use a read-only key'); ok = false; }
    try {
        const since = String(Math.floor(Date.now() / 1000) - 86_400);
        const a = await mispAttributeSearch({ returnFormat: 'json', to_ids: true, timestamp: since, deleted: false, enforceWarninglist: true, includeEventTags: true, includeEventUuid: true, limit: 1, page: 1 });
        const n = ((a as { response?: { Attribute?: unknown[] } }).response?.Attribute ?? []).length;
        console.log(`Attribute search (last 24 h, 1 row): OK (${n} returned)`);
        const e = await mispEventSearch({ returnFormat: 'json', timestamp: since, metadata: true, limit: 1, page: 1 });
        console.log(`Event search (last 24 h, 1 row): OK (${((e as { response?: unknown[] }).response ?? []).length} returned)`);
    } catch (err) {
        console.log(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
        ok = false;
    }
    console.log(ok ? 'MISP CHECK: COMPATIBLE' : 'MISP CHECK: NOT COMPATIBLE');
    process.exit(ok ? 0 : 1);
}
void main();
