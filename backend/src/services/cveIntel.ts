// CVE intelligence (phase P5): authoritative public sources only, cached in cve_intel.
//   CISA KEV  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   FIRST EPSS https://api.first.org/data/v1/epss?cve=…        (probability of exploitation)
//   NVD 2.0   https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…  (description, CVSS, CWE)
//   OSV       https://api.osv.dev/v1/vulns/<CVE id>   (P16: related advisory ids, fixed versions per
//             package). Needs sql/2026-10-22_p16_osv.sql; without it the step is skipped and says so.
//             Informational only: it never changes risk, priority or status.
// A value a source didn't give stays null ("unknown"); nothing is inferred. NVD is rate limited
// (5 requests / 30 s without NVD_API_KEY, 50 with), so lookups are paced and capped per run.
// Only CVEs that appear in findings are tracked.

import { getSupabase } from './geoEnrichment';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_URL = 'https://api.first.org/data/v1/epss';
export const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

const TIMEOUT = 30_000;
const isCve = (v: unknown): v is string => typeof v === 'string' && CVE_RE.test(v);
const num = (v: unknown): number | null => { const n = typeof v === 'string' ? Number(v) : typeof v === 'number' ? v : NaN; return Number.isFinite(n) ? n : null; };
const day = (v: unknown): string | null => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v) ? v.slice(0, 10) : null);

export interface KevEntry { date_added: string | null; due_date: string | null; required_action: string | null; ransomware: string | null }
export function parseKev(json: unknown): Map<string, KevEntry> {
    const out = new Map<string, KevEntry>();
    const items = (json as { vulnerabilities?: unknown[] })?.vulnerabilities;
    if (!Array.isArray(items)) throw new Error('KEV feed: unexpected format');
    for (const v of items as Record<string, unknown>[]) {
        if (!isCve(v.cveID)) continue;
        out.set(v.cveID, {
            date_added: day(v.dateAdded), due_date: day(v.dueDate),
            required_action: typeof v.requiredAction === 'string' ? v.requiredAction.slice(0, 1000) : null,
            ransomware: typeof v.knownRansomwareCampaignUse === 'string' ? v.knownRansomwareCampaignUse.slice(0, 40) : null,
        });
    }
    return out;
}

export function parseEpss(json: unknown): Map<string, { epss: number; percentile: number | null; date: string | null }> {
    const out = new Map<string, { epss: number; percentile: number | null; date: string | null }>();
    const rows = (json as { data?: unknown[] })?.data;
    if (!Array.isArray(rows)) throw new Error('EPSS: unexpected format');
    for (const r of rows as Record<string, unknown>[]) {
        const epss = num(r.epss);
        if (!isCve(r.cve) || epss === null || epss < 0 || epss > 1) continue;
        const pct = num(r.percentile);
        out.set(r.cve, { epss, percentile: pct !== null && pct >= 0 && pct <= 1 ? pct : null, date: day(r.date) });
    }
    return out;
}

export interface NvdFields { description: string | null; cvss_score: number | null; cvss_vector: string | null; cvss_version: string | null; cwe_ids: string[]; published_at: string | null; nvd_last_modified: string | null; references_urls: string[] }
/** The CVE's English description, the highest-precedence CVSS (v3.1, v3.0, then v2; primary source first), CWEs and references. */
export function parseNvd(json: unknown, cveId: string): NvdFields | null {
    const vulns = (json as { vulnerabilities?: { cve?: Record<string, unknown> }[] })?.vulnerabilities;
    const cve = Array.isArray(vulns) ? vulns.map((v) => v.cve).find((c) => c?.id === cveId) : undefined;
    if (!cve) return null;
    const desc = (cve.descriptions as { lang?: string; value?: string }[] | undefined)?.find((d) => d.lang === 'en')?.value ?? null;
    const metrics = (cve.metrics ?? {}) as Record<string, { type?: string; cvssData?: { baseScore?: unknown; vectorString?: string; version?: string } }[]>;
    let cvss: { score: number | null; vector: string | null; version: string | null } = { score: null, vector: null, version: null };
    for (const key of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
        const list = metrics[key];
        if (!Array.isArray(list) || !list.length) continue;
        const m = list.find((x) => x.type === 'Primary') ?? list[0];
        const score = num(m.cvssData?.baseScore);
        if (score !== null && score >= 0 && score <= 10) { cvss = { score, vector: m.cvssData?.vectorString?.slice(0, 200) ?? null, version: m.cvssData?.version ?? null }; break; }
    }
    const cwes = ((cve.weaknesses as { description?: { value?: string }[] }[] | undefined) ?? [])
        .flatMap((w) => w.description ?? []).map((d) => d.value ?? '').filter((v) => /^CWE-\d+$/.test(v));
    const refs = ((cve.references as { url?: string }[] | undefined) ?? []).map((r) => r.url ?? '').filter((u) => /^https?:\/\//.test(u)).slice(0, 25);
    return {
        description: desc?.slice(0, 4000) ?? null, cvss_score: cvss.score, cvss_vector: cvss.vector, cvss_version: cvss.version,
        cwe_ids: [...new Set(cwes)], published_at: typeof cve.published === 'string' ? cve.published : null,
        nvd_last_modified: typeof cve.lastModified === 'string' ? cve.lastModified : null, references_urls: refs,
    };
}

async function getJson(url: string, headers: Record<string, string> = {}): Promise<unknown> {
    const r = await fetch(url, { headers: { Accept: 'application/json', ...headers }, signal: AbortSignal.timeout(TIMEOUT) });
    if (!r.ok) throw new Error(`${new URL(url).host}: HTTP ${r.status}`);
    return r.json();
}

/** Makes sure each CVE has a cve_intel row (values stay null until a source fills them). */
export async function ensureCves(ids: string[]): Promise<void> {
    const cves = [...new Set(ids.filter(isCve))];
    if (!cves.length) return;
    const supabase = getSupabase();
    if (!supabase) return;
    const { error } = await supabase.from('cve_intel').upsert(cves.map((cve_id) => ({ cve_id })), { onConflict: 'cve_id', ignoreDuplicates: true });
    if (error) throw new Error(`cve_intel upsert failed: ${error.message}`);
}

export interface IntelRunResult { tracked: number; kev_marked: number; epss_updated: number; nvd_updated: number; errors: string[]; osv?: OsvRunResult }

// ── OSV (P16) ──────────────────────────────────────────────────────────────────────────────────
export const OSV_URL = 'https://api.osv.dev/v1/vulns';
const OSV_TIMEOUT = 15_000;
const OSV_REFRESH_DAYS = 7;
export interface OsvAffected { ecosystem: string | null; name: string | null; repo: string | null; fixed: string[]; last_affected: string[] }
export interface OsvRunResult { state: 'done' | 'not_set_up' | 'rate_limited' | 'failed'; looked_up: number; found: number; not_found: number; errors: string[] }
const str = (v: unknown, max = 200) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);

/** The fields kept from an OSV record (osv.dev schema): ids naming the same issue, a summary, fixes per package. */
export function parseOsv(json: unknown): { ids: string[]; summary: string | null; affected: OsvAffected[] } | null {
    const j = json as { id?: unknown; aliases?: unknown; related?: unknown; summary?: unknown; details?: unknown; affected?: unknown } | null;
    const id = str(j?.id, 100);
    if (!id) return null;
    const list = (v: unknown) => (Array.isArray(v) ? v.map((x) => str(x, 100)).filter((x): x is string => !!x) : []);
    const ids = [...new Set([id, ...list(j?.aliases), ...list(j?.related)])].slice(0, 50);
    const affected: OsvAffected[] = [];
    for (const a of Array.isArray(j?.affected) ? j!.affected as Record<string, unknown>[] : []) {
        const pkg = (a?.package ?? {}) as { ecosystem?: unknown; name?: unknown };
        const ranges = Array.isArray(a?.ranges) ? a.ranges as { repo?: unknown; events?: unknown }[] : [];
        const events = ranges.flatMap((r) => (Array.isArray(r?.events) ? r.events as Record<string, unknown>[] : []));
        const entry: OsvAffected = {
            ecosystem: str(pkg.ecosystem, 80), name: str(pkg.name, 200), repo: str(ranges.find((r) => str(r?.repo))?.repo, 300),
            fixed: [...new Set(events.map((e) => str(e?.fixed, 100)).filter((x): x is string => !!x))].slice(0, 20),
            last_affected: [...new Set(events.map((e) => str(e?.last_affected, 100)).filter((x): x is string => !!x))].slice(0, 20),
        };
        if (entry.name || entry.repo) affected.push(entry);
        if (affected.length >= 50) break;
    }
    return { ids, summary: str(j?.summary, 1000) ?? str(j?.details, 1000), affected };
}

const isMissingColumn = (e: { code?: string; message?: string } | null) => !!e && (e.code === '42703' || e.code === 'PGRST204' || /osv_/.test(e.message ?? '') && /does not exist|Could not find/i.test(e.message ?? ''));

/**
 * Looks up to `limit` tracked CVEs in OSV: never looked up first, then the oldest past the refresh
 * interval. One request at a time with a pause; HTTP 429 stops the run (retried next run); any other
 * failure is recorded and the CVE is retried next run — a failed lookup is never stored as "none".
 */
export async function refreshOsv(opts: { limit?: number; fetchImpl?: typeof fetch; sleep?: (ms: number) => Promise<void>; now?: Date } = {}): Promise<OsvRunResult> {
    const out: OsvRunResult = { state: 'done', looked_up: 0, found: 0, not_found: 0, errors: [] };
    const supabase = getSupabase();
    if (!supabase) return { ...out, state: 'failed', errors: ['database not configured'] };
    const doFetch = opts.fetchImpl ?? fetch;
    const sleep = opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
    const now = opts.now ?? new Date();
    const staleBefore = new Date(now.getTime() - OSV_REFRESH_DAYS * 86_400_000).toISOString();
    const { data, error } = await supabase.from('cve_intel').select('cve_id, osv_fetched_at').or(`osv_fetched_at.is.null,osv_fetched_at.lt.${staleBefore}`)
        .order('osv_fetched_at', { ascending: true, nullsFirst: true }).limit(opts.limit ?? 50);
    if (error) return isMissingColumn(error) ? { ...out, state: 'not_set_up', errors: ['OSV is not set up (run sql/2026-10-22_p16_osv.sql)'] } : { ...out, state: 'failed', errors: [`cve_intel read: ${error.message}`] };
    for (const [i, row] of ((data ?? []) as { cve_id: string }[]).filter((r) => isCve(r.cve_id)).entries()) {
        if (i) await sleep(250);
        out.looked_up++;
        try {
            const r = await doFetch(`${OSV_URL}/${encodeURIComponent(row.cve_id)}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(OSV_TIMEOUT) });
            if (r.status === 429) { out.state = 'rate_limited'; out.errors.push('OSV: HTTP 429, stopped for this run'); break; }
            if (r.status === 404) {
                await supabase.from('cve_intel').update({ osv_ids: [], osv_summary: null, osv_affected: [], osv_status: 'not_found', osv_fetched_at: now.toISOString() }).eq('cve_id', row.cve_id);
                out.not_found++; continue;
            }
            if (!r.ok) { out.errors.push(`OSV ${row.cve_id}: HTTP ${r.status}`); continue; }
            const parsed = parseOsv(await r.json());
            if (!parsed) { out.errors.push(`OSV ${row.cve_id}: unreadable record`); continue; }
            const { error: uErr } = await supabase.from('cve_intel').update({ osv_ids: parsed.ids, osv_summary: parsed.summary, osv_affected: parsed.affected, osv_status: 'found', osv_fetched_at: now.toISOString() }).eq('cve_id', row.cve_id);
            if (uErr) { out.errors.push(`OSV ${row.cve_id}: not stored (${uErr.message})`); continue; }
            out.found++;
        } catch (err) {
            out.errors.push(`OSV ${row.cve_id}: ${err instanceof Error ? (err.name === 'TimeoutError' ? `no answer within ${OSV_TIMEOUT / 1000} s` : err.message) : String(err)}`.slice(0, 200));
        }
    }
    if (out.errors.length && out.state === 'done' && out.found + out.not_found === 0) out.state = 'failed';
    return out;
}

/** One refresh: KEV flags for every tracked CVE, EPSS for every tracked CVE, NVD for up to nvdLimit missing ones. */
export async function refreshCveIntel(opts: { nvdLimit?: number; sleep?: (ms: number) => Promise<void> } = {}): Promise<IntelRunResult> {
    const supabase = getSupabase();
    const out: IntelRunResult = { tracked: 0, kev_marked: 0, epss_updated: 0, nvd_updated: 0, errors: [] };
    if (!supabase) { out.errors.push('database not configured'); return out; }
    const sleep = opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
    const { data: rows, error } = await supabase.from('cve_intel').select('cve_id, nvd_fetched_at').limit(20_000);
    if (error) { out.errors.push(error.message); return out; }
    const tracked = (rows ?? []).map((r) => r.cve_id as string).filter(isCve);
    out.tracked = tracked.length;
    if (!tracked.length) return out;
    const now = new Date().toISOString();

    try {
        const kev = parseKev(await getJson(KEV_URL));
        for (let i = 0; i < tracked.length; i += 200) {
            const chunk = tracked.slice(i, i + 200);
            await Promise.all(chunk.map(async (id) => {
                const k = kev.get(id);
                const upd = k
                    ? { kev: true, kev_date_added: k.date_added, kev_due_date: k.due_date, kev_required_action: k.required_action, kev_ransomware: k.ransomware, kev_checked_at: now }
                    : { kev: false, kev_date_added: null, kev_due_date: null, kev_required_action: null, kev_ransomware: null, kev_checked_at: now };
                await supabase.from('cve_intel').update(upd).eq('cve_id', id);
                if (k) out.kev_marked++;
            }));
        }
    } catch (err) { out.errors.push(`KEV: ${err instanceof Error ? err.message : err}`); }

    try {
        for (let i = 0; i < tracked.length; i += 100) {
            const chunk = tracked.slice(i, i + 100);
            const epss = parseEpss(await getJson(`${EPSS_URL}?cve=${chunk.join(',')}`));
            for (const [id, e] of epss) {
                await supabase.from('cve_intel').update({ epss_score: e.epss, epss_percentile: e.percentile, epss_date: e.date, epss_fetched_at: now }).eq('cve_id', id);
                out.epss_updated++;
            }
        }
    } catch (err) { out.errors.push(`EPSS: ${err instanceof Error ? err.message : err}`); }

    const key = process.env.NVD_API_KEY?.trim();
    const pause = key ? 700 : 6_500;
    const missing = (rows ?? []).filter((r) => !r.nvd_fetched_at).map((r) => r.cve_id as string).filter(isCve).slice(0, opts.nvdLimit ?? 40);
    for (const [i, id] of missing.entries()) {
        try {
            if (i) await sleep(pause);
            const fields = parseNvd(await getJson(`${NVD_URL}?cveId=${id}`, key ? { apiKey: key } : {}), id);
            await supabase.from('cve_intel').update({ ...(fields ?? {}), nvd_fetched_at: now }).eq('cve_id', id);
            if (fields) out.nvd_updated++;
        } catch (err) { out.errors.push(`NVD ${id}: ${err instanceof Error ? err.message : err}`); }
    }

    // OSV last and isolated: whatever happens there, KEV, EPSS and NVD above are already stored.
    try { out.osv = await refreshOsv({ sleep }); } catch (err) { out.osv = { state: 'failed', looked_up: 0, found: 0, not_found: 0, errors: [err instanceof Error ? err.message : String(err)] }; }
    return out;
}
