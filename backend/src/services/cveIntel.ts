// CVE intelligence (phase P5): authoritative public sources only, cached in cve_intel.
//   CISA KEV  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   FIRST EPSS https://api.first.org/data/v1/epss?cve=…        (probability of exploitation)
//   NVD 2.0   https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…  (description, CVSS, CWE)
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

export interface IntelRunResult { tracked: number; kev_marked: number; epss_updated: number; nvd_updated: number; errors: string[] }

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
    return out;
}
