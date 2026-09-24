// NITDA advisory collection.
//
// NITDA (National Information Technology Development Agency) runs Nigeria's CERRT — Computer
// Emergency Readiness and Response Team — at cerrt.nitda.gov.ng. Neither publishes a machine
// readable feed, so advisories are discovered through search (services/serper.ts) rather than
// fetched from an API.
//
// THREE THINGS THIS DELIBERATELY DOES NOT DO, each verified live on 2026-09-17:
//
//  1. It does NOT write to `nigeria_intel.advisories`. That schema does not exist on this
//     project — the real table is public.nigeria_advisories (same finding recorded in
//     nigeriaDemoSeed.ts). Writing to the former fails on every row.
//  2. It does NOT set an `affected_sector` column. nigeria_advisories has no such column; the
//     frontend's sector filter reads the `tags` array, so sector ships as a `sector:banking`
//     style tag, matching the existing convention.
//  3. It does NOT key rows on `NITDA-SEARCH-${Date.now()}`. A timestamped id changes on every
//     run, so upserting on advisory_id would never match an existing row and the table would
//     gain a fresh duplicate of the same article on every job tick. Ids are derived from the
//     URL instead, so re-finding an article updates it in place.
//
// Search results are mostly navigation pages — the CERRT homepage, /contact/, /kids-advisory/ —
// rather than discrete advisories. Those are filtered out below: an advisory feed listing
// "Contact — Computer Emergency Readiness and Response Team" as a security advisory is worse
// than an empty feed.

import { createHash } from 'crypto';
import { searchWeb, isConfigured as serperConfigured, type SearchResult } from './serper';
import { getSupabase } from './geoEnrichment';

export interface NITDAAdvisory {
    advisory_id: string;
    source: string;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    threat_type: string;
    tags: string[];
    source_url: string;
    published_at: string;
    org_id: string;
}

const QUERIES = [
    'site:cerrt.nitda.gov.ng advisory',
    'site:nitda.gov.ng cybersecurity advisory',
    'NITDA CERRT Nigeria cybersecurity advisory alert',
];

const NITDA_HOSTS = ['nitda.gov.ng', 'cerrt.nitda.gov.ng'];

// Pages that are navigation, not advisories. Matched on the URL path so a genuine advisory that
// merely mentions "contact" in its title is not dropped.
const NON_ADVISORY_PATHS = [
    '/contact', '/about', '/team', '/kids-advisory', '/privacy', '/rfc',
    '/category', '/tag/', '/author', '/feed', '/report-incidence', '/report-incident',
    '/home', '/login', '/register', '/search', '/sitemap', '/terms', '/cookie', '/faq',
];

// Page TITLES that are site furniture, not advisories. The URL list above missed CERRT's
// "Report Incidence" form page, which then passed the keyword check because its snippet says
// "threats" — so titles are checked too.
//
// Whole words only. Plain substring matching (as first specified) drops real advisories:
// "tag" is inside "outage", "search" inside "research", "home" inside "homeland",
// "error" inside "terrorism".
const NAV_TITLE_WORDS = [
    'contact', 'contact us', 'about', 'about us', 'home', 'homepage', 'menu', 'navigation',
    'report incidence', 'report an incident', 'report incident', 'sitemap', 'privacy',
    'privacy policy', 'terms', 'terms of use', 'login', 'log in', 'sign in', 'register',
    'search', 'tag', 'tags', 'category', 'categories', '404', 'page not found', 'error',
    'cookie', 'cookies', 'cookie policy', 'faq', 'faqs',
];
const NAV_TITLE_RE = new RegExp(`\\b(${NAV_TITLE_WORDS.map((w) => w.replace(/ /g, '\\s+')).join('|')})\\b`, 'i');

// Title minus a "[PDF] " prefix and the site-name suffix
// ("Report Incidence – CERRT" -> "Report Incidence").
function pageTitle(title: string): string {
    return title.replace(/^\s*\[[a-z]+\]\s*/i, '').split(/\s[|\u2013\u2014-]\s/)[0].trim();
}

// Listing pages: the advisories index itself, not an advisory.
const INDEX_TITLE_RE = /^(general |security |all |latest |recent )?(advisories|alerts|news|publications|resources|downloads)$/i;

// The TITLE must name a security issue. Checking the snippet as well (as first specified) lets
// through almost every page on a CERT's site, because their snippets all mention threats — the
// live table held a charter, an RFC 2350 description, a cloud-computing guideline and a
// trustmark press release that way. "vuln" is a prefix on purpose: NITDA's own advisory titles
// include the misspelling "Vulnurability".
const TITLE_SECURITY_RE = /\b(advisory|alert|warning|vuln\w*|cve-\d{4}-\d+|ransomware|phishing|malware|breach|exploit\w*|threat|attack|patch|security update|critical update|scam|fraud|ddos|zero-day|0-day|compromise\w*|botnet|trojan|spyware|backdoor|data leak)\b/i;

/** True when a search result's title reads as an actual advisory rather than a site page. */
export function isAdvisoryTitle(title: string): boolean {
    const t = pageTitle(title);
    if (!t || isNavigationTitle(title) || INDEX_TITLE_RE.test(t)) return false;
    return TITLE_SECURITY_RE.test(t);
}

/**
 * True when a page title is site navigation. A title counts as navigation when it is short
 * (≤ 5 words once the site name is stripped) AND contains a navigation word — so
 * "Contact Us" and "Report Incidence" are dropped, while "Advisory on phishing campaigns
 * targeting login pages" is kept.
 */
export function isNavigationTitle(title: string): boolean {
    const t = pageTitle(title);
    if (!t) return true;
    return t.split(/\s+/).length <= 5 && NAV_TITLE_RE.test(t);
}

function isAdvisoryLike(result: SearchResult): boolean {
    let url: URL;
    try {
        url = new URL(result.url);
    } catch {
        return false;
    }

    if (!NITDA_HOSTS.some((h) => url.hostname === h || url.hostname.endsWith(`.${h}`))) return false;

    // A bare host with no path is a homepage, never an advisory.
    const path = url.pathname.replace(/\/+$/, '');
    if (path === '' || path === '/') return false;
    if (NON_ADVISORY_PATHS.some((p) => path.toLowerCase().startsWith(p))) return false;
    // Title must itself name a security issue (see isAdvisoryTitle). "cyber" never counts:
    // every page on a cybersecurity agency's site says it.
    return isAdvisoryTitle(result.title);
}

// Stable per-URL id. A hash rather than the raw URL so the value is a predictable length and
// safe as a primary key regardless of query strings or unicode in the path.
function advisoryIdFor(url: string): string {
    return `NITDA-${createHash('sha1').update(url).digest('hex').slice(0, 12)}`;
}

// Keyword classification over a search snippet, which is a weak signal — the snippet is a
// fragment Google chose, not the advisory text. Defaults to 'medium' rather than guessing high,
// and 'critical' requires an explicit word: over-reporting severity on an advisory feed trains
// analysts to ignore it.
function detectSeverity(text: string): NITDAAdvisory['severity'] {
    const t = text.toLowerCase();
    if (t.includes('critical') || t.includes('emergency') || t.includes('zero-day') || t.includes('zero day')) return 'critical';
    if (t.includes('urgent') || t.includes('severe') || t.includes('high severity')) return 'high';
    if (t.includes('low severity') || t.includes('informational')) return 'low';
    return 'medium';
}

function detectThreatType(text: string): string {
    const t = text.toLowerCase();
    if (t.includes('ransomware')) return 'ransomware';
    if (t.includes('phishing') || t.includes('scam')) return 'phishing';
    if (t.includes('ddos')) return 'ddos';
    if (t.includes('breach') || t.includes('leak')) return 'data-breach';
    if (t.includes('vulnerability') || t.includes('cve') || t.includes('patch')) return 'vulnerability';
    if (t.includes('malware') || t.includes('trojan')) return 'malware';
    return 'advisory';
}

// Sector ships as a tag, since nigeria_advisories has no sector column and the UI filters on tags.
function detectSectorTag(text: string): string | null {
    const t = text.toLowerCase();
    if (t.includes('bank') || t.includes('financial') || t.includes('fintech')) return 'sector:banking';
    if (t.includes('telecom') || t.includes('mobile network') || t.includes('ncc')) return 'sector:telecom';
    if (t.includes('government') || t.includes('federal') || t.includes('ministry') || t.includes('public sector')) return 'sector:government';
    if (t.includes('health') || t.includes('hospital')) return 'sector:healthcare';
    if (t.includes('energy') || t.includes('oil') || t.includes('nnpc') || t.includes('power')) return 'sector:energy';
    return null;
}

function buildTags(text: string, threatType: string): string[] {
    const tags = new Set<string>(['nigeria', 'nitda', threatType]);
    const sector = detectSectorTag(text);
    if (sector) tags.add(sector);
    return [...tags];
}

/** Searches for NITDA/CERRT advisories. Returns [] when Serper isn't configured. */
export async function fetchNITDAAdvisories(): Promise<NITDAAdvisory[]> {
    if (!serperConfigured()) return [];

    const byId = new Map<string, NITDAAdvisory>();

    for (const query of QUERIES) {
        let response;
        try {
            response = await searchWeb(query);
        } catch (err) {
            console.warn('[NITDA] search failed for', query, err instanceof Error ? err.message : err);
            continue;
        }
        if (!response) continue;

        for (const result of response.results) {
            if (!isAdvisoryLike(result)) continue;

            const text = `${result.title} ${result.snippet}`;
            const threatType = detectThreatType(text);
            const id = advisoryIdFor(result.url);

            // Deduped across queries — the same advisory surfaces in more than one of them.
            if (byId.has(id)) continue;

            byId.set(id, {
                advisory_id: id,
                source: 'NITDA',
                title: result.title,
                description: result.snippet || result.title,
                severity: detectSeverity(text),
                threat_type: threatType,
                tags: buildTags(text, threatType),
                source_url: result.url,
                // Serper only sometimes returns a date, and it's the page date rather than a
                // publication timestamp. Discovery time is used when it's absent — never a
                // fabricated publication date.
                published_at: result.date ? new Date(result.date).toISOString() : new Date().toISOString(),
                org_id: 'global',
            });
        }
    }

    return [...byId.values()];
}

/** Upserts advisories into public.nigeria_advisories. Returns how many were written. */
export async function storeNITDAAdvisories(advisories: NITDAAdvisory[]): Promise<number> {
    if (advisories.length === 0) return 0;

    const supabase = getSupabase();
    if (!supabase) {
        console.warn('[NITDA] Supabase not configured — advisories not stored');
        return 0;
    }

    // One upsert for the whole batch, not a loop of single writes: the spec's per-row loop is
    // N round trips and cannot report a partial failure usefully.
    const { error } = await supabase
        .from('nigeria_advisories')
        .upsert(advisories, { onConflict: 'advisory_id' });

    if (error) {
        console.error('[NITDA] Store failed:', error.message);
        return 0;
    }
    return advisories.length;
}

/** Fetch + store in one call, for the scheduled job. */
export async function collectNITDAAdvisories(): Promise<{ found: number; stored: number; pruned: number }> {
    const advisories = await fetchNITDAAdvisories();
    const stored = await storeNITDAAdvisories(advisories);
    const pruned = await pruneNavigationPages();
    return { found: advisories.length, stored, pruned };
}

/**
 * Removes NITDA rows saved under the older, looser filter that the current one rejects (the
 * "Report Incidence" form page, index pages, charters, press releases). Scoped to
 * source = 'NITDA' and to titles isAdvisoryTitle() rejects — nothing else is touched.
 */
export async function pruneNavigationPages(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    const { data, error } = await supabase.from('nigeria_advisories').select('advisory_id, title').eq('source', 'NITDA');
    if (error || !data) return 0;
    const stale = data.filter((r) => !isAdvisoryTitle(r.title ?? '')).map((r) => r.advisory_id);
    if (stale.length === 0) return 0;
    const { error: delErr } = await supabase.from('nigeria_advisories').delete().eq('source', 'NITDA').in('advisory_id', stale);
    if (delErr) {
        console.error('[NITDA] prune failed:', delErr.message);
        return 0;
    }
    console.log(`[NITDA] pruned ${stale.length} non-advisory page(s): ${data.filter((r) => stale.includes(r.advisory_id)).map((r) => r.title).join('; ')}`);
    return stale.length;
}
