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
    '/category', '/tag/', '/author', '/feed',
];

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

    // Require at least one security word in the title or snippet. Without this the feed fills
    // with agency news — appointments, MoUs, digital-literacy programmes — which NITDA's site
    // carries far more of than it does advisories.
    const text = `${result.title} ${result.snippet}`.toLowerCase();
    const SECURITY_WORDS = [
        'advisory', 'alert', 'vulnerability', 'cve', 'ransomware', 'phishing', 'malware',
        'breach', 'exploit', 'threat', 'attack', 'patch', 'scam', 'fraud', 'ddos',
    ];
    return SECURITY_WORDS.some((w) => text.includes(w));
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
export async function collectNITDAAdvisories(): Promise<{ found: number; stored: number }> {
    const advisories = await fetchNITDAAdvisories();
    const stored = await storeNITDAAdvisories(advisories);
    return { found: advisories.length, stored };
}
