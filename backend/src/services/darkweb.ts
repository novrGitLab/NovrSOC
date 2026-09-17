// Dark web exposure checks against free, publicly available sources.
//
// WHAT ACTUALLY WORKS, verified live on 2026-09-17 — this matters, because two of the three
// sources commonly cited for this are dead:
//
//   Ransomwatch  WORKS, but NOT at ransomwatch.telemetry.ltd/v2/posts.json (404 — that host
//                serves an HTML error page). The maintained data is the posts.json in the
//                GitHub repo, which returns ~16,000 real victim posts across 157 groups.
//   Ahmia        NOT USABLE. https://ahmia.fi/search/?q=... 302-redirects to the site root and
//                returns no parseable results, so an HTML scraper against it silently yields
//                nothing — worse than not having it, because an always-empty source renders as
//                "no mentions found" and reads like an all-clear.
//   psbdmp.ws    NOT USABLE. The host does not resolve/connect at all (curl exit 000).
//
// Only Ransomwatch is implemented. The route reports exactly which sources were consulted so the
// UI can never imply broader coverage than this actually provides.

const RANSOMWATCH_URL = 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json';

export interface DarkWebFinding {
    source: string;
    group: string | null;
    title: string;
    date: string | null;
    url: string | null;
    type: 'ransomware_listing';
    severity: 'critical';
    /** Which search term matched, so an analyst can tell a company-name hit from a domain hit. */
    matched_query: string;
}

interface RansomwatchPost {
    post_title?: string;
    group_name?: string;
    discovered?: string;
}

// Cached in-process: the file is ~2.3MB and the underlying data changes at most daily, so
// re-downloading it per query (the route runs several) would be wasteful and slow.
let cache: { posts: RansomwatchPost[]; fetchedAt: number } | null = null;
const CACHE_TTL_MS = 60 * 60 * 1000;

export interface RansomwatchMeta {
    ok: boolean;
    total_posts: number;
    /** Newest `discovered` value in the dataset — the feed has stalled before, and a stale
     *  dataset must be visible rather than presented as current coverage. */
    latest_post: string | null;
}

async function loadRansomwatch(): Promise<RansomwatchPost[] | null> {
    if (cache && Date.now() - cache.fetchedAt < CACHE_TTL_MS) return cache.posts;
    try {
        const res = await fetch(RANSOMWATCH_URL, { signal: AbortSignal.timeout(20000) });
        if (!res.ok) return null;
        const data = await res.json();
        if (!Array.isArray(data)) return null;
        cache = { posts: data as RansomwatchPost[], fetchedAt: Date.now() };
        return cache.posts;
    } catch {
        return null;
    }
}

/**
 * Searches ransomware leak-site victim listings for a term.
 *
 * Only `post_title` is searched because it is the only searchable field the dataset carries —
 * each record is {post_title, group_name, discovered}. There is no description and no post URL,
 * so findings carry a null url rather than a fabricated link to the leak site.
 */
export async function checkRansomwatch(query: string): Promise<{ findings: DarkWebFinding[]; meta: RansomwatchMeta }> {
    const term = query.trim().toLowerCase();
    const posts = await loadRansomwatch();

    if (!posts) return { findings: [], meta: { ok: false, total_posts: 0, latest_post: null } };

    const latest = posts.reduce<string | null>((max, p) => {
        const d = p.discovered ?? '';
        return d && (!max || d > max) ? d : max;
    }, null);

    const meta: RansomwatchMeta = { ok: true, total_posts: posts.length, latest_post: latest };
    // A term under 4 characters would match thousands of unrelated victim names — refused
    // rather than returned as a wall of false positives.
    if (term.length < 4) return { findings: [], meta };

    const findings = posts
        .filter((p) => (p.post_title ?? '').toLowerCase().includes(term))
        .slice(0, 50)
        .map((p): DarkWebFinding => ({
            source: 'Ransomwatch',
            group: p.group_name ?? null,
            title: p.post_title ?? 'Untitled listing',
            date: p.discovered ?? null,
            url: null,
            type: 'ransomware_listing',
            severity: 'critical',
            matched_query: query,
        }));

    return { findings, meta };
}

export interface DarkWebSearchResult {
    findings: DarkWebFinding[];
    sources: Array<{ name: string; ok: boolean; detail: string }>;
}

/** Runs every implemented dark web check across the supplied search terms. */
export async function darkWebSearch(terms: string[]): Promise<DarkWebSearchResult> {
    const queries = terms.map((t) => t.trim()).filter((t) => t.length >= 4);
    const findings: DarkWebFinding[] = [];
    let meta: RansomwatchMeta = { ok: false, total_posts: 0, latest_post: null };

    for (const q of queries) {
        const result = await checkRansomwatch(q);
        meta = result.meta;
        findings.push(...result.findings);
    }

    // The same victim can be listed by several groups; dedupe on group+title so one victim
    // posted twice doesn't read as two separate breaches.
    const seen = new Set<string>();
    const unique = findings.filter((f) => {
        const key = `${f.group}::${f.title}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    return {
        findings: unique,
        sources: [
            {
                name: 'Ransomwatch',
                ok: meta.ok,
                detail: meta.ok
                    ? `${meta.total_posts.toLocaleString()} victim listings indexed${meta.latest_post ? `, most recent ${meta.latest_post.slice(0, 10)}` : ''}`
                    : 'Could not reach the Ransomwatch dataset',
            },
            {
                name: 'Ahmia (Tor search)',
                ok: false,
                detail: 'Not implemented — ahmia.fi redirects search requests to its homepage and returns no parseable results.',
            },
            {
                name: 'Paste sites',
                ok: false,
                detail: 'Not implemented — psbdmp.ws is unreachable (no connection).',
            },
        ],
    };
}
