// Reusable URL intelligence — used by Messaging Suite (links in email), Phish ID (discovered
// sites) and anything else in the SOC that has a URL to judge. One implementation, so the same
// URL gets the same answer wherever it appears.
//
// Every source is reported individually with whether it was actually consulted: a feed that is
// not configured says "not configured", it never counts as a clean result.
import { domainToASCII } from 'url';
import { urlhausLookupURL, urlhausLookupHost } from '../urlhaus';
import { checkPhishSources } from '../phishCheck';
import { vtCheckURL, isConfigured as vtConfigured } from '../virustotal';
import { lookupDomain } from '../rdap';
import { registrableDomain } from './similarity';
import { safeGet, BlockedTargetError, type Hop, type TlsInfo } from './safeFetch';

export interface NormalizedUrl { url: string; host: string; domain: string; scheme: string; path: string }

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in', 's.id']);
const ABUSED_TLDS = new Set(['zip', 'mov', 'xyz', 'top', 'click', 'link', 'work', 'support', 'rest', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'cyou', 'icu', 'buzz']);

/** Canonical form of a URL (defanged forms like hxxp / [.] accepted). Null if unparseable. */
export function normalizeUrl(input: string): NormalizedUrl | null {
    let s = input.trim().replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':');
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `http://${s}`;
    let u: URL;
    try { u = new URL(s); } catch { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = domainToASCII(u.hostname.replace(/\.$/, '').toLowerCase()) || u.hostname.toLowerCase();
    if (!host) return null;
    u.hostname = host;
    u.hash = '';
    if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) u.port = '';
    const ipHost = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':');
    return { url: u.toString(), host, domain: ipHost ? host : registrableDomain(host), scheme: u.protocol.slice(0, -1), path: u.pathname };
}

export interface Signal { id: string; label: string; detail: string; weight: number }

/** Signals from the URL text alone — no network. */
export function structureSignals(n: NormalizedUrl, raw: string): Signal[] {
    const s: Signal[] = [];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(n.host)) s.push({ id: 'ip_host', label: 'IP address instead of a domain', detail: n.host, weight: 20 });
    if (raw.includes('@') && /^[a-z]+:\/\/[^/]*@/i.test(raw)) s.push({ id: 'userinfo', label: 'Text before "@" disguises the real host', detail: n.host, weight: 25 });
    if (n.host.startsWith('xn--') || n.host.includes('.xn--')) s.push({ id: 'punycode', label: 'Internationalised (punycode) hostname', detail: n.host, weight: 15 });
    if (n.host.split('.').length > 5) s.push({ id: 'deep_subdomains', label: 'Unusually many subdomain levels', detail: n.host, weight: 10 });
    if (raw.length > 200) s.push({ id: 'long_url', label: 'Very long URL', detail: `${raw.length} characters`, weight: 5 });
    if (SHORTENERS.has(n.host)) s.push({ id: 'shortener', label: 'URL shortener hides the destination', detail: n.host, weight: 10 });
    const tld = n.host.split('.').pop() ?? '';
    if (ABUSED_TLDS.has(tld)) s.push({ id: 'abused_tld', label: `.${tld} is frequently abused for phishing`, detail: n.host, weight: 5 });
    if (/(login|signin|verify|account|secure|update|password|webscr|wp-login)/i.test(n.path)) s.push({ id: 'credential_path', label: 'Credential-themed path', detail: n.path.slice(0, 120), weight: 5 });
    return s;
}

export interface SourceResult { source: string; consulted: boolean; malicious: boolean; detail: string }
export interface UrlAnalysis {
    input: string;
    normalized: NormalizedUrl | null;
    analyzed_at: string;
    verdict: 'malicious' | 'suspicious' | 'no_known_threat' | 'invalid';
    reasons: string[];
    signals: Signal[];
    sources: SourceResult[];
    domain_age_days: number | null;
    registrar: string | null;
    fetch: { performed: boolean; status: number | null; final_url: string | null; redirects: Hop[]; tls: TlsInfo | null; error: string | null } | null;
}

const cache = new Map<string, { at: number; value: UrlAnalysis }>();
const CACHE_MS = 60 * 60 * 1000;

export async function analyzeUrl(input: string, opts: { fetch?: boolean } = {}): Promise<UrlAnalysis> {
    const n = normalizeUrl(input);
    const base: UrlAnalysis = { input, normalized: n, analyzed_at: new Date().toISOString(), verdict: 'invalid', reasons: [], signals: [], sources: [], domain_age_days: null, registrar: null, fetch: null };
    if (!n) return { ...base, reasons: ['Not a valid http(s) URL.'] };
    const key = `${n.url}|${opts.fetch ? 1 : 0}`;
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.value;

    const signals = structureSignals(n, input);
    const sources: SourceResult[] = [];
    const [uh, uhHost, phish, vt, whois] = await Promise.allSettled([
        urlhausLookupURL(n.url), urlhausLookupHost(n.host), checkPhishSources(n.url),
        vtConfigured() ? vtCheckURL(n.url) : Promise.resolve(null),
        /^\d/.test(n.domain) ? Promise.resolve(null) : lookupDomain(n.domain),
    ]);

    const uhUrl = uh.status === 'fulfilled' ? uh.value : null;
    const uhH = uhHost.status === 'fulfilled' ? uhHost.value : null;
    const uhUrlHit = !!uhUrl && (uhUrl as { query_status?: string }).query_status === 'ok';
    const uhHostHit = !!uhH && (uhH as { query_status?: string }).query_status === 'ok';
    // urlhaus.ts returns null both for "no results" and for a failed call, so a null here can't
    // be reported as a clean result.
    const uhKey = !!process.env.URLHAUS_API_KEY;
    sources.push({
        source: 'URLhaus', consulted: uhKey, malicious: uhUrlHit || uhHostHit,
        detail: !uhKey ? 'Not configured (URLHAUS_API_KEY)'
            : uhUrlHit ? `Listed: ${(uhUrl as { threat?: string }).threat ?? 'malware distribution'}`
            : uhHostHit ? 'Host has listed malware URLs' : 'Not listed (or the lookup failed)',
    });
    if (phish.status === 'fulfilled') {
        for (const d of phish.value.details) {
            const name = d.source === 'phishtank' ? 'PhishTank' : 'OpenPhish';
            sources.push({ source: name, consulted: !d.error, malicious: d.is_phishing, detail: d.error ? `Unavailable: ${d.error}` : d.is_phishing ? 'Listed as phishing' : 'Not listed' });
        }
    }
    if (!vtConfigured()) sources.push({ source: 'VirusTotal', consulted: false, malicious: false, detail: 'Not configured (VIRUSTOTAL_API_KEY)' });
    else {
        const v = vt.status === 'fulfilled' ? vt.value : null;
        const mal = (v?.stats?.malicious ?? 0);
        sources.push({ source: 'VirusTotal', consulted: v !== null, malicious: mal >= 2, detail: v ? `${mal} engine${mal === 1 ? '' : 's'} flag it malicious` : 'Lookup failed or URL not yet known' });
    }

    const w = whois.status === 'fulfilled' ? whois.value : null;
    const created = w?.created ? Date.parse(w.created) : NaN;
    const ageDays = Number.isFinite(created) ? Math.floor((Date.now() - created) / 86_400_000) : null;
    if (ageDays !== null && ageDays < 30) signals.push({ id: 'young_domain', label: 'Domain registered in the last 30 days', detail: `${ageDays} days old`, weight: 15 });

    let fetch: UrlAnalysis['fetch'] = null;
    if (opts.fetch) {
        try {
            const r = await safeGet(n.url);
            fetch = { performed: true, status: r.status, final_url: r.final_url, redirects: r.redirects, tls: r.tls, error: null };
            const endHost = normalizeUrl(r.final_url)?.domain;
            if (endHost && endHost !== n.domain) signals.push({ id: 'cross_domain_redirect', label: 'Redirects to a different domain', detail: `${n.domain} → ${endHost}`, weight: 10 });
        } catch (err) {
            fetch = { performed: false, status: null, final_url: null, redirects: [], tls: null, error: err instanceof BlockedTargetError ? `Refused: ${err.message}` : (err as Error).message };
        }
    }

    const listed = sources.filter((s) => s.malicious);
    const score = signals.reduce((s, x) => s + x.weight, 0);
    const verdict: UrlAnalysis['verdict'] = listed.length ? 'malicious' : score >= 25 ? 'suspicious' : 'no_known_threat';
    const reasons = [
        ...listed.map((s) => `${s.source}: ${s.detail}`),
        ...signals.map((s) => s.label),
    ];
    if (verdict === 'no_known_threat') reasons.push('No threat-intelligence source lists it and its structure is unremarkable. This is not proof it is safe.');
    const value: UrlAnalysis = { ...base, verdict, reasons, signals, sources, domain_age_days: ageDays, registrar: w?.registrar ?? null, fetch };
    cache.set(key, { at: Date.now(), value });
    if (cache.size > 2000) cache.delete(cache.keys().next().value as string);
    return value;
}
