// Website evidence for a suspicious domain: one safe GET (safeFetch.ts rules), then static
// extraction from the HTML. Nothing is executed, submitted or clicked — forms are described,
// never filled; scripts are counted, never run.
import { safeGet, BlockedTargetError, type TlsInfo, type Hop } from './safeFetch';

export interface FormEvidence { action: string | null; method: string; external: boolean; password_fields: number; email_fields: number; hidden_fields: number }
export interface WebsiteEvidence {
    inspected_at: string;
    url: string;
    reachable: boolean;
    error: string | null;
    blocked: boolean;
    final_url: string | null;
    status: number | null;
    redirects: Hop[];
    cross_domain_redirect: boolean;
    tls: TlsInfo | null;
    title: string | null;
    meta: Record<string, string>;
    forms: FormEvidence[];
    login_indicators: string[];
    brand_mentions: string[];
    external_scripts: number;
    iframes: number;
    content_type: string | null;
    truncated: boolean;
}

const hostOf = (u: string) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
const attr = (tag: string, name: string) => new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)?.slice(2).find((x) => x !== undefined) ?? null;
const stripTags = (html: string) => html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

const LOGIN_PHRASES = ['sign in', 'log in', 'login', 'verify your account', 'confirm your identity', 'enter your password', 'account suspended', 'update your payment', 'one-time password', 'otp'];

/** Static analysis of an HTML document. Exported for tests. */
export function extractEvidence(html: string, pageUrl: string, brandTerms: string[]) {
    const pageHost = hostOf(pageUrl);
    const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1].replace(/\s+/g, ' ').trim().slice(0, 300) || null;
    const meta: Record<string, string> = {};
    for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
        const key = (attr(m[0], 'name') ?? attr(m[0], 'property') ?? attr(m[0], 'http-equiv'))?.toLowerCase();
        const content = attr(m[0], 'content');
        if (key && content && ['description', 'og:site_name', 'og:title', 'generator', 'refresh', 'robots'].includes(key)) meta[key] = content.slice(0, 300);
    }
    const forms: FormEvidence[] = [];
    for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)(<\/form>|$)/gi)) {
        const action = attr(m[1], 'action');
        const inputs = [...m[2].matchAll(/<input\b[^>]*>/gi)].map((i) => (attr(i[0], 'type') ?? 'text').toLowerCase());
        let external = false;
        if (action && /^https?:/i.test(action)) external = hostOf(action) !== pageHost;
        forms.push({
            action: action?.slice(0, 300) ?? null,
            method: (attr(m[1], 'method') ?? 'get').toLowerCase(),
            external,
            password_fields: inputs.filter((t) => t === 'password').length,
            email_fields: inputs.filter((t) => t === 'email').length,
            hidden_fields: inputs.filter((t) => t === 'hidden').length,
        });
    }
    const passwordOutsideForm = /<input\b[^>]*type\s*=\s*["']?password/i.test(html) && forms.every((f) => f.password_fields === 0);
    const textLower = stripTags(html).toLowerCase();
    const login = LOGIN_PHRASES.filter((p) => textLower.includes(p));
    if (forms.some((f) => f.password_fields > 0) || passwordOutsideForm) login.unshift('password field');
    const brand = [...new Set(brandTerms.map((t) => t.toLowerCase()).filter((t) => t.length >= 3 && (textLower.includes(t) || (title ?? '').toLowerCase().includes(t))))];
    return {
        title, meta, forms,
        login_indicators: [...new Set(login)],
        brand_mentions: brand,
        external_scripts: [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?https?:\/\/([^/"'\s>]+)/gi)].filter((m) => m[1].toLowerCase() !== pageHost).length,
        iframes: (html.match(/<iframe\b/gi) ?? []).length,
    };
}

export async function inspectWebsite(domainOrUrl: string, brandTerms: string[]): Promise<WebsiteEvidence> {
    const url = /^https?:\/\//i.test(domainOrUrl) ? domainOrUrl : `https://${domainOrUrl}/`;
    const base: WebsiteEvidence = {
        inspected_at: new Date().toISOString(), url, reachable: false, error: null, blocked: false, final_url: null, status: null,
        redirects: [], cross_domain_redirect: false, tls: null, title: null, meta: {}, forms: [], login_indicators: [], brand_mentions: [],
        external_scripts: 0, iframes: 0, content_type: null, truncated: false,
    };
    let res;
    try {
        res = await safeGet(url);
    } catch (err) {
        // https failed for a reason other than policy — many phishing kits are plain http.
        if (!(err instanceof BlockedTargetError) && url.startsWith('https://') && !/^https?:\/\//i.test(domainOrUrl)) {
            try { res = await safeGet(`http://${domainOrUrl}/`); } catch (err2) { return { ...base, error: (err2 as Error).message, blocked: err2 instanceof BlockedTargetError }; }
        } else {
            return { ...base, error: (err as Error).message, blocked: err instanceof BlockedTargetError };
        }
    }
    const startHost = hostOf(url);
    const html = /html|xml|text\/plain/i.test(res.content_type ?? 'text/html') ? res.body : '';
    return {
        ...base,
        reachable: true,
        final_url: res.final_url,
        status: res.status,
        redirects: res.redirects,
        cross_domain_redirect: [...res.redirects.map((h) => h.url), res.final_url].some((u) => hostOf(u) !== startHost && !hostOf(u).endsWith(`.${startHost}`)),
        tls: res.tls,
        content_type: res.content_type,
        truncated: res.truncated,
        ...extractEvidence(html, res.final_url, brandTerms),
    };
}
