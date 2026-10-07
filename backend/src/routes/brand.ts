import { Router } from 'express';
import { darkWebSearch } from '../services/darkweb';
import { requireAuth } from '../middleware/auth';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { searchCode as githubSearch, isConfigured as githubConfigured, type GitHubCodeMatch } from '../services/github';
import { searchCode as gitlabSearch, isConfigured as gitlabConfigured, type GitLabCodeMatch } from '../services/gitlab';
import {
    searchBrandMentions as serperSearchBrandMentions,
    searchCounterfeitSites as serperSearchCounterfeitSites,
    searchBreachMentions,
    isConfigured as serperConfigured,
} from '../services/serper';
import { searchBrandMentions as googleSearchBrandMentions, searchCounterfeitSites as googleSearchCounterfeitSites, isConfigured as googleConfigured } from '../services/google';
import { checkEmailBreach } from '../services/breachCheck';
import { searchSocialMentions } from '../services/socialMonitor';
import { logAudit } from '../lib/audit';
import gplay from 'google-play-scraper';

const SocialSchema = z.object({
    platform: z.enum(['twitter', 'facebook', 'instagram', 'linkedin']),
    handle: z.string().min(1).max(100).trim(),
    display_name: z.string().max(200).trim().optional(),
    profile_url: z.string().max(500).trim().optional(),
});

const ExecutiveSchema = z.object({
    name: z.string().min(1).max(200).trim(),
    email: z.string().email().max(200).toLowerCase().trim(),
    role: z.string().max(100).trim().optional(),
    department: z.string().max(100).trim().optional(),
    org: z.string().max(200).trim().optional(),
});

const ExecutiveSocialSchema = z.object({
    platform: z.enum(['twitter', 'facebook', 'instagram', 'linkedin']),
    handle: z.string().min(1).max(100).trim(),
});

const AppSchema = z.object({
    name: z.string().min(1).max(200).trim(),
    platform: z.enum(['iOS', 'Android']),
    bundle_id: z.string().max(200).trim().optional(),
    developer: z.string().max(200).trim().optional(),
    store_url_ios: z.string().max(500).trim().optional(),
    store_url_android: z.string().max(500).trim().optional(),
});

const SignatureSchema = z.object({
    type: z.enum(['STRING', 'REGEX', 'HASH']),
    pattern: z.string().min(1).max(500).trim(),
    description: z.string().max(300).trim().optional(),
});

const AssetsPatchSchema = z.object({
    official_domain: z.string().max(253).trim().optional(),
    brand_name: z.string().max(200).trim().optional(),
    trademark_keywords: z.array(z.string().max(100)).max(50).optional(),
});

// Brand Protection — domains, socials, executives, apps, and code-leak monitoring.
// Scans call real services where they exist (breach checks, iTunes/Play search, GitHub/GitLab
// code search, Serper/Google brand search, Ransomwatch). Monitored entities (socials, executives,
// apps, signatures, brand assets) are kept in memory per resource and reset on restart. Alert
// feeds with no detector behind them (social impersonation, rogue apps) return empty with
// connected:false — their fabricated sample data was removed in the 2026-10 cleanup.

const router = Router();

let nextId = 100;
const newId = () => String(nextId++);

// ── DOMAINS ─────────────────────────────────────────────────────────
// Moved to routes/domainSuite.ts (mounted at /api/brand/domains) — real crt.sh + RDAP lookups,
// monitored-domain add/remove/scan/dns flow. Kept out of this file to avoid a route collision.

// ── SOCIALS ─────────────────────────────────────────────────────────

interface MonitoredSocial {
    id: string;
    platform: string;
    handle: string;
    display_name: string;
    profile_url: string;
    exec_names: string[];
    keywords: string[];
    followers: number;
    verified: boolean;
    last_checked: string;
}

// Starts empty: the previous seed carried invented follower counts. Accounts are added via POST.
const socials: MonitoredSocial[] = [];

router.get('/socials', (_req, res) => {
    res.json({ socials });
});

router.post('/socials', validate(SocialSchema), (req, res) => {
    const {
        platform, handle, display_name, profile_url, exec_names, keywords,
    }: {
        platform?: string;
        handle?: string;
        display_name?: string;
        profile_url?: string;
        exec_names?: string[];
        keywords?: string[];
    } = req.body ?? {};

    if (!platform || !handle) {
        res.status(400).json({ error: 'platform and handle are required' });
        return;
    }
    const entry: MonitoredSocial = {
        id: newId(),
        platform,
        handle,
        display_name: display_name ?? handle,
        profile_url: profile_url ?? '',
        exec_names: exec_names ?? [],
        keywords: keywords ?? [],
        followers: 0,
        verified: false,
        last_checked: 'Just now',
    };
    socials.push(entry);
    res.status(201).json(entry);
});

// No impersonation/mention detector is connected; the previous fabricated alerts were removed.
router.get('/socials/alerts', (_req, res) => {
    res.json({ impersonations: [], mentions: [], connected: false, note: 'Impersonation and mention monitoring is not connected yet.' });
});

// GET /api/brand/socials/search?brand=X — real web/social mention search (services/
// socialMonitor.ts: rsshub X search + Google Custom Search), separate from the /socials/alerts
// feed above.
router.get('/socials/search', async (req, res) => {
    const brand = typeof req.query.brand === 'string' ? req.query.brand.trim() : '';
    if (!brand) {
        res.status(400).json({ error: 'brand query param required' });
        return;
    }
    const result = await searchSocialMentions(brand);
    res.json(result);
});

// ── EXECUTIVES ──────────────────────────────────────────────────────

interface ExecBreach {
    source: string;
    title: string;
    breach_date: string;
    data_classes: string[];
    is_sensitive: boolean;
    is_verified: boolean;
}

interface ExecutiveSocial {
    platform: 'twitter' | 'facebook' | 'instagram' | 'linkedin';
    handle: string;
}

interface AuthAnomaly {
    type: string;
    message: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    time: string;
}

interface MonitoredExecutive {
    id: string;
    name: string;
    email: string;
    role: string;
    department: string;
    org: string;
    socials: ExecutiveSocial[];
    status: 'monitored' | 'at_risk' | 'clear';
    added_at: string;
    last_scanned: string | null;
    breach_count: number;
    breaches: ExecBreach[];
    scan_status: 'pending' | 'scanning' | 'complete' | 'error';
    auth_anomalies: AuthAnomaly[];
    risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
}

const executives: MonitoredExecutive[] = [
    // Intentionally empty. This used to ship four hardcoded executives (a CEO, CTO, CFO and
    // Head of Sales) carrying invented breach records — a fabricated LinkedIn 2021 hit, Adobe
    // 2013/Dropbox 2012 hits, and a fake "unusual login from London" anomaly. None of it came
    // from a real breach check, so the page was presenting fiction as findings.
    //
    // Executives are now added by the operator via POST /executives, and their breach data
    // comes from POST /executives/:id/scan (services/breachCheck.ts — XposedOrNot). An empty
    // list renders the empty state in the UI; don't reseed it.
];

function maskEmail(email: string): string {
    const [user, domain] = email.split('@');
    if (!domain) return email;
    return `${user[0] ?? ''}***@${domain}`;
}

router.get('/executives', (_req, res) => {
    res.json({
        // Explicit field list, not `...e` — the raw `email` on the in-memory record must
        // never leave this response; only the masked form does. `...e` alongside
        // `email_masked` used to spread the unmasked email in too, defeating the point.
        executives: executives.map((e) => ({
            id: e.id,
            name: e.name,
            role: e.role,
            department: e.department,
            org: e.org,
            socials: e.socials,
            status: e.status,
            added_at: e.added_at,
            last_scanned: e.last_scanned,
            breach_count: e.breach_count,
            breaches: e.breaches,
            scan_status: e.scan_status,
            auth_anomalies: e.auth_anomalies,
            risk_level: e.risk_level,
            email_masked: maskEmail(e.email),
        })),
        capabilities: {
            // Always true — XposedOrNot and BreachDirectory (services/breachCheck.ts) replaced
            // the paid HIBP dependency; XposedOrNot never needs a key at all. BreachDirectory's
            // public API is Cloudflare-blocked in practice (see that file's header) so it
            // contributes nothing today, but breach checking as a whole no longer depends on it.
            breach_check: true,
            wazuh: false, // true once Wazuh is reachable from this backend
            darkweb: false, // true once Flare.io is configured (Phase 2)
        },
    });
});

router.post('/executives', validate(ExecutiveSchema), (req, res) => {
    const { name, email, role, department, org }: { name?: string; email?: string; role?: string; department?: string; org?: string } = req.body ?? {};
    if (!name || !email) {
        res.status(400).json({ error: 'name and email are required' });
        return;
    }
    const entry: MonitoredExecutive = {
        id: newId(),
        name,
        email,
        role: role ?? 'Executive',
        department: department ?? '—',
        org: org ?? 'Cybernovr',
        socials: [],
        status: 'monitored',
        added_at: new Date().toISOString().split('T')[0],
        last_scanned: null,
        breach_count: 0,
        breaches: [],
        scan_status: 'pending',
        auth_anomalies: [],
        risk_level: 'LOW',
    };
    executives.push(entry);
    logAudit({
        user: 'unknown', // no auth context on this route yet — see index.ts's requireAuth comment
        action: 'ADD_EXECUTIVE',
        resource: `Executive: ${name}`,
        ip: req.ip || (req.headers['x-forwarded-for'] as string) || 'unknown',
        result: 'success',
    });
    res.status(201).json(entry);
});

// POST /api/brand/executives/:id/socials — attach a social handle to an executive
router.post('/executives/:id/socials', validate(ExecutiveSocialSchema), (req, res) => {
    const exec = executives.find((e) => e.id === req.params.id);
    if (!exec) {
        res.status(404).json({ error: 'Executive not found' });
        return;
    }
    const { platform, handle }: { platform?: ExecutiveSocial['platform']; handle?: string } = req.body ?? {};
    if (!platform || !handle) {
        res.status(400).json({ error: 'platform and handle required' });
        return;
    }
    if (!exec.socials) exec.socials = [];
    exec.socials.push({ platform, handle });
    res.json({ success: true, socials: exec.socials });
});

router.get('/executives/alerts', (_req, res) => {
    const breaches = executives.flatMap((e) => e.breaches.map((b) => ({
        name: e.name,
        source: b.title,
        date: b.breach_date,
        classes: b.data_classes,
        severity: b.is_sensitive ? 'critical' : 'high',
    })));
    res.json({ breaches });
});

interface ExecScanResult {
    executive_id: string;
    scanned_at: string;
    checked: boolean;
    sources: string[];
    breaches: ExecBreach[];
    web_mentions?: Array<{ title: string; url: string; snippet: string }>;
    note?: string;
}

// POST /api/brand/executives/:id/scan — free breach check via XposedOrNot + BreachDirectory
// (services/breachCheck.ts), replacing the paid HIBP dependency, plus a Serper web search for
// breach/leak/paste-site mentions of the exec's name/email (services/serper.ts). XposedOrNot
// needs no key at all, so there's no "not configured" branch for the structured check; the
// Serper half silently contributes nothing without SERPER_API_KEY.
router.post('/executives/:id/scan', async (req, res) => {
    const exec = executives.find((e) => e.id === req.params.id);
    if (!exec) {
        res.status(404).json({ error: 'Executive not found' });
        return;
    }

    exec.scan_status = 'scanning';
    const scanResult: ExecScanResult = {
        executive_id: exec.id,
        scanned_at: new Date().toISOString(),
        checked: false,
        sources: [],
        breaches: [],
    };

    try {
        const [result, breachMentions] = await Promise.all([
            checkEmailBreach(exec.email),
            // Serper web search for the exec's name/email alongside breach/leak/paste-site
            // phrasing — catches informal mentions (forum posts, paste dumps) that XposedOrNot's
            // structured breach-name lookup below wouldn't surface. Silently empty when
            // SERPER_API_KEY isn't set (serper.ts's own isConfigured() gate).
            searchBreachMentions(exec.name, exec.email).catch(() => null),
        ]);
        scanResult.checked = true;
        scanResult.sources = result.details.filter((d) => !d.error).map((d) => d.source);
        // Neither free source exposes a breach date, data classes, or a sensitivity flag the
        // way HIBP's paid API did — XposedOrNot returns breach *names* only. is_sensitive stays
        // false (unknown, not "confirmed not sensitive") rather than guessed.
        scanResult.breaches = result.sources.map((name) => ({
            source: name,
            title: name,
            breach_date: 'Unknown',
            data_classes: [],
            is_sensitive: false,
            is_verified: true,
        }));
        if (breachMentions?.results.length) {
            scanResult.sources.push('serper');
            scanResult.web_mentions = breachMentions.results.map((r) => ({
                title: r.title,
                url: r.url,
                snippet: r.snippet,
            }));
        }
        exec.breach_count = scanResult.breaches.length;
        exec.breaches = scanResult.breaches;
        exec.last_scanned = scanResult.scanned_at;
        exec.scan_status = 'complete';
        exec.status = exec.breach_count > 0 ? 'at_risk' : 'clear';
        exec.risk_level = exec.breach_count > 5 ? 'HIGH' : exec.breach_count > 0 ? 'MEDIUM' : 'LOW';
        if (result.details.every((d) => d.error)) scanResult.note = 'Both breach-check sources were unreachable — result may be incomplete.';
    } catch {
        exec.scan_status = 'error';
    }

    res.json(scanResult);
});

// ── MOBILE APPS ─────────────────────────────────────────────────────

interface MonitoredApp {
    id: string;
    name: string;
    bundle_id: string;
    platform: 'iOS' | 'Android';
    developer: string;
    store_url_ios: string | null;
    store_url_android: string | null;
    added_at: string;
    last_scanned: string | null;
    // null: not checked. The seeded entries used to claim verified:true and an invented scan date.
    verified: boolean | null;
}

const apps: MonitoredApp[] = [
    {
        id: 'app_001', name: 'NovrSOC Mobile', bundle_id: 'com.cybernovr.novrsoc', platform: 'iOS', developer: 'Cybernovr Ltd',
        store_url_ios: 'https://apps.apple.com/app/novrsoc', store_url_android: 'https://play.google.com/store/apps/details?id=com.cybernovr.novrsoc',
        added_at: '2026-01-15', last_scanned: null, verified: null,
    },
    {
        id: 'app_001b', name: 'NovrSOC Mobile', bundle_id: 'com.cybernovr.novrsoc', platform: 'Android', developer: 'Cybernovr Ltd',
        store_url_ios: 'https://apps.apple.com/app/novrsoc', store_url_android: 'https://play.google.com/store/apps/details?id=com.cybernovr.novrsoc',
        added_at: '2026-01-15', last_scanned: null, verified: null,
    },
    {
        id: 'app_002', name: 'Cybernovr Security', bundle_id: 'com.cybernovr.security', platform: 'Android', developer: 'Cybernovr Ltd',
        store_url_ios: null, store_url_android: 'https://play.google.com/store/apps/details?id=com.cybernovr.security',
        added_at: '2026-03-01', last_scanned: null, verified: null,
    },
];

router.get('/apps', (_req, res) => {
    res.json({ apps });
});

router.post('/apps', validate(AppSchema), (req, res) => {
    const { name, bundle_id, platform, developer, store_url_ios, store_url_android } = req.body ?? {};
    if (!name || !platform) {
        res.status(400).json({ error: 'name and platform are required' });
        return;
    }
    const entry: MonitoredApp = {
        id: newId(),
        name,
        bundle_id: bundle_id ?? '—',
        platform,
        developer: developer ?? '—',
        store_url_ios: store_url_ios ?? null,
        store_url_android: store_url_android ?? null,
        added_at: new Date().toISOString().split('T')[0],
        last_scanned: null,
        verified: false,
    };
    apps.push(entry);
    res.status(201).json(entry);
});

// No rogue-app detector is connected; the previous fabricated alerts were removed.
router.get('/apps/alerts', (_req, res) => {
    res.json({ rogueApps: [], connected: false, note: 'Rogue app detection is not connected yet.' });
});

interface AppStoreHit {
    name: string;
    bundle_id: string;
    developer: string;
    store_url: string;
    icon_url: string;
    price: string;
    rating: number | null;
    review_count: number | null;
}

interface PlayStoreHit {
    name: string;
    bundle_id: string;
    developer: string;
    store_url: string;
    icon_url: string;
    rating: number | null;
}

interface ITunesResult {
    trackName: string;
    bundleId: string;
    artistName: string;
    trackViewUrl: string;
    artworkUrl100: string;
    formattedPrice: string;
    averageUserRating: number | null;
    userRatingCount: number | null;
}

interface ITunesSearchResponse {
    results: ITunesResult[];
}

// POST /api/brand/apps/scan — real iTunes Search API + Google Play search
router.post('/apps/scan', async (req, res) => {
    const brandName: string = typeof req.body?.brand_name === 'string' && req.body.brand_name.trim() ? req.body.brand_name.trim() : 'cybernovr';

    const results: { brand_name: string; scanned_at: string; appstore: AppStoreHit[]; playstore: PlayStoreHit[] } = {
        brand_name: brandName,
        scanned_at: new Date().toISOString(),
        appstore: [],
        playstore: [],
    };

    try {
        const itunesRes = await fetch(
            `https://itunes.apple.com/search?term=${encodeURIComponent(brandName)}&entity=software&limit=10`,
            { signal: AbortSignal.timeout(8000) }
        );
        const data = (await itunesRes.json()) as ITunesSearchResponse;
        results.appstore = (data.results ?? []).map((app) => ({
            name: app.trackName,
            bundle_id: app.bundleId,
            developer: app.artistName,
            store_url: app.trackViewUrl,
            icon_url: app.artworkUrl100,
            price: app.formattedPrice,
            rating: app.averageUserRating ?? null,
            review_count: app.userRatingCount ?? null,
        }));
    } catch (err) {
        console.warn('[Mobile App Suite] iTunes search error:', err);
    }

    try {
        const playResults = await gplay.search({ term: brandName, num: 10, lang: 'en', country: 'ng' });
        results.playstore = playResults.map((app) => ({
            name: app.title,
            bundle_id: app.appId,
            developer: app.developer,
            store_url: app.url,
            icon_url: app.icon,
            rating: app.score ?? null,
        }));
    } catch (err) {
        console.warn('[Mobile App Suite] Play Store search error:', err);
    }

    res.json(results);
});

// ── CODE SIGNATURES / LEAK DETECTION ───────────────────────────────

interface CodeSignature {
    id: string;
    type: 'STRING' | 'REGEX' | 'HASH';
    pattern: string;
    description: string;
    matches: number;
}

const signatures: CodeSignature[] = [
    { id: '1', type: 'REGEX', pattern: 'AKIA[0-9A-Z]{16}', description: 'AWS Access Key', matches: 0 },
    { id: '2', type: 'REGEX', pattern: '"api_key"\\s*:\\s*"[^"]+"', description: 'API Key Pattern', matches: 0 },
    { id: '3', type: 'STRING', pattern: 'cybernovr.com', description: 'Brand Domain', matches: 0 },
    { id: '4', type: 'REGEX', pattern: 'postgresql://.*:.*@', description: 'Database URL', matches: 0 },
    { id: '5', type: 'REGEX', pattern: 'JWT_SECRET\\s*=\\s*\\S+', description: 'JWT Secret', matches: 0 },
    { id: '6', type: 'REGEX', pattern: '-----BEGIN.*PRIVATE KEY', description: 'Private Key Block', matches: 0 },
];

router.get('/signatures', (_req, res) => {
    res.json({ signatures });
});

router.post('/signatures', validate(SignatureSchema), (req, res) => {
    const { type, pattern, description } = req.body ?? {};
    if (!type || !pattern) {
        res.status(400).json({ error: 'type and pattern are required' });
        return;
    }
    const entry: CodeSignature = { id: newId(), type, pattern, description: description ?? '—', matches: 0 };
    signatures.push(entry);
    res.status(201).json(entry);
});

interface LeakScanHit extends Partial<GitHubCodeMatch>, Partial<GitLabCodeMatch> {
    source: 'github' | 'gitlab';
}

// POST /api/brand/leaks/scan — triggers a real GitHub + GitLab code search when tokens are
// configured (services/github.ts, services/gitlab.ts). With neither configured it says so —
// it used to answer {status:'queued'} although nothing was queued.
router.post('/leaks/scan', async (req, res) => {
    const orgName: string = typeof req.body?.org_name === 'string' ? req.body.org_name : 'cybernovr';

    const results: LeakScanHit[] = [];
    const summary = {
        github_configured: githubConfigured(),
        gitlab_configured: gitlabConfigured(),
        github_results: 0,
        gitlab_results: 0,
        scanned_at: new Date().toISOString(),
    };

    if (!summary.github_configured && !summary.gitlab_configured) {
        res.json({ status: 'not_configured', results, summary, note: 'Neither GITHUB_TOKEN nor GITLAB_TOKEN is set — no code search ran.' });
        return;
    }

    if (summary.github_configured) {
        try {
            const [brandMatches, keyMatches, apiKeyMatches] = await Promise.allSettled([
                githubSearch(`"${orgName}.com" filename:.env`, 5),
                githubSearch(`"${orgName}" AKIA`, 5), // AWS key pattern
                githubSearch(`"${orgName}" api_key`, 5),
            ]);
            const allMatches = [brandMatches, keyMatches, apiKeyMatches]
                .filter((r): r is PromiseFulfilledResult<GitHubCodeMatch[]> => r.status === 'fulfilled')
                .flatMap((r) => r.value);
            summary.github_results = allMatches.length;
            results.push(...allMatches.map((m) => ({ ...m, source: 'github' as const })));
        } catch (err) {
            console.warn('[copyID] GitHub scan error:', err);
        }
    }

    if (summary.gitlab_configured) {
        try {
            const gitlabMatches = await gitlabSearch(`${orgName}.com`);
            summary.gitlab_results = gitlabMatches.length;
            results.push(...gitlabMatches.map((m) => ({ ...m, source: 'gitlab' as const })));
        } catch (err) {
            console.warn('[copyID] GitLab scan error:', err);
        }
    }

    res.json({ results, summary });
});

// POST /api/brand/search — brand-mention monitoring. Prefers Serper (services/serper.ts); falls
// back to Google Custom Search (services/google.ts) when SERPER_API_KEY isn't set, so an
// already-working Google CSE key from before this change keeps working with no config change.
router.post('/search', async (req, res) => {
    const { brand_name, official_domains = [], search_type = 'mentions' } = req.body ?? {};

    if (!brand_name || typeof brand_name !== 'string') {
        res.status(400).json({ error: 'brand_name required' });
        return;
    }

    const provider = serperConfigured() ? 'serper' : googleConfigured() ? 'google' : null;

    if (!provider) {
        // No search provider configured: say so. (This used to return three fabricated
        // violations with invented threat scores.)
        res.json({
            configured: false,
            results: [],
            note: 'Web Intelligence Engine not configured (SERPER_API_KEY or Google Custom Search keys) — no live results.',
        });
        return;
    }

    try {
        const [searchMentions, searchCounterfeit] = provider === 'serper'
            ? [serperSearchBrandMentions, serperSearchCounterfeitSites]
            : [googleSearchBrandMentions, googleSearchCounterfeitSites];

        const result = search_type === 'counterfeit'
            ? await searchCounterfeit(brand_name, official_domains)
            : await searchMentions(brand_name, official_domains);

        res.json({ configured: true, provider, ...(result ?? { results: [], total_results: 0 }) });
    } catch {
        res.status(500).json({ error: 'Brand search failed' });
    }
});

// ── BRAND ASSETS ────────────────────────────────────────────────────

interface BrandAssets {
    official_domain: string;
    brand_name: string;
    trademark_keywords: string[];
    logo_uploaded: boolean;
    logo_filename: string | null;
}

const brandAssets: BrandAssets = {
    official_domain: 'cybernovr.com',
    brand_name: 'Cybernovr',
    trademark_keywords: ['cybernovr', 'novrsoc', 'novr'],
    logo_uploaded: false,
    logo_filename: null,
};

router.get('/assets', (_req, res) => {
    res.json({ ...brandAssets, capabilities: { vision: false, web_search: googleConfigured() } });
});

router.patch('/assets', validate(AssetsPatchSchema), (req, res) => {
    const { official_domain, brand_name, trademark_keywords }: {
        official_domain?: string;
        brand_name?: string;
        trademark_keywords?: string[];
    } = req.body ?? {};

    if (official_domain) brandAssets.official_domain = official_domain;
    if (brand_name) brandAssets.brand_name = brand_name;
    if (trademark_keywords) brandAssets.trademark_keywords = trademark_keywords;
    res.json(brandAssets);
});

// POST /api/brand/assets/logo — logo upload acknowledgement (real file storage/S3 lands with
// a later multer + object-storage pass; this records that a logo was provided).
router.post('/assets/logo', (req, res) => {
    const { filename }: { filename?: string } = req.body ?? {};
    brandAssets.logo_uploaded = true;
    brandAssets.logo_filename = filename ?? 'logo.png';
    res.json({ success: true, message: 'Logo uploaded successfully', logo_filename: brandAssets.logo_filename });
});

// GET /api/brand/darkweb?company=&domain=
//
// Dark web exposure check. Only Ransomwatch is actually consulted — see services/darkweb.ts for
// why Ahmia and the paste-site APIs are not (both are dead or unusable, and a scraper that
// silently returns nothing would render as a reassuring "no mentions found"). The `sources`
// array reports the real state of each so the UI can show coverage honestly.
//
// Deliberately does NOT auto-create a case or send a notification on a hit. This route is a
// read-only search an analyst can run repeatedly while tuning search terms; auto-creating a case
// per scan would spam the case queue with duplicates of the same finding. The UI offers an
// explicit "Create case" action instead, so raising a case stays a decision rather than a
// side effect of looking.
// Terms: repeated ?keywords= (company, domains, executive or product names), max 20. The old
// ?company=&domain= form still works. For any keyword that looks like a domain, its bare label
// is searched too — leak sites list victims by trading name ("Cybernovr"), rarely by the full
// domain. Analyst-only: only the admin Dark Web Monitor calls this.
router.get('/darkweb', requireAuth, async (req, res) => {
    const asList = (v: unknown): string[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]).filter((x): x is string => typeof x === 'string');
    let keywords = asList(req.query.keywords).map((k) => k.trim()).filter(Boolean);
    if (keywords.length === 0) {
        const company = typeof req.query.company === 'string' && req.query.company.trim() ? req.query.company.trim() : 'Cybernovr';
        const domain = typeof req.query.domain === 'string' && req.query.domain.trim() ? req.query.domain.trim() : 'cybernovr.com';
        keywords = [company, domain];
    }
    keywords = keywords.slice(0, 20).map((k) => k.slice(0, 100));
    const expanded = keywords.flatMap((k) => (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(k) ? [k, k.split('.')[0]] : [k]));
    const terms = Array.from(new Set(expanded.map((t) => t.trim()).filter(Boolean)));

    try {
        const { findings, sources } = await darkWebSearch(terms);
        res.json({
            results: findings,
            total: findings.length,
            critical: findings.filter((f) => f.severity === 'critical').length,
            searched: terms,
            keywords,
            sources,
            scanned_at: new Date().toISOString(),
        });
    } catch (err) {
        console.error('[brand/darkweb] failed:', err instanceof Error ? err.message : err);
        res.status(502).json({ error: 'Dark web search failed', results: [], total: 0, critical: 0, searched: terms, sources: [] });
    }
});

export default router;
