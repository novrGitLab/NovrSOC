import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { botProtection, requireAuth, requireRole } from './middleware/auth';

import authRouter from './routes/auth';
import portalRouter from './routes/portal';
import accountRouter from './routes/account';
import customersRouter from './routes/customers';
import advisoriesRouter from './routes/advisories';
import complianceRouter from './routes/compliance';
import vendorAssessmentsRouter from './routes/vendor-assessments';
import scanRouter from './routes/scan';
import dnsRouter from './routes/dns';
import domainsRouter from './routes/domains';
import reportsRouter from './routes/reports';
import ctipRouter from './routes/ctip';
import threatIntelRouter from './routes/threat-intel';
import wazuhRouter from './routes/wazuh';
import geoRouter from './routes/geo';
import brandRouter from './routes/brand';
import domainSuiteRouter from './routes/domainSuite';
import contactRouter from './routes/contact';
import threatRouter from './routes/threat';
import ctiRouter from './routes/cti';
import urlscanRouter from './routes/urlscan';
import webscanRouter from './routes/webscan';
import emailSecurityRouter from './routes/emailSecurity';
import vendorsRouter from './routes/vendors';
import dataRecoveryRouter from './routes/dataRecovery';
import slaRouter from './routes/sla';
import alertsRouter from './routes/alerts';
import threatManagementRouter from './routes/threatManagement';
import publicRouter from './routes/public';
import incidentResponseRouter from './routes/incidentResponse';
import weblogicRouter from './routes/weblogic';
import assetsRouter from './routes/assets';
import dashboardRouter from './routes/dashboard';
import handoverRouter from './routes/handover';
import emailRouter from './routes/email';
import orgCTIRouter from './routes/orgCTI';
import { runCTIWatcher } from './jobs/ctiWatcher';
import { startAutoCloseJob } from './jobs/autoClose';
import { startEscalationJob } from './jobs/incidentEscalation';
import { startNigerianIntelJob } from './jobs/nigerianIntelJob';
import { startGlobalIntelJob } from './jobs/globalIntelJob';
import platformRouter from './routes/platform';
import organisationsRouter from './routes/organisations';
import secopsRouter from './routes/secops';
import notificationsRouter from './routes/notifications';
import playbooksRouter from './routes/playbooks';
import novrAiRouter from './routes/novr-ai';

const app = express();

// Railway (and most PaaS hosts) terminate TLS and proxy requests to this process, setting
// X-Forwarded-For/X-Forwarded-Proto on the way in. Without trust proxy set, express-rate-limit
// treats an incoming X-Forwarded-For header as a spoofing attempt from a client that shouldn't
// be able to set it (correct default for an app that IS the edge) and throws
// ERR_ERL_UNEXPECTED_X_FORWARDED_FOR — which crashed the whole process here, since nothing
// downstream of the rate limiters' registration could catch a throw that happens during
// request handling before Express's own error handler runs for it. `1` (not `true`) means
// "trust exactly one hop" — Railway's own edge — rather than trusting the entire forwarded
// chain, which matters for req.ip/rate-limit-by-IP actually reflecting the real client instead
// of whatever a malicious client claims via its own X-Forwarded-For.
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 8000);

// Health check routes — registered before every other app.use() on purpose, not just
// commented as such (a prior version of this file had that comment on a /health route that
// was actually registered after helmet, a permissions-policy middleware, the HTTPS-redirect
// below, cors, and express.json — the comment was simply wrong about what the code did).
// This matters concretely for Railway: its healthcheck prober hits the container directly
// over Railway's internal network, not through the public HTTPS edge, so it never sends
// `x-forwarded-proto: https`. The production-only HTTPS-redirect middleware further down
// treats that as "insecure request" and 301s it — which a healthcheck prober does not follow,
// so it read as "unreachable" even though the process was up and the route existed. Placing
// these two routes before any middleware at all — no helmet headers, no redirect, no CORS, no
// body parsing, no rate limit — guarantees a direct 200 no matter what headers the caller did
// or didn't send.
app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'healthy' });
});
app.get('/', (_req, res) => {
    res.status(200).json({ ok: true, service: 'novrsoc-backend' });
});

// requireAuth is now mounted, but only on routes confirmed to have ZERO client-portal
// exposure — see the per-route comment below. It is NOT mounted globally, and NOT mounted
// on most feature routes, for a reason specific to this app's architecture:
//
// 22 feature components (ThreatManagement, IncidentResponse, CtiPlatform, DnsSuite,
// BrandSuite, DomainSuite, UrlScanSuite, WebsiteScanning, VendorAssessments,
// WebLogicAppliances, MessagingSuite, PHISHIDProtection, DataLossRecovery, RecoveryCredit,
// AlertCommunication, DMARCSaaS, MobileAppSuite, SocialSuite, CopyIdSuite, ExecutiveMonitor,
// ThreatAdvisory, DigitalAssets — cross-checked by diffing every component imported by any
// /admin page against every component imported by any /client page) are rendered by BOTH the
// admin app and the client portal, and call the same backend routes either way: /api/wazuh,
// /api/incidents, /api/threats, /api/threat, /api/brand, /api/dns, /api/urlscan,
// /api/webscan, /api/vendor-assessments, /api/sla, /api/org-cti, /api/recovery,
// /api/weblogic, /api/alerts, /api/advisories.
//
// Client-portal users only ever hold a `portal_token` (see frontend/src/lib/portal-auth.ts),
// minted by the separate external backend at APP_API_BASE_URL with a secret this backend
// does not have. requireAuth can only verify admin JWTs (JWT_SECRET/DEV_TOKEN_SECRET) — it
// has no way to verify a portal_token's signature. Mounting requireAuth on any of the 15
// routes above would 401 every client-portal user immediately, the same "platform
// inaccessible" failure this whole rollout is trying to avoid, just for portal users instead
// of admins. Fixing that needs requireAuth (or a sibling middleware) to accept both token
// shapes — either a shared signing secret with the external backend, or a per-request
// verification call to it — neither confirmed to exist. Until that's built, those 15 routes
// stay open on purpose; don't "fix" this by mounting requireAuth on them blind.
//
// frontend/src/lib/api.ts's apiFetch() already attaches whichever token the browser holds
// (portal_token or admin_token — see lib/account.ts's getAuthToken()) to every apiUrl() call,
// admin and portal alike, so no further frontend work is needed once a route below starts
// enforcing auth — the header is already there, just currently ignored by most routes.

// Origins allowed to call this API with credentials. Known Vercel deployments (prod +
// preview) and local dev ports are listed explicitly; FRONTEND_URL and the legacy
// comma-separated FRONTEND_ORIGIN are folded in too so a Railway env var can add one
// without a code change or override what's hardcoded here. This exact list is still checked
// first below — the *.vercel.app wildcard beneath it is what actually covers Vercel's
// per-branch/per-PR preview URLs (they're not enumerable ahead of time), not this array.
const ALLOWED_ORIGINS = [
    'https://socnovr.vercel.app',
    'https://novrsoc-prev.vercel.app',
    'https://novr-soc.vercel.app',
    'https://novrsoc.vercel.app',
    // This backend's own Railway origin. Not needed for the frontend->backend calls that make up
    // ~all traffic (a page served from Vercel sends its own Vercel origin, and same-origin
    // requests send no Origin header at all), but listed so anything served from the API's own
    // domain — a docs/status page opened in a browser, or a same-site tool — isn't rejected.
    'https://novrsoc-production-1fb6.up.railway.app',
    process.env.FRONTEND_URL,
    process.env.FRONTEND_ORIGIN,
    'http://localhost:3000',
    'http://localhost:3001',
]
    // FRONTEND_ORIGIN has historically been documented/used as a comma-separated list (see the
    // old allowedOrigins.push(...split(','))) — keep supporting that alongside a single value.
    .flatMap((o) => (o ? o.split(',').map((s) => s.trim()) : []))
    .filter(Boolean);

// Shared by both the explicit preflight handler and the main CORS mount just below, so the
// two can't drift out of sync with each other. `!origin` allows non-browser/same-origin
// requests (curl, server-to-server, Postman) — those don't send an Origin header at all, and
// CORS is a browser-enforced check anyway, not an access control mechanism for such requests.
const corsOptions: cors.CorsOptions = {
    origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin) || origin.endsWith('.vercel.app')) {
            cb(null, true);
            return;
        }
        cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

// CORS is registered here — immediately after the two unconditional health-check routes above,
// and BEFORE helmet/the HTTPS-redirect below — on purpose. It used to sit after both of those,
// which was fine for real GET/POST requests but broke preflight OPTIONS requests specifically:
// confirmed live, the HTTPS-redirect middleware 301s any request in production whose
// x-forwarded-proto isn't exactly "https" (see its own comment for why that header isn't
// always present), and a 301 response to an OPTIONS preflight is not something a browser will
// follow — it just reads as "CORS blocked," which is what was actually happening despite the
// origin-matching logic itself (ALLOWED_ORIGINS + the *.vercel.app wildcard) already being
// correct. Putting CORS first means preflight requests get answered before they can ever reach
// that redirect. `app.options('*', cors(corsOptions))` handles preflight explicitly and
// `app.use(cors(corsOptions))` below covers every other method — cors() already fully
// short-circuits OPTIONS on its own when mounted via app.use(), so the explicit handler is
// belt-and-suspenders, not strictly load-bearing once the ordering above is fixed, but it
// keeps preflight handling self-evidently correct without relying on that behaviour.
app.options('*', cors(corsOptions));
app.use(cors(corsOptions));

// This backend only ever serves JSON, never HTML, so most of helmet's CSP directives are
// inert here in practice (a browser only enforces a response's CSP against the document that
// response itself renders as — fetch()/XHR responses from other tabs/scripts aren't governed
// by it). Kept anyway as defense-in-depth and to satisfy the security review baseline;
// next.config.ts carries the headers that actually matter for what the frontend renders.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", 'https://api.anthropic.com', 'https://*.supabase.co'],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
        },
    },
    // Only send HSTS in real production when not on localhost
    hsts: process.env.NODE_ENV === 'production' ? {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    } : false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
    noSniff: true,
    frameguard: { action: 'deny' },
}));

app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
});

// Redirect HTTP to HTTPS in production (Railway terminates TLS in front of this process and
// forwards x-forwarded-proto, so this is the only place that can see the original scheme).
// Redirect HTTP to HTTPS in production (Railway terminates TLS in front of this process)
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        // Belt-and-suspenders on top of CORS now being registered before this middleware
        // (see the comment on corsOptions above for the actual bug this was causing): a
        // preflight OPTIONS request should never be redirected regardless of registration
        // order elsewhere in this file, since a 301 response to one isn't something a browser
        // will follow.
        if (req.method === 'OPTIONS') return next();

        const host = req.headers.host || '';
        const isLocal = host.startsWith('localhost') || host.startsWith('127.0.0.1');

        if (!isLocal && req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect(301, `https://${req.headers.host}${req.url}`);
        }
        next();
    });
}

app.use(express.json());

// Rate limiting — auth endpoints get a tight per-IP window (stacks with the general limiter
// below); everything else gets the looser general one. skipSuccessfulRequests on the auth
// limiter means only *failed* attempts count toward the 10/15min cap, so a legitimate user
// who mistypes their password a couple of times before succeeding isn't penalised.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts — try again in 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: { error: 'Rate limit exceeded' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/auth', authLimiter, botProtection);
app.use('/api/portal/auth', authLimiter, botProtection);
app.use('/api', apiLimiter);

// Public, unauthenticated — the marketing site's free scanner. Mounted ahead of every
// requireAuth-gated route below and never gated itself; it carries its own tighter per-IP limit
// (10/hour) on top of the general apiLimiter above, since it's the one anonymous path that
// spends third-party API quota. See routes/public.ts.
app.use('/api/public', publicRouter);

app.use('/api/auth', authRouter);
app.use('/api/portal', portalRouter);
app.use('/api/account', accountRouter);
// admin-only — no client-portal component calls these, confirmed safe to gate now (see the
// block comment above for how that was checked and why most other routes aren't gated yet).
// soc_manager gets access alongside super_admin here (and on /api/compliance below) — per the
// soc_manager role's spec: "Access compliance data for their org," but analysts and below do
// not get customer/compliance-admin access.
app.use('/api/customers', requireAuth, requireRole('super_admin', 'soc_manager'), customersRouter);
app.use('/api/advisories', advisoriesRouter);
app.use('/api/compliance', requireAuth, requireRole('super_admin', 'soc_manager'), complianceRouter);
app.use('/api/vendor-assessments', vendorAssessmentsRouter);
app.use('/api/scan', scanRouter);
app.use('/api/dns', dnsRouter);
app.use('/api/domains', domainsRouter);
app.use('/api/reports', reportsRouter);
// admin-only — no client-portal component calls this, confirmed safe to gate now.
app.use('/api/novr-ai', requireAuth, novrAiRouter);
app.use('/api/ctip', ctipRouter);
app.use('/api/threat-intel', threatIntelRouter);
app.use('/api/wazuh', wazuhRouter);
app.use('/api/geo', geoRouter);
app.use('/api/brand/domains', domainSuiteRouter);
app.use('/api/brand', brandRouter);
app.use('/api/contact', contactRouter);
app.use('/api/threat', threatRouter);
app.use('/api/cti', ctiRouter);
app.use('/api/urlscan', urlscanRouter);
app.use('/api/webscan', webscanRouter);
app.use('/api/email', emailSecurityRouter);
// Same '/api/email' prefix as emailSecurityRouter above (DMARC domain monitoring /
// messaging gateway checks) — this one is outbound send (SendGrid alerts/reports) plus the
// Mailgun DMARC inbound webhook. Sub-paths don't collide; kept distinct files since the two
// are different concerns (sending vs. scanning) that happen to share a URL namespace.
app.use('/api/email', emailRouter);
app.use('/api/vendors', vendorsRouter);
app.use('/api/recovery', dataRecoveryRouter);
app.use('/api/sla', slaRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/threats', threatManagementRouter);
app.use('/api/incidents', incidentResponseRouter);
app.use('/api/weblogic', weblogicRouter);
app.use('/api/assets', assetsRouter);
// admin-only — no client-portal component calls these, confirmed safe to gate now (see the
// block comment above for how that was checked and why most other routes aren't gated yet).
app.use('/api/dashboard', requireAuth, dashboardRouter);
app.use('/api/handover', requireAuth, handoverRouter);
app.use('/api/org-cti', orgCTIRouter);
// super_admin only — platform infra health is explicitly out of scope for soc_manager per that
// role's spec ("Cannot access platform settings").
app.use('/api/platform', requireAuth, requireRole('super_admin'), platformRouter);
// Just requireAuth here, not requireRole — organisationsRouter's own routes each apply their own
// role requirement (list/create orgs: super_admin only; update/team management: super_admin or
// soc_manager per the customer-onboarding + multitenancy spec; a user reading their own org: any
// authenticated role). A single router-level role would force all of those to the same tier.
app.use('/api/organisations', requireAuth, organisationsRouter);
// admin-only — no client-portal component calls Threat Hunting or the Security Ops Management
// tabs that use this (confirmed: no /client route imports either).
app.use('/api/secops', requireAuth, secopsRouter);
// Not gated — shared by the admin app and the client portal (Header.tsx's notification bell
// polls this from both). See routes/notifications.ts's own header comment.
app.use('/api/notifications', notificationsRouter);
// Not gated at the router level — GET and /:id/run are reachable from IncidentResponse.tsx's
// Attach Playbook picker, which the client portal also renders. The mutating CRUD routes are
// individually gated to super_admin/soc_manager inside routes/playbooks.ts.
app.use('/api/playbooks', playbooksRouter);

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`novrsoc-backend listening on http://localhost:${PORT}`);
});

// CTI watcher — periodically folds newly-seen external IPs from Wazuh alerts into the org CTI
// store (lib/orgCtiStore.ts). Runs once on boot, then every 5 minutes; unref() so it can't
// keep the process alive on its own (matches Node's default expectation that a bare interval
// shouldn't block a clean shutdown).
//
// runCTIWatcher() already catches every error internally (a Wazuh connection failure there
// logs and returns, it never throws/rejects) — a synchronous try/catch wrapped around the call
// site below would NOT actually add protection, since that only catches synchronous throws,
// not a promise that rejects later. The real belt-and-suspenders equivalent is the .catch()
// below: if runCTIWatcher's own handling were ever accidentally broken by a future edit, an
// unhandled rejection here would otherwise crash the process outright on modern Node (default
// behavior since Node 15) — this is what actually stands between "Wazuh down" and "server down".
const startCTIWatcher = () => {
    runCTIWatcher().catch((err) => {
        console.log(`CTI Watcher: Wazuh indexer unavailable, will retry (${err instanceof Error ? err.message : err})`);
    });
};
startCTIWatcher();
setInterval(startCTIWatcher, 5 * 60 * 1000).unref();

// Auto-close job for low/medium-severity TheHive cases — see jobs/autoClose.ts for the
// resolve-after-30-minutes-idle logic. No-ops (with a log line) when TheHive isn't configured.
startAutoCloseJob();
// Escalation emails for unresolved HIGH/CRITICAL cases — see jobs/incidentEscalation.ts.
// No-ops (with a log line) when TheHive isn't configured.
startEscalationJob();
// Hourly Nigerian threat-intel collection (ngCERT + CIRCL + Feodo Tracker -> Nigeria heatmap +
// MISP). Each source degrades to zero independently — see nigerianIntelCollector.ts's header
// for which ones are actually reachable today.
startNigerianIntelJob();
// CIRCL pulse + Wazuh-derived MITRE technique sync — see jobs/globalIntelJob.ts.
startGlobalIntelJob();
