import 'dotenv/config';
import './lib/tlsGuard';
import './lib/envGuard';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { botProtection, requireAuth, requireRole } from './middleware/auth';
import { requirePermission, requireOrg } from './lib/permissions';

import authRouter from './routes/auth';
import portalRouter from './routes/portal';
import customersRouter from './routes/customers';
import complianceRouter from './routes/compliance';
import dnsRouter from './routes/dns';
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
import dataRecoveryRouter from './routes/dataRecovery';
import alertsRouter from './routes/alerts';
import alertStoreRouter from './routes/alertStore';
import ingestRouter from './routes/ingest';
import exportApiRouter from './routes/exportApi';
import exportClientsRouter from './routes/exportClients';
import pushStatusRouter from './routes/pushStatus';
import usersRouter from './routes/users';
import responseApprovalsRouter from './routes/responseApprovals';
import aiRouter from './routes/ai';
import vmsRouter from './routes/vms';
import vmsWorkerRouter from './routes/vmsWorker';
import vmsFindingsRouter from './routes/vmsFindings';
import threatInfoRouter from './routes/threatInfo';
import taxiiRouter from './routes/taxii';
import vmsImportRouter from './routes/vmsImport';
import vmsContinuousRouter from './routes/vmsContinuous';
import vmsAssessmentsRouter from './routes/vmsAssessments';
import vmsAdminRouter from './routes/vmsAdmin';
import vmsOperationsRouter from './routes/vmsOperations';
import vmsInsightsRouter from './routes/vmsInsights';
import vmsClientRouter from './routes/vmsClient';
import clientSecopsRouter from './routes/clientSecops';
import cniiNationalRouter from './routes/cniiNational';
import { adminRouter as orgAssignmentsRouter, mineRouter as orgAccessRouter } from './routes/orgAccess';
import insightsRouter from './routes/insights';
import wazuhGroupMapRouter from './routes/wazuhGroupMap';
import threatManagementRouter from './routes/threatManagement';
import publicRouter from './routes/public';
import intelligenceRouter from './routes/intelligence';
import casesRouter from './routes/cases';
import soarRouter from './routes/soar';
import searchRouter from './routes/search';
import testRouter from './routes/test';
import communicationsRouter from './routes/communications';
import teamRouter from './routes/team';
import { adminRouter as securityAssessmentAdminRouter, clientRouter as securityAssessmentClientRouter } from './routes/securityAssessment';
import assetsRouter from './routes/assets';
import dashboardRouter from './routes/dashboard';
import handoverRouter from './routes/handover';
import emailRouter from './routes/email';
import emailProxyRouter from './routes/emailProxy';
import mitreRouter from './routes/mitre';
import orgCTIRouter from './routes/orgCTI';
import cniiRouter from './routes/cnii';
import { runCTIWatcher } from './jobs/ctiWatcher';
import { startEscalationJob } from './jobs/incidentEscalation';
import { startNigerianIntelJob } from './jobs/nigerianIntelJob';
import { startGlobalIntelJob } from './jobs/globalIntelJob';
import { startEmailSecurityJob } from './jobs/emailSecurityJob';
import { startStellarPushJob } from './jobs/stellarPush';
import { startAutoCaseJob } from './jobs/autoCase';
import { startVmsMaintenanceJob } from './jobs/vmsMaintenance';
import { startVmsIntelJob } from './jobs/vmsIntelJob';
import { startThreatInfoJob } from './jobs/threatInfoJob';
import { startVmsContinuousJob } from './jobs/vmsContinuousJob';
import { startCniiPassiveJob } from './jobs/cniiPassiveJob';
import { announceJobPolicy } from './lib/runtimeEnv';
import { announceVerificationSecret } from './services/emailsec/verification';
import platformRouter from './routes/platform';
import organisationsRouter from './routes/organisations';
import onboardingRouter from './routes/onboarding';
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
    // The deployed commit (Railway sets RAILWAY_GIT_COMMIT_SHA, Render RENDER_GIT_COMMIT), so a
    // deployment can be confirmed from outside.
    res.status(200).json({ status: 'healthy', version: (process.env.RAILWAY_GIT_COMMIT_SHA || process.env.RENDER_GIT_COMMIT || '').slice(0, 12) || null });
});
app.get('/', (_req, res) => {
    res.status(200).json({ ok: true, service: 'novrsoc-backend' });
});

// Authentication is applied per mount below (or inside a router where a route has its own
// machine credential). Every data route needs a login: the routes that used to stay open so
// client-portal tokens could reach them were gated in phase P1 (2026-10-14), because portal
// sign-in proxies to APP_API_BASE_URL, which is not configured — no portal token exists for
// them to serve, while the open routes exposed the Wazuh agent list and paid lookups to anyone.
// When portal sign-in is rebuilt on this backend, its tokens go through requireAuth like
// any other. The few mounts that stay reachable without a login are listed, with their reason,
// in routes/__tests__/routeGating.test.ts, which fails if a new mount is added without a gate.

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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Org-Id'], // X-Org-Id: staff org selection (lib/resolveOrg.ts)
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
            connectSrc: ["'self'", 'https://*.supabase.co'],
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

// Machine alert ingest (routes/ingest.ts) is mounted before the global 100 KB JSON parser and the
// /api limiter: it authenticates with its own service token, parses up to 1 MB itself and has
// its own rate limit.
app.use('/api/ingest', ingestRouter);
// Vendor export (routes/exportApi.ts): machine credential, own kill switch and rate limits; GET only.
app.use('/api/export/v1', exportApiRouter);
// VMS scanner worker (routes/vmsWorker.ts): machine credential VMS_WORKER_TOKEN, own rate limit.
app.use('/api/vms/worker', express.json({ limit: '2mb' }), vmsWorkerRouter);
// TAXII 2.1 (routes/taxii.ts, phase P25): read-only threat-intelligence exchange; per-client HTTP
// Basic credentials, own rate limit, TAXII media types. Holds shared intelligence only.
app.use('/taxii2', taxiiRouter);
// VMS asset onboarding (routes/vmsImport.ts, phase P27): its own 1 MB parser for CSV imports.
app.use('/api/vms/import', requireAuth, express.json({ limit: '1mb' }), vmsImportRouter);

app.use(express.json());

// Rate limiting — auth endpoints get a tight per-IP window (stacks with the general limiter
// below); everything else gets the looser general one. skipSuccessfulRequests on the auth
// limiter means only *failed* attempts count toward the 10/15min cap, so a legitimate user
// who mistypes their password a couple of times before succeeding isn't penalised.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    // Presence heartbeats (every 2 min per signed-in user) must not use up the login budget.
    skip: (req) => req.path === '/heartbeat',
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
// admin-only.
// soc_manager gets access alongside super_admin here (and on /api/compliance below) — per the
// soc_manager role's spec: "Access compliance data for their org," but analysts and below do
// not get customer/compliance-admin access.
app.use('/api/customers', requireAuth, requireRole('super_admin', 'soc_manager'), customersRouter);
app.use('/api/compliance', requireAuth, requireRole('super_admin', 'soc_manager'), complianceRouter);
app.use('/api/dns', requireAuth, dnsRouter);
// admin-only — no client-portal component calls this, confirmed safe to gate now.
app.use('/api/novr-ai', requireAuth, novrAiRouter);
app.use('/api/wazuh', wazuhRouter);
app.use('/api/geo', requireAuth, geoRouter);
// F-01 containment: Brand Protection keeps every tenant's monitored domains/socials/executives/
// apps/signatures in shared, un-scoped in-memory stores (routes/brand.ts, routes/domainSuite.ts).
// Until that data is moved into per-organisation tables, access is staff-only — the client
// `executive` role (and portal_user, already excluded by requireAuth) must not reach it.
app.use('/api/brand/domains', requireAuth, requireRole('super_admin', 'soc_manager', 'analyst'), domainSuiteRouter);
app.use('/api/brand', requireAuth, requireRole('super_admin', 'soc_manager', 'analyst'), brandRouter);
app.use('/api/contact', contactRouter);
app.use('/api/threat', requireAuth, threatRouter);
app.use('/api/cti', requireAuth, ctiRouter);
app.use('/api/urlscan', requireAuth, urlscanRouter);
app.use('/api/webscan', requireAuth, webscanRouter);
// Email Security module (DMARC SaaS, Phish ID, Messaging Suite) — auth is per-route inside the
// router because the Microsoft 365 admin-consent callback must be reachable without a token.
app.use('/api/email-security', emailSecurityRouter);
// Platform notification email (status, test, alert, weekly report) plus the Mailgun DMARC
// report inbox, which hands reports to the Email Security module.
app.use('/api/email', emailRouter);
app.use('/api/email-proxy', emailProxyRouter);
app.use('/api/mitre', mitreRouter);
// Backup agents report from cron with no user session, so POST /jobs/report stays reachable
// without a login (it can only upsert a reporting row); every read needs a login.
app.use('/api/recovery', (req, res, next) => (req.method === 'POST' && req.path === '/jobs/report' ? next() : requireAuth(req, res, next)), dataRecoveryRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/alerts', alertStoreRouter); // stored, org-scoped alerts (phase R2)
app.use('/api/threats', threatManagementRouter);
// STIX export — gated: a bundle is the org's whole accumulated IOC set in one file.
app.use('/api/intelligence', requireAuth, intelligenceRouter);
// Cases (Supabase). Analyst-only: case records carry source IPs, host names
// and CISO escalations for the whole SOC. The client portal's case page shows a sign-in notice
// instead (see routes/cases.ts).
app.use('/api/cases', requireAuth, casesRouter);
// SOAR reporting (requireAuth per route) + the engine's token-authenticated /enrich.
app.use('/api/soar', soarRouter);
// Header global search (requireAuth inside) and operator diagnostics (manager-only inside).
app.use('/api/search', searchRouter);
app.use('/api/test', testRouter);
// Alert Communication: compose/send + log. Analyst-only.
app.use('/api/communications', requireAuth, communicationsRouter);
// Team presence (Settings → Team, Security Assessment widget).
app.use('/api/admin/team', requireAuth, teamRouter);
app.use('/api/admin/wazuh-group-map', requireAuth, requireRole('super_admin'), wazuhGroupMapRouter);
app.use('/api/admin/export-clients', requireAuth, requireRole('super_admin'), exportClientsRouter);
app.use('/api/admin/push-status', requireAuth, requireRole('super_admin'), pushStatusRouter);
app.use('/api/admin/users', requireAuth, requireRole('super_admin'), usersRouter);
// Consequential response actions wait here for a manager's approval — services/responseApprovals.ts.
app.use('/api/response-approvals', requireAuth, responseApprovalsRouter);
// AI analysis (services/ai.ts, NVIDIA via services/nvidia.ts). Advice only: never changes records or runs actions.
app.use('/api/ai', requireAuth, aiRouter);
// Vulnerability Management (routes/vms.ts) — attack surface, scope, scans.
app.use('/api/vms', requireAuth, vmsRouter);
app.use('/api/vms', requireAuth, vmsFindingsRouter); // findings, remediation (phase P5)
app.use('/api/vms', requireAuth, vmsContinuousRouter); // schedules, trends, reports, notifications (phase P7)
app.use('/api/vms', requireAuth, vmsAssessmentsRouter); // asset-centric Full Assessment (phase P13)
app.use('/api/vms', requireAuth, vmsAdminRouter); // VMS administration: policies, workers, integrations (phase P14)
app.use('/api/vms', requireAuth, vmsOperationsRouter); // profiles, scanner operations, services, endpoint eligibility (phase P19)
app.use('/api/vms', requireAuth, vmsInsightsRouter); // read-only dashboard, risk, audit, task and AI-plan views (phase P20)
// Client VMS portal (phase P21): a client's own organisation, read-only; the only API a portal_user may use.
app.use('/api/client/vms', requireAuth, vmsClientRouter);
// Client portal: the organisation's own alerts, firewall activity and agents (phase P24).
app.use('/api/client/secops', requireAuth, clientSecopsRouter);
// Analyst organisation assignments (P21): managed by super_admin; /mine lists what the caller may view.
app.use('/api/admin/org-assignments', requireAuth, requireRole('super_admin'), orgAssignmentsRouter);
app.use('/api/org-access', requireAuth, orgAccessRouter);
app.use('/api/ti', requireAuth, threatInfoRouter); // Threat Information System (phase P6)
app.use('/api/insights', requireAuth, insightsRouter); // weekly insights (phase P8)
// Security Assessment: posture from real case data.
app.use('/api/admin/security-assessment', requireAuth, securityAssessmentAdminRouter);
app.use('/api/client/security-assessment', requireAuth, securityAssessmentClientRouter);
// Wazuh agent inventory (names, IPs, OS): same gate as /api/wazuh/agents.
app.use('/api/assets', requirePermission('alerts:read'), assetsRouter);
// admin-only.
app.use('/api/dashboard', requireAuth, dashboardRouter);
app.use('/api/handover', requireAuth, handoverRouter);
app.use('/api/org-cti', requireAuth, requireOrg, orgCTIRouter);
// CNII Watch — admin-only (no client-portal page uses it). Role checks per route inside.
// CNII national intelligence (P23): read-only drill-down over profiled organisations the caller may view.
app.use('/api/cnii/national', requireAuth, cniiNationalRouter);
app.use('/api/cnii', requireAuth, cniiRouter);
// super_admin only — platform infra health is explicitly out of scope for soc_manager per that
// role's spec ("Cannot access platform settings").
app.use('/api/platform', requireAuth, requireRole('super_admin'), platformRouter);
// Just requireAuth here, not requireRole — organisationsRouter's own routes each apply their own
// role requirement (list/create orgs: super_admin only; update/team management: super_admin or
// soc_manager per the customer-onboarding + multitenancy spec; a user reading their own org: any
// authenticated role). A single router-level role would force all of those to the same tier.
app.use('/api/organisations', requireAuth, organisationsRouter);
app.use('/api/admin/onboarding', requireAuth, requireRole('super_admin', 'soc_manager'), onboardingRouter);
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

// (No auto-close job: the SOAR engine closes tier-1 cases as it creates them — infra/soar.)
// The jobs below WRITE (database, MISP, email). They start only in production or against a
// declared development/test database — see lib/runtimeEnv.ts. The CTI watcher above only reads
// Wazuh into memory, so it always runs.
announceVerificationSecret();
if (announceJobPolicy()) {
    // Escalation emails for unresolved HIGH/CRITICAL cases — see jobs/incidentEscalation.ts.
    // No-ops (with a log line) when the case store isn't configured.
    startEscalationJob();
    // Hourly Nigerian threat-intel collection (ngCERT + CIRCL + Feodo Tracker -> Nigeria heatmap +
    // MISP). Each source degrades to zero independently — see nigerianIntelCollector.ts's header
    // for which ones are actually reachable today.
    startNigerianIntelJob();
    // CIRCL pulse + Wazuh-derived MITRE technique sync — see jobs/globalIntelJob.ts.
    startGlobalIntelJob();
    // DMARC DNS checks, Phish ID discovery/enrichment, mail-provider sync — jobs/emailSecurityJob.ts.
    startEmailSecurityJob();
    // Push stored alerts to Stellar Cyber's webhook — jobs/stellarPush.ts. Off unless
    // STELLAR_PUSH_ENABLED=true and its URL, key and org list are set.
    startStellarPushJob();
    // Open cases from stored alerts by documented rules — jobs/autoCase.ts. Off unless
    // AUTO_CASE_ENABLED=true.
    startAutoCaseJob();
    // VMS scan queue upkeep: dead workers' jobs requeued/failed, expired-scope jobs cancelled.
    startVmsMaintenanceJob();
    // CVE intelligence (KEV, EPSS, NVD) and the Wazuh vulnerability sync — jobs/vmsIntelJob.ts.
    startVmsIntelJob();
    // Threat feeds (abuse.ch, CISA KEV), expiry and correlation — jobs/threatInfoJob.ts.
    startThreatInfoJob();
    // Scan schedules, daily risk snapshots and change digests — jobs/vmsContinuousJob.ts.
    startVmsContinuousJob();
    // CNII passive collection (SpiderFoot passive modules, CT logs, DNS, RIPE Stat, OpenCTI) for
    // passive_osint jobs in the VMS queue — jobs/cniiPassiveJob.ts. Off with CNII_PASSIVE_ENABLED=false.
    startCniiPassiveJob();
}
