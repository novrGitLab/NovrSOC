// /api/cnii/national — CNII Watch national intelligence (phase P23). Read-only.
//
//   GET /                         national overview: KPIs, charts, every configured sector
//   GET /sectors/:sector          one sector: organisations, severities, most vulnerable assets
//   GET /orgs/:org                one organisation: monitoring, risk, assets, findings, remediation
//   GET /orgs/:org/assets/:id     one asset: findings with CVE / CVSS / contextual risk, evidence, history
//
// What is counted. An organisation belongs to CNII only through its recorded CNII profile
// (cnii_org_profiles: sector set by a manager, designation "designated" or "candidate"); nothing is
// inferred from names or domains. Its assets and findings are its own VMS records — CNII keeps no
// copy. Designation is shown everywhere and ?designated=1 restricts every figure to designated ones.
//
// Who sees what. cnii:sector (staff). The figures cover only the organisations the caller may act on:
// super_admin and soc_manager every profiled organisation; an analyst its own plus those it is
// assigned to (staff_org_assignments, as lib/resolveOrg.ts enforces for X-Org-Id). An organisation
// outside that set is 404, and is never counted. Viewing another organisation is audited.
//
// Risk. "Infrastructure risk" is the mean NovrSOC contextual risk score (lib/riskScore.ts, 0–100) of
// open non-informational findings, with the highest score beside it — never an average of CVSS. CVSS
// is the scanner's severity and is reported separately. History comes from the daily risk
// snapshots only; days without a snapshot are absent, never filled.

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { logAudit } from '../lib/audit';
import { isUuid } from '../services/cases';
import { CNII_SECTORS, SECTOR_BY_ID } from '../lib/cnii-sectors';
import { coverageState, tallyCoverage, type CoverageState } from '../lib/cniiCoverage';
import { mostRestrictive, type Tlp } from '../services/tiPolicy';

const router = Router();
const OPEN = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const DAY = 86_400_000;
const can = requirePermission('cnii:sector');
const db = () => getSupabase()!;

type Profile = { org_id: string; sector_id: string; subfield: string | null; designation: string; designation_reference?: string | null; updated_at?: string | null };
type Asset = { id: string; org_id: string; value: string; asset_type: string; exposure: string; criticality: string; first_seen: string; last_seen: string; last_assessed_at?: string | null };
type Finding = { id: string; org_id: string; asset_id: string | null; asset_value: string; port: number | null; title: string; rule_id: string; cve_ids: string[] | null; scanner_severity: string; scanner_cvss: number | null; risk_score: number | null; priority: string | null; status: string; detected_by: string[] | null; source_class: string | null; first_seen: string; last_seen: string; due_at: string | null; verified_at: string | null; evidence_class?: string | null };

/** The organisations this caller may see: 'all', or a set of slugs. */
async function visibility(req: AuthRequest): Promise<{ mode: 'all' | 'assigned'; slugs: Set<string> | null }> {
    const role = req.user?.role;
    if (role === 'super_admin' || role === 'soc_manager') return { mode: 'all', slugs: null };
    const own = req.user?.org_id ? [req.user.org_id] : [];
    const { data, error } = await db().from('staff_org_assignments').select('org_slug').eq('user_id', req.user?.sub ?? '').limit(2000);
    return { mode: 'assigned', slugs: new Set([...own, ...(error ? [] : (data ?? []).map((r) => r.org_slug as string))]) };
}

async function loadProfiles(req: AuthRequest, opts: { sector?: string; org?: string } = {}) {
    const vis = await visibility(req);
    let q = db().from('cnii_org_profiles').select('*').order('org_id');
    if (opts.sector) q = q.eq('sector_id', opts.sector);
    if (opts.org) q = q.eq('org_id', opts.org);
    const { data, error } = await q;
    if (error) return { error, profiles: [] as Profile[], vis };
    let profiles = (data ?? []) as Profile[];
    if (vis.slugs) profiles = profiles.filter((p) => vis.slugs!.has(p.org_id));
    if (req.query.designated === '1') profiles = profiles.filter((p) => p.designation === 'designated');
    return { error: null, profiles, vis };
}

interface TiMatchRow { org_id: string; entity_id: string; status: string; case_id: string | null; indicator_id: string; indicator: { id: string; type: string; value: string; max_confidence: number | null; malware_families: string[] | null; threat_types: string[] | null; status: string | null } | null }

/** Threat Intelligence correlation (R3.3B Stage 4) — the same entity_type='asset' join
 * routes/cnii.ts's /assets/:id already uses for a single organisation, read here for any set of
 * asset ids. 'dismissed' matches are an analyst's verdict that the match isn't relevant and are
 * excluded; everything else is kept, with 'promoted' or a linked case_id treated as a verified
 * association and 'new'/'reviewed' as contextual/possible only — a shared indicator or CVE
 * appearing is never itself proof an actor attacked the asset. TLP is the most restrictive marking
 * among an indicator's sources (services/tiPolicy.ts mostRestrictive) — an indicator with no
 * source row is treated the same conservative way tlpFromTags() treats an untagged record. */
async function loadTi(assetIds: string[]) {
    const tiByAsset = new Map<string, TiMatchRow[]>();
    const tlpByIndicator = new Map<string, Tlp>();
    if (!assetIds.length) return { tiByAsset, tlpByIndicator };
    const { data: matches } = await db().from('ti_matches')
        .select('org_id, entity_id, status, case_id, indicator_id, ti_indicators(id, type, value, max_confidence, malware_families, threat_types, status)')
        .eq('entity_type', 'asset').in('entity_id', assetIds).neq('status', 'dismissed').limit(20_000);
    for (const m of (matches ?? []) as unknown as (Omit<TiMatchRow, 'indicator'> & { ti_indicators: TiMatchRow['indicator'] })[]) {
        const row: TiMatchRow = { org_id: m.org_id, entity_id: m.entity_id, status: m.status, case_id: m.case_id, indicator_id: m.indicator_id, indicator: m.ti_indicators };
        const list = tiByAsset.get(m.entity_id) ?? [];
        list.push(row);
        tiByAsset.set(m.entity_id, list);
    }
    const indicatorIds = [...new Set([...tiByAsset.values()].flat().map((m) => m.indicator_id))];
    if (indicatorIds.length) {
        const { data: sources } = await db().from('ti_indicator_sources').select('indicator_id, tlp').in('indicator_id', indicatorIds).limit(20_000);
        const byIndicator = new Map<string, Tlp[]>();
        for (const s of sources ?? []) byIndicator.set(s.indicator_id, [...(byIndicator.get(s.indicator_id) ?? []), s.tlp as Tlp]);
        for (const id of indicatorIds) tlpByIndicator.set(id, byIndicator.has(id) ? mostRestrictive(byIndicator.get(id)!) : 'amber');
    }
    return { tiByAsset, tlpByIndicator };
}

/** VMS (and, R3.3B, Threat Intelligence) records of the given organisations, read once. */
async function loadRecords(orgIds: string[]) {
    if (!orgIds.length) {
        return {
            assets: [] as Asset[], findings: [] as Finding[], scopes: [] as { org_id: string; expires_at: string }[], kev: new Set<string>(),
            lastCollection: new Map<string, { at: string; status: string }>(), tiByAsset: new Map<string, TiMatchRow[]>(), tlpByIndicator: new Map<string, Tlp>(),
        };
    }
    const now = new Date().toISOString();
    const [assets, findings, scopes, collections] = await Promise.all([
        db().from('vms_assets').select('*').in('org_id', orgIds).eq('status', 'active').limit(50_000),
        db().from('vms_findings').select('*').in('org_id', orgIds).in('status', OPEN).limit(50_000),
        db().from('vms_scopes').select('org_id, expires_at').in('org_id', orgIds).eq('status', 'active').gt('expires_at', now),
        // Same passive-collection signal routes/cnii.ts's orgStats() already uses for its own
        // monitoring gaps, read here too so the national/sector view carries the same coverage
        // state instead of its previous binary "has a scope" pill.
        db().from('vms_scan_jobs').select('org_id, finished_at, status').in('org_id', orgIds).eq('kind', 'passive_osint').not('finished_at', 'is', null).order('finished_at', { ascending: false }).limit(5000),
    ]);
    if (assets.error) throw assets.error;
    if (findings.error) throw findings.error;
    const cves = [...new Set((findings.data ?? []).flatMap((f) => f.cve_ids ?? []))];
    const kev = new Set<string>();
    for (let i = 0; i < cves.length; i += 200) {
        const { data } = await db().from('cve_intel').select('cve_id').eq('kev', true).in('cve_id', cves.slice(i, i + 200));
        for (const k of data ?? []) kev.add(k.cve_id);
    }
    const lastCollection = new Map<string, { at: string; status: string }>();
    for (const r of collections.data ?? []) if (!lastCollection.has(r.org_id)) lastCollection.set(r.org_id, { at: r.finished_at!, status: r.status });
    const { tiByAsset, tlpByIndicator } = await loadTi((assets.data ?? []).map((a) => a.id as string));
    return { assets: (assets.data ?? []) as Asset[], findings: (findings.data ?? []) as Finding[], scopes: scopes.data ?? [], kev, lastCollection, tiByAsset, tlpByIndicator };
}

const sevCounts = (fs: Finding[]) => Object.fromEntries(SEVERITIES.map((s) => [s, fs.filter((f) => f.scanner_severity === s).length])) as Record<string, number>;
const prioCounts = (fs: Finding[]) => Object.fromEntries(['P1', 'P2', 'P3', 'P4'].map((p) => [p, fs.filter((f) => f.priority === p).length]));
function risk(fs: Finding[]) {
    const scored = fs.filter((f) => f.scanner_severity !== 'info' && typeof f.risk_score === 'number').map((f) => Number(f.risk_score));
    return { mean: scored.length ? Math.round((scored.reduce((a, b) => a + b, 0) / scored.length) * 10) / 10 : null, max: scored.length ? Math.max(...scored) : null, scored: scored.length };
}
const attention = (f: Finding, kev: Set<string>) => f.scanner_severity === 'critical' || f.scanner_severity === 'high' || f.priority === 'P1' || f.priority === 'P2' || (f.cve_ids ?? []).some((c) => kev.has(c));
function sources(fs: Finding[]) {
    const m: Record<string, number> = {};
    for (const f of fs) for (const d of f.source_class === 'wazuh' ? ['wazuh'] : (f.detected_by ?? []).length ? f.detected_by! : ['unknown']) m[d] = (m[d] ?? 0) + 1;
    return m;
}
/** Verified (promoted, or linked to a case) vs contextual-only (new/reviewed) counts for an
 * organisation's assets — never a single merged "threat matches" number, per R3.3B Stage 4. */
function tiSummary(assetIds: string[], recs: Awaited<ReturnType<typeof loadRecords>>) {
    const rows = assetIds.flatMap((id) => recs.tiByAsset.get(id) ?? []);
    const verified = rows.filter((m) => m.status === 'promoted' || !!m.case_id);
    return { total: rows.length, verified: verified.length, contextual: rows.length - verified.length };
}
function orgSummary(slug: string, recs: Awaited<ReturnType<typeof loadRecords>>) {
    const assets = recs.assets.filter((a) => a.org_id === slug);
    const open = recs.findings.filter((f) => f.org_id === slug);
    const vulns = open.filter((f) => f.scanner_severity !== 'info');
    const since30 = Date.now() - 30 * DAY;
    const assessed = assets.filter((a) => a.last_assessed_at && Date.parse(a.last_assessed_at) > since30).length;
    const needing = new Set(open.filter((f) => f.asset_id && attention(f, recs.kev)).map((f) => f.asset_id));
    const activeScopes = recs.scopes.filter((s) => s.org_id === slug).length;
    const lastCollection = recs.lastCollection.get(slug) ?? null;
    return {
        assets: assets.length, internet_facing: assets.filter((a) => a.exposure === 'internet').length,
        open_findings: open.length, open_vulnerabilities: vulns.length, severity: sevCounts(open), priority: prioCounts(open),
        critical_high: open.filter((f) => f.scanner_severity === 'critical' || f.scanner_severity === 'high').length,
        kev_open: open.filter((f) => (f.cve_ids ?? []).some((c) => recs.kev.has(c))).length,
        risk: risk(open), assets_requiring_attention: needing.size,
        monitoring: { active_scopes: activeScopes, assets_assessed_30d: assessed, last_collection: lastCollection },
        coverage_state: coverageState({ active_scopes: activeScopes, last_collection: lastCollection }) as CoverageState,
        threat_intelligence: tiSummary(assets.map((a) => a.id), recs),
    };
}
function topAssets(recs: Awaited<ReturnType<typeof loadRecords>>, names: Map<string, string>, limit = 10) {
    const per = new Map<string, { asset_id: string; org_id: string; value: string; open: number; severity: Record<string, number>; max_risk: number; kev: number }>();
    for (const f of recs.findings) {
        if (!f.asset_id) continue;
        const e = per.get(f.asset_id) ?? { asset_id: f.asset_id, org_id: f.org_id, value: f.asset_value, open: 0, severity: {}, max_risk: 0, kev: 0 };
        e.open++; e.severity[f.scanner_severity] = (e.severity[f.scanner_severity] ?? 0) + 1; e.max_risk = Math.max(e.max_risk, Number(f.risk_score ?? 0));
        if ((f.cve_ids ?? []).some((c) => recs.kev.has(c))) e.kev++;
        per.set(f.asset_id, e);
    }
    const W: Record<string, number> = { critical: 1000, high: 100, medium: 10, low: 1 };
    const w = (x: { severity: Record<string, number> }) => Object.entries(x.severity).reduce((n, [s, c]) => n + (W[s] ?? 0) * c, 0);
    const byId = new Map(recs.assets.map((a) => [a.id, a]));
    return [...per.values()].sort((a, b) => b.max_risk - a.max_risk || w(b) - w(a)).slice(0, limit)
        .map((x) => ({ ...x, organisation: names.get(x.org_id) ?? x.org_id, asset_type: byId.get(x.asset_id)?.asset_type ?? null, exposure: byId.get(x.asset_id)?.exposure ?? null, criticality: byId.get(x.asset_id)?.criticality ?? null }));
}
async function orgNames(slugs: string[]) {
    if (!slugs.length) return new Map<string, string>();
    const { data } = await db().from('organisations').select('slug, name').in('slug', slugs);
    return new Map((data ?? []).map((o) => [o.slug as string, o.name as string]));
}
const DEFINITIONS = {
    infrastructure_risk: 'Mean NovrSOC contextual risk score (0–100) of open non-informational findings on monitored assets, with the highest score beside it. It weighs CVSS 45%, exploitation evidence (KEV, EPSS) 30%, exposure 15% and asset criticality 10% — it is not an average of CVSS.',
    assets_requiring_attention: 'Assets with at least one open critical or high finding, a P1/P2 finding, or a CVE in the CISA KEV catalogue.',
    monitoring_coverage: 'Organisations with real, recent evidence of collection — an authorised scope alone is not enough. "Connected — stale" (collection ran, but not within 8 days) and "configured — not yet receiving data" (a scope exists but nothing has ever been collected) are shown apart, never counted as covered.',
    organisations: 'Organisations with a recorded CNII profile (sector set by a manager). Candidates are classified but not yet formally designated.',
};

// ── National overview ─────────────────────────────────────────────────────────────────────────
router.get('/', can, async (req: AuthRequest, res) => {
    const { error, profiles, vis } = await loadProfiles(req);
    if (error) { res.status(503).json({ error: 'CNII profiles are not available' }); return; }
    try {
        const slugs = profiles.map((p) => p.org_id);
        const [recs, names, snaps] = await Promise.all([
            loadRecords(slugs), orgNames(slugs),
            slugs.length ? db().from('vms_risk_snapshots').select('org_id, day, open_total, open_by_priority, kev_open, internet_open, risk_mean, critical_exposures').in('org_id', slugs).gte('day', new Date(Date.now() - 90 * DAY).toISOString().slice(0, 10)).order('day').limit(10_000) : Promise.resolve({ data: [] }),
        ]);
        const orgCoverage = (orgId: string): CoverageState =>
            coverageState({ active_scopes: recs.scopes.filter((s) => s.org_id === orgId).length, last_collection: recs.lastCollection.get(orgId) ?? null });
        const sectorCards = CNII_SECTORS.map((sec) => {
            const orgs = profiles.filter((p) => p.sector_id === sec.id);
            const ids = new Set(orgs.map((o) => o.org_id));
            const fs = recs.findings.filter((f) => ids.has(f.org_id));
            const assets = recs.assets.filter((a) => ids.has(a.org_id));
            return {
                id: sec.id, organisations: orgs.length, designated: orgs.filter((o) => o.designation === 'designated').length, candidates: orgs.filter((o) => o.designation !== 'designated').length,
                assets: assets.length, open_vulnerabilities: fs.filter((f) => f.scanner_severity !== 'info').length,
                critical_high: fs.filter((f) => f.scanner_severity === 'critical' || f.scanner_severity === 'high').length,
                severity: sevCounts(fs), priority: prioCounts(fs), risk: risk(fs),
                // R3.3B Stage 2/5: the five-state model, not a binary "monitored" pill — a never-
                // collected or stale organisation is never counted the same as a fresh one.
                coverage: tallyCoverage(orgs.map((o) => orgCoverage(o.org_id))),
                threat_intelligence: tiSummary(assets.map((a) => a.id), recs),
            };
        });
        const vulns = recs.findings.filter((f) => f.scanner_severity !== 'info');
        const needing = new Set(recs.findings.filter((f) => f.asset_id && attention(f, recs.kev)).map((f) => f.asset_id));
        const coverage = tallyCoverage(profiles.map((p) => orgCoverage(p.org_id)));
        // History: per day, summed over the organisations that recorded a snapshot that day.
        const byDay = new Map<string, { day: string; open_total: number; kev_open: number; internet_open: number; organisations: number }>();
        for (const s of snaps.data ?? []) {
            const e = byDay.get(s.day) ?? { day: s.day, open_total: 0, kev_open: 0, internet_open: 0, organisations: 0 };
            e.open_total += s.open_total ?? 0; e.kev_open += s.kev_open ?? 0; e.internet_open += s.internet_open ?? 0; e.organisations++;
            byDay.set(s.day, e);
        }
        res.json({
            visibility: { mode: vis.mode, organisations: profiles.length, designated_only: req.query.designated === '1' },
            definitions: DEFINITIONS,
            kpis: {
                sectors_configured: CNII_SECTORS.length, sectors_monitored: sectorCards.filter((s) => s.organisations > 0).length,
                organisations: profiles.length, designated: profiles.filter((p) => p.designation === 'designated').length,
                assets: recs.assets.length, open_vulnerabilities: vulns.length,
                critical: recs.findings.filter((f) => f.scanner_severity === 'critical').length, high: recs.findings.filter((f) => f.scanner_severity === 'high').length,
                kev_open: recs.findings.filter((f) => (f.cve_ids ?? []).some((c) => recs.kev.has(c))).length,
                risk: risk(recs.findings), assets_requiring_attention: needing.size,
                coverage: { organisations_scoped: coverage.by_state.connected_fresh + coverage.by_state.connected_stale, organisations: profiles.length, pct: coverage.connected_pct, by_state: coverage.by_state },
            },
            severity: sevCounts(recs.findings),
            priority: prioCounts(recs.findings),
            sources: sources(recs.findings),
            trend: [...byDay.values()],
            sectors: sectorCards,
            organisations: profiles.map((p) => ({ slug: p.org_id, name: names.get(p.org_id) ?? p.org_id, sector: p.sector_id, subfield: p.subfield, designation: p.designation, ...orgSummary(p.org_id, recs) })),
            top_assets: topAssets(recs, names, 8),
        });
    } catch { res.status(502).json({ error: 'Could not read CNII records' }); }
});

// ── Sector ────────────────────────────────────────────────────────────────────────────────────
router.get('/sectors/:sector', can, async (req: AuthRequest, res) => {
    const sector = req.params.sector;
    if (!SECTOR_BY_ID[sector]) { res.status(404).json({ error: 'Unknown sector' }); return; }
    const { error, profiles, vis } = await loadProfiles(req, { sector });
    if (error) { res.status(503).json({ error: 'CNII profiles are not available' }); return; }
    try {
        const slugs = profiles.map((p) => p.org_id);
        const [recs, names] = await Promise.all([loadRecords(slugs), orgNames(slugs)]);
        const orgs = profiles.map((p) => ({ slug: p.org_id, name: names.get(p.org_id) ?? p.org_id, subfield: p.subfield, designation: p.designation, ...orgSummary(p.org_id, recs) }));
        const needing = new Set(recs.findings.filter((f) => f.asset_id && attention(f, recs.kev)).map((f) => f.asset_id));
        res.json({
            sector, visibility: { mode: vis.mode, organisations: profiles.length }, definitions: DEFINITIONS,
            kpis: {
                organisations: profiles.length, designated: profiles.filter((p) => p.designation === 'designated').length, assets: recs.assets.length,
                internet_facing: recs.assets.filter((a) => a.exposure === 'internet').length,
                open_vulnerabilities: recs.findings.filter((f) => f.scanner_severity !== 'info').length,
                kev_open: recs.findings.filter((f) => (f.cve_ids ?? []).some((c) => recs.kev.has(c))).length,
                risk: risk(recs.findings), assets_requiring_attention: needing.size,
                coverage: { organisations_scoped: orgs.filter((o) => o.monitoring.active_scopes > 0).length, assets_assessed_30d: orgs.reduce((n, o) => n + o.monitoring.assets_assessed_30d, 0), by_state: tallyCoverage(orgs.map((o) => o.coverage_state)).by_state },
            },
            severity: sevCounts(recs.findings), priority: prioCounts(recs.findings), sources: sources(recs.findings),
            organisations: orgs,
            top_assets: topAssets(recs, names, 10),
        });
    } catch { res.status(502).json({ error: 'Could not read CNII records' }); }
});

/** The organisation's CNII profile, if the caller may see it; else null (→ 404, never "forbidden"). */
async function visibleProfile(req: AuthRequest, org: string): Promise<Profile | null> {
    if (!/^[a-z0-9][a-z0-9-]{0,99}$/i.test(org)) return null;
    const { profiles } = await loadProfiles(req, { org });
    const p = profiles[0] ?? null;
    if (p && org !== req.user?.org_id) logAudit({ user: req.user?.email ?? 'unknown', action: 'CNII_ORG_VIEW', resource: `${req.method} ${(req.originalUrl || req.url).split('?')[0].slice(0, 200)}`, resource_id: org, org_id: org, ip: req.ip ?? 'unknown', result: 'success' });
    return p;
}

// ── Organisation ──────────────────────────────────────────────────────────────────────────────
router.get('/orgs/:org', can, async (req: AuthRequest, res) => {
    const p = await visibleProfile(req, req.params.org);
    if (!p) { res.status(404).json({ error: 'No CNII organisation by that name that you may view' }); return; }
    try {
        const recs = await loadRecords([p.org_id]);
        const [names, tasks, closed, lastJob, snaps] = await Promise.all([
            orgNames([p.org_id]),
            db().from('vms_remediation_tasks').select('status').eq('org_id', p.org_id).limit(5000),
            db().from('vms_findings').select('status').eq('org_id', p.org_id).in('status', ['verified', 'risk_accepted', 'false_positive']).limit(20_000),
            db().from('vms_scan_jobs').select('kind, status, finished_at').eq('org_id', p.org_id).not('finished_at', 'is', null).order('finished_at', { ascending: false }).limit(1).maybeSingle(),
            // Same daily snapshot the national overview reads, scoped to this one organisation —
            // for the Executive report's "historical trends where data exists" (R3.3B Stage 6).
            // Absent days stay absent, never filled, same as the national trend's own rule.
            db().from('vms_risk_snapshots').select('day, open_total, kev_open, internet_open, risk_mean, critical_exposures').eq('org_id', p.org_id).gte('day', new Date(Date.now() - 90 * DAY).toISOString().slice(0, 10)).order('day').limit(1000),
        ]);
        const per = new Map<string, { open: number; severity: Record<string, number>; max_risk: number | null }>();
        for (const f of recs.findings) {
            if (!f.asset_id) continue;
            const e = per.get(f.asset_id) ?? { open: 0, severity: {}, max_risk: null };
            e.open++; e.severity[f.scanner_severity] = (e.severity[f.scanner_severity] ?? 0) + 1;
            if (typeof f.risk_score === 'number') e.max_risk = Math.max(e.max_risk ?? 0, f.risk_score);
            per.set(f.asset_id, e);
        }
        const tally = (xs: { status: string }[]) => xs.reduce<Record<string, number>>((m, x) => { m[x.status] = (m[x.status] ?? 0) + 1; return m; }, {});
        const cves = [...new Set(recs.findings.flatMap((f) => f.cve_ids ?? []))].sort();
        res.json({
            organisation: { slug: p.org_id, name: names.get(p.org_id) ?? p.org_id, sector: p.sector_id, subfield: p.subfield, designation: p.designation, designation_reference: p.designation_reference ?? null, profile_updated_at: p.updated_at ?? null },
            definitions: DEFINITIONS,
            summary: orgSummary(p.org_id, recs),
            monitoring: { active_scopes: recs.scopes.length, last_scan: lastJob.data ?? null },
            remediation: { findings_open_by_status: tally(recs.findings), findings_closed_by_status: tally(closed.data ?? []), tasks_by_status: tally(tasks.data ?? []) },
            sources: sources(recs.findings),
            cves: cves.map((c) => ({ cve_id: c, kev: recs.kev.has(c), findings: recs.findings.filter((f) => (f.cve_ids ?? []).includes(c)).length })),
            assets: recs.assets.map((a) => ({ id: a.id, value: a.value, asset_type: a.asset_type, exposure: a.exposure, criticality: a.criticality, last_seen: a.last_seen, last_assessed_at: a.last_assessed_at ?? null, findings: per.get(a.id) ?? { open: 0, severity: {}, max_risk: null }, threat_intelligence: tiSummary([a.id], recs) })),
            findings: recs.findings.map((f) => ({ id: f.id, asset_id: f.asset_id, asset_value: f.asset_value, port: f.port, title: f.title, rule_id: f.rule_id, cve_ids: f.cve_ids ?? [], scanner_cvss: f.scanner_cvss, risk_score: f.risk_score, priority: f.priority, severity: f.scanner_severity, status: f.status, detected_by: f.source_class === 'wazuh' ? ['wazuh'] : f.detected_by ?? [], kev: (f.cve_ids ?? []).some((c) => recs.kev.has(c)), first_seen: f.first_seen, last_seen: f.last_seen, due_at: f.due_at, evidence_class: f.evidence_class ?? null })),
            trend: snaps.data ?? [],
        });
    } catch { res.status(502).json({ error: 'Could not read CNII records' }); }
});

// ── Asset ─────────────────────────────────────────────────────────────────────────────────────
router.get('/orgs/:org/assets/:id', can, async (req: AuthRequest, res) => {
    const p = await visibleProfile(req, req.params.org);
    if (!p || !isUuid(req.params.id)) { res.status(404).json({ error: 'Not found' }); return; }
    const { data: a } = await db().from('vms_assets').select('*').eq('id', req.params.id).eq('org_id', p.org_id).maybeSingle();
    if (!a) { res.status(404).json({ error: 'Not found' }); return; }
    const [findings, names] = await Promise.all([
        db().from('vms_findings').select('*').eq('org_id', p.org_id).eq('asset_id', a.id).order('risk_score', { ascending: false, nullsFirst: false }).limit(500),
        orgNames([p.org_id]),
    ]);
    const fs = (findings.data ?? []) as (Finding & { description: string | null; remediation: string | null })[];
    const ids = fs.map((f) => f.id);
    const [evidence, events, intel, tasks, ti] = await Promise.all([
        ids.length ? db().from('vms_finding_evidence').select('finding_id, source, observed_at, matched_at, evidence').eq('org_id', p.org_id).in('finding_id', ids).order('observed_at', { ascending: false }).limit(2000) : Promise.resolve({ data: [] }),
        ids.length ? db().from('vms_finding_events').select('finding_id, at, action, from_value, to_value').eq('org_id', p.org_id).in('finding_id', ids).in('action', ['detected', 'status', 'verified', 'reopened', 'verification_queued']).order('at').limit(2000) : Promise.resolve({ data: [] }),
        (() => { const c = [...new Set(fs.flatMap((f) => f.cve_ids ?? []))]; return c.length ? db().from('cve_intel').select('cve_id, kev, epss_score, cvss_score').in('cve_id', c.slice(0, 200)) : Promise.resolve({ data: [] }); })(),
        ids.length ? db().from('vms_remediation_tasks').select('finding_id, title, status, due_at').eq('org_id', p.org_id).in('finding_id', ids).neq('status', 'cancelled') : Promise.resolve({ data: [] }),
        loadTi([a.id]),
    ]);
    const intelBy = new Map((intel.data ?? []).map((c) => [c.cve_id as string, c]));
    const tiRows = ti.tiByAsset.get(a.id) ?? [];
    res.json({
        organisation: { slug: p.org_id, name: names.get(p.org_id) ?? p.org_id, sector: p.sector_id, designation: p.designation },
        asset: { id: a.id, value: a.value, asset_type: a.asset_type, exposure: a.exposure, criticality: a.criticality, hostnames: a.hostnames ?? [], ips: a.ips ?? [], discovery_sources: a.discovery_sources ?? [], first_seen: a.first_seen, last_seen: a.last_seen, last_assessed_at: a.last_assessed_at ?? null, last_assessment: a.last_assessment ?? null },
        // R3.3B Stage 4: each match keeps its own verdict distinction — 'promoted' or a linked
        // case means an analyst confirmed it, 'new'/'reviewed' is contextual only, never implied
        // to be a confirmed attack on this asset.
        threat_intelligence: tiRows.map((m) => ({
            indicator_type: m.indicator?.type ?? null, indicator_value: m.indicator?.value ?? null,
            confidence: m.indicator?.max_confidence ?? null, malware_families: m.indicator?.malware_families ?? [], threat_types: m.indicator?.threat_types ?? [],
            verified: m.status === 'promoted' || !!m.case_id, status: m.status, case_id: m.case_id,
            tlp: ti.tlpByIndicator.get(m.indicator_id) ?? 'amber',
        })),
        findings: fs.map((f) => {
            // Evidence summary only: when, where and by what; never the raw scanner output.
            const ev = (evidence.data ?? []).filter((e) => e.finding_id === f.id);
            const cv = ev.map((e) => e.evidence as Record<string, unknown> | null).find((x) => x && (x.cvss_version || x.cvss_vector)) ?? null;
            return {
                id: f.id, title: f.title, rule_id: f.rule_id, port: f.port, status: f.status, severity: f.scanner_severity, priority: f.priority, risk_score: f.risk_score,
                cvss: { score: f.scanner_cvss, version: (cv?.cvss_version as string | undefined) ?? null, vector: (cv?.cvss_vector as string | undefined) ?? null },
                cves: (f.cve_ids ?? []).map((c) => ({ cve_id: c, kev: !!intelBy.get(c)?.kev, epss: intelBy.get(c)?.epss_score ?? null })),
                detected_by: f.source_class === 'wazuh' ? ['wazuh'] : f.detected_by ?? [], evidence_class: f.evidence_class ?? null,
                first_seen: f.first_seen, last_seen: f.last_seen, verified_at: f.verified_at, due_at: f.due_at,
                remediation: f.remediation, description: f.description,
                evidence: { detections: ev.length, last_observed_at: ev[0]?.observed_at ?? null, sources: [...new Set(ev.map((e) => e.source))], locations: [...new Set(ev.map((e) => e.matched_at).filter(Boolean))].slice(0, 5) },
                history: (events.data ?? []).filter((e) => e.finding_id === f.id).map((e) => ({ at: e.at, action: e.action, from: e.from_value, to: e.to_value })),
                tasks: (tasks.data ?? []).filter((t) => t.finding_id === f.id).map((t) => ({ title: t.title, status: t.status, due_at: t.due_at })),
            };
        }),
    });
});

export default router;
