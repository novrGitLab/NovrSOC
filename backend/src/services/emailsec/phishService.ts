// Intellicode Phish ID: brand profile, look-alike discovery, domain intelligence, safe website
// inspection, risk classification and analyst investigation.
//
// Discovery finds domains that EXIST and resemble the brand; it never labels them malicious.
// Everything starts as "discovered" and only evidence (phishRisk.ts) or an analyst moves it on.
import { Resolver } from 'dns/promises';
import type { Db } from './db';
import { f } from './db';
import { generateCandidates, resemblance, registrableDomain, type Technique } from './similarity';
import { inspectWebsite, type WebsiteEvidence } from './siteInspect';
import { assessPhishingRisk, riskAtLeast, severityForRisk, type Risk, type RiskSignal } from './phishRisk';
import { correlateOrRaise, recordIndicators, updateAlert } from './alerts';
import { lookupDomain } from '../rdap';
import { checkPhishSources } from '../phishCheck';
import { threatfoxSearchIOC } from '../threatfox';
import { emailsecConfig } from './config';
import { normalizeDomain } from './dnsInspect';

export interface BrandProfile {
    id: string; org_id: string; organization_name: string; primary_domains: string[]; additional_domains: string[]; keywords: string[];
    legitimate_domains: string[]; legitimate_urls: string[]; logo_url: string | null; last_discovery: string | null; updated_by: string | null; updated_at: string;
}
export type PhishStatus = 'discovered' | 'under_investigation' | 'suspicious' | 'confirmed_phishing' | 'false_positive' | 'resolved';
export const PHISH_STATUSES: PhishStatus[] = ['discovered', 'under_investigation', 'suspicious', 'confirmed_phishing', 'false_positive', 'resolved'];
export interface PhishingDomain {
    id: string; org_id: string; domain: string; brand_domain: string | null; techniques: Technique[]; similarity: number | null; discovered_via: string;
    status: PhishStatus; risk: Risk; risk_score: number; risk_signals: RiskSignal[]; intel: DomainIntel | null; website: WebsiteEvidence | null;
    resolves: boolean | null; assigned_to: string | null; alert_id: string | null; opencti_id: string | null;
    first_observed: string; last_observed: string; last_enriched: string | null; created_at: string; updated_at: string;
}
export interface DomainIntel {
    registrar: string | null; created: string | null; expires: string | null; age_days: number | null; nameservers: string[];
    dns: { a: string[]; aaaa: string[]; mx: string[]; ns: string[] };
    hosting: { ip: string; asn: string | null; holder: string | null; prefix: string | null }[];
    certificates: { issuer: string; not_before: string; not_after: string; names: string }[];
    ti: { source: string; detail: string }[];
    collected_at: string;
}

// ── Brand ──────────────────────────────────────────────────────────────────────────────────

export function cleanBrandInput(body: Record<string, unknown>): { ok: true; value: Omit<BrandProfile, 'id' | 'org_id' | 'last_discovery' | 'updated_by' | 'updated_at'> } | { ok: false; error: string } {
    const list = (v: unknown, max = 50) => (Array.isArray(v) ? v : typeof v === 'string' ? v.split(/[\n,]/) : []).map((x) => String(x).trim()).filter(Boolean).slice(0, max);
    const name = String(body.organization_name ?? '').trim();
    if (!name || name.length > 200) return { ok: false, error: 'organization_name is required (max 200 characters).' };
    const domains = (key: string) => {
        const raw = list(body[key]);
        const bad = raw.filter((d) => !normalizeDomain(d));
        return { good: raw.map((d) => normalizeDomain(d)).filter((d): d is string => !!d), bad };
    };
    const primary = domains('primary_domains');
    if (!primary.good.length) return { ok: false, error: 'At least one valid primary domain is required.' };
    const additional = domains('additional_domains');
    const legit = domains('legitimate_domains');
    const bad = [...primary.bad, ...additional.bad, ...legit.bad];
    if (bad.length) return { ok: false, error: `Not valid domains: ${bad.join(', ')}` };
    const urls = list(body.legitimate_urls, 200).filter((u) => /^https?:\/\/[^\s]+$/i.test(u));
    const logo = typeof body.logo_url === 'string' && /^https:\/\/[^\s]+$/i.test(body.logo_url) ? body.logo_url : null;
    return {
        ok: true,
        value: {
            organization_name: name, primary_domains: [...new Set(primary.good)], additional_domains: [...new Set(additional.good)],
            keywords: [...new Set(list(body.keywords).map((k) => k.toLowerCase()).filter((k) => k.length >= 3 && k.length <= 60))],
            legitimate_domains: [...new Set(legit.good)], legitimate_urls: urls, logo_url: logo,
        },
    };
}

export async function getBrand(db: Db, orgId: string): Promise<BrandProfile | null> {
    const [b] = await db.select<BrandProfile>('brand_profiles', { filters: [f.eq('org_id', orgId)], limit: 1 });
    return b ?? null;
}

const protectedDomains = (b: BrandProfile) => [...b.primary_domains, ...b.additional_domains];
const allowlisted = (b: BrandProfile, domain: string) => {
    const reg = registrableDomain(domain);
    return [...protectedDomains(b), ...b.legitimate_domains].some((d) => d === domain || d === reg || domain.endsWith(`.${d}`));
};
const brandTerms = (b: BrandProfile) => [b.organization_name, ...b.keywords, ...protectedDomains(b).map((d) => d.split('.')[0])];

// ── Discovery ──────────────────────────────────────────────────────────────────────────────

async function exists(r: Resolver, domain: string): Promise<boolean | null> {
    const tries = [() => r.resolve4(domain), () => r.resolveNs(domain), () => r.resolveMx(domain)];
    let errored = false;
    for (const t of tries) {
        try { if ((await t()).length) return true; }
        catch (err) { const c = (err as { code?: string }).code; if (c !== 'ENOTFOUND' && c !== 'ENODATA') errored = true; }
    }
    return errored ? null : false;
}

async function ctNames(label: string): Promise<{ names: string[]; error: string | null }> {
    try {
        const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%${label}%`)}&output=json&exclude=expired`, { signal: AbortSignal.timeout(25_000), headers: { Accept: 'application/json' } });
        if (!r.ok) return { names: [], error: `crt.sh answered HTTP ${r.status}` };
        const d = (await r.json()) as { name_value?: string }[];
        const names = new Set<string>();
        for (const c of Array.isArray(d) ? d : []) for (const n of (c.name_value ?? '').split('\n')) {
            const clean = normalizeDomain(n.replace(/^\*\./, ''));
            if (clean) names.add(registrableDomain(clean));
        }
        return { names: [...names], error: null };
    } catch (err) {
        return { names: [], error: `crt.sh unavailable: ${(err as Error).message}` };
    }
}

export interface DiscoveryResult { candidates_checked: number; registered: number; new_domains: string[]; ct_error: string | null; errors: number }

export async function discover(db: Db, orgId: string, actor = 'system'): Promise<DiscoveryResult | null> {
    const brand = await getBrand(db, orgId);
    if (!brand) return null;
    const resolver = new Resolver({ timeout: 3000, tries: 1 });
    const found = new Map<string, { brand_domain: string; techniques: Technique[]; via: string }>();
    let checked = 0;
    let errors = 0;
    let ctError: string | null = null;

    for (const target of protectedDomains(brand)) {
        const candidates = generateCandidates(target, emailsecConfig.maxCandidatesPerDomain()).filter((c) => !allowlisted(brand, c.domain));
        checked += candidates.length;
        for (let i = 0; i < candidates.length; i += 20) {
            const batch = candidates.slice(i, i + 20);
            const res = await Promise.all(batch.map((c) => exists(resolver, c.domain)));
            batch.forEach((c, k) => {
                if (res[k] === null) errors++;
                if (res[k]) found.set(c.domain, { brand_domain: target, techniques: [c.technique], via: 'permutation' });
            });
        }
        // Certificate Transparency: names in newly issued certificates that contain the brand.
        const label = target.split('.')[0];
        if (label.length >= 4) {
            const ct = await ctNames(label);
            if (ct.error) ctError = ct.error;
            for (const name of ct.names) {
                if (allowlisted(brand, name) || found.has(name)) continue;
                const r = resemblance(name, target, brand.keywords);
                if (r) found.set(name, { brand_domain: target, techniques: r.techniques, via: 'certificate_transparency' });
            }
        }
    }

    const existing = await db.select<{ domain: string }>('phishing_domains', { filters: [f.eq('org_id', orgId), f.in('domain', [...found.keys()])], limit: 1000, select: 'domain' });
    const known = new Set(existing.map((e) => e.domain));
    const now = new Date().toISOString();
    const fresh: string[] = [];
    for (const [domain, info] of found) {
        if (known.has(domain)) {
            await db.update('phishing_domains', [f.eq('org_id', orgId), f.eq('domain', domain)], { last_observed: now });
            continue;
        }
        const r = resemblance(domain, info.brand_domain, brand.keywords);
        const [row] = await db.insert<PhishingDomain>('phishing_domains', {
            org_id: orgId, domain, brand_domain: info.brand_domain, techniques: r?.techniques ?? info.techniques, similarity: r?.similarity ?? null,
            discovered_via: info.via, status: 'discovered', risk: 'informational', risk_score: 0, risk_signals: [], resolves: true,
            first_observed: now, last_observed: now, updated_at: now,
        });
        await db.insert('phishing_observations', {
            org_id: orgId, phishing_domain_id: row.id, kind: 'discovered', actor,
            summary: `Discovered via ${info.via === 'permutation' ? 'look-alike permutation' : 'Certificate Transparency'}: ${(r?.reasons ?? [info.techniques.join(', ')]).join(' ')}`,
        });
        fresh.push(domain);
    }
    await db.update('brand_profiles', [f.eq('org_id', orgId)], { last_discovery: now });
    return { candidates_checked: checked, registered: found.size, new_domains: fresh, ct_error: ctError, errors };
}

/** Analyst-submitted suspicious domain (e.g. from a user report). */
export async function addManualDomain(db: Db, orgId: string, input: string, actor: string): Promise<{ ok: true; row: PhishingDomain; created: boolean } | { ok: false; error: string }> {
    const domain = normalizeDomain(input);
    if (!domain) return { ok: false, error: 'Not a valid domain.' };
    const brand = await getBrand(db, orgId);
    if (brand && allowlisted(brand, domain)) return { ok: false, error: `${domain} is one of your own or allow-listed domains.` };
    const [existing] = await db.select<PhishingDomain>('phishing_domains', { filters: [f.eq('org_id', orgId), f.eq('domain', domain)], limit: 1 });
    if (existing) return { ok: true, row: existing, created: false };
    const best = brand ? protectedDomains(brand).map((d) => resemblance(domain, d, brand.keywords)).find(Boolean) ?? null : null;
    const now = new Date().toISOString();
    const [row] = await db.insert<PhishingDomain>('phishing_domains', {
        org_id: orgId, domain, brand_domain: best?.brand_domain ?? null, techniques: best?.techniques ?? [], similarity: best?.similarity ?? null,
        discovered_via: 'manual', status: 'under_investigation', risk: 'informational', risk_score: 0, risk_signals: [], first_observed: now, last_observed: now, updated_at: now,
        assigned_to: actor,
    });
    await db.insert('phishing_observations', { org_id: orgId, phishing_domain_id: row.id, kind: 'discovered', actor, summary: `Added manually by ${actor}.` });
    return { ok: true, row, created: true };
}

// ── Enrichment + inspection ────────────────────────────────────────────────────────────────

async function ipIntel(ip: string): Promise<{ ip: string; asn: string | null; holder: string | null; prefix: string | null }> {
    try {
        const r = await fetch(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(8000) });
        const d = (await r.json()) as { data?: { asns?: string[]; prefix?: string } };
        const asn = d.data?.asns?.[0] ?? null;
        let holder: string | null = null;
        if (asn) {
            const o = await fetch(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn}`, { signal: AbortSignal.timeout(8000) });
            holder = ((await o.json()) as { data?: { holder?: string } }).data?.holder ?? null;
        }
        return { ip, asn: asn ? `AS${asn}` : null, holder, prefix: d.data?.prefix ?? null };
    } catch {
        return { ip, asn: null, holder: null, prefix: null };
    }
}

async function certsFor(domain: string): Promise<DomainIntel['certificates']> {
    try {
        const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, { signal: AbortSignal.timeout(20_000), headers: { Accept: 'application/json' } });
        if (!r.ok) return [];
        const d = (await r.json()) as { issuer_name: string; not_before: string; not_after: string; name_value: string }[];
        return (Array.isArray(d) ? d : []).sort((a, b) => b.not_before.localeCompare(a.not_before)).slice(0, 10)
            .map((c) => ({ issuer: c.issuer_name, not_before: c.not_before, not_after: c.not_after, names: c.name_value.split('\n').slice(0, 5).join(', ') }));
    } catch { return []; }
}

export async function collectIntel(domain: string): Promise<DomainIntel> {
    const r = new Resolver({ timeout: 4000, tries: 2 });
    const safe = <T>(p: Promise<T>, fb: T) => p.catch(() => fb);
    const [whois, a, aaaa, mx, ns, certs, phish, tf] = await Promise.all([
        lookupDomain(domain), safe(r.resolve4(domain), [] as string[]), safe(r.resolve6(domain), [] as string[]),
        safe(r.resolveMx(domain), [] as { exchange: string }[]), safe(r.resolveNs(domain), [] as string[]),
        certsFor(domain), checkPhishSources(`https://${domain}/`).catch(() => null), threatfoxSearchIOC(domain).catch(() => []),
    ]);
    const hosting = await Promise.all(a.slice(0, 3).map(ipIntel));
    const created = whois?.created ? Date.parse(whois.created) : NaN;
    const ti: DomainIntel['ti'] = [];
    for (const h of phish?.hits ?? []) ti.push({ source: h === 'phishtank' ? 'PhishTank' : 'OpenPhish', detail: 'Listed as phishing' });
    for (const t of tf) ti.push({ source: 'ThreatFox', detail: `${t.threat_type_desc} — ${t.malware_printable} (confidence ${t.confidence_level}%)` });
    return {
        registrar: whois?.registrar ?? null, created: whois?.created ?? null, expires: whois?.expires ?? null,
        age_days: Number.isFinite(created) ? Math.floor((Date.now() - created) / 86_400_000) : null,
        nameservers: whois?.nameservers ?? ns,
        dns: { a, aaaa, mx: mx.map((m) => m.exchange), ns },
        hosting, certificates: certs, ti, collected_at: new Date().toISOString(),
    };
}

/** Collect intelligence, inspect the site, re-score, and raise / update the alert. */
export async function enrichDomain(db: Db, row: PhishingDomain, actor = 'system'): Promise<PhishingDomain> {
    const brand = await getBrand(db, row.org_id);
    const intel = await collectIntel(row.domain);
    const resolves = intel.dns.a.length + intel.dns.aaaa.length > 0;
    const website = resolves ? await inspectWebsite(row.domain, brand ? brandTerms(brand) : []) : null;
    const res = brand && row.brand_domain ? resemblance(row.domain, row.brand_domain, brand.keywords) : null;
    const assessment = assessPhishingRisk({
        resemblance: res, domain_age_days: intel.age_days, resolves, website,
        ti_hits: intel.ti.map((t) => `${t.source}: ${t.detail}`), brand_terms: brand ? brandTerms(brand) : [],
    });
    const now = new Date().toISOString();
    const [updated] = await db.update<PhishingDomain>('phishing_domains', [f.eq('id', row.id)], {
        intel, website, resolves, risk: assessment.risk, risk_score: assessment.score, risk_signals: assessment.signals,
        last_enriched: now, last_observed: resolves ? now : row.last_observed, updated_at: now,
        // Evidence can move a fresh discovery to "suspicious"; it never overrides an analyst's call.
        status: row.status === 'discovered' && riskAtLeast(assessment.risk, 'medium') ? 'suspicious' : row.status,
    });
    await db.insert('phishing_observations', {
        org_id: row.org_id, phishing_domain_id: row.id, kind: 'enriched', actor,
        summary: `${assessment.summary}${website ? ` Website: ${website.reachable ? `HTTP ${website.status}${website.title ? ` "${website.title}"` : ''}` : `unreachable (${website.error})`}.` : ' Does not resolve.'}`,
        data: { risk: assessment.risk, score: assessment.score },
    });
    const indicators = [{ type: 'domain' as const, value: row.domain }, ...intel.dns.a.map((ip) => ({ type: 'ip' as const, value: ip }))];
    if (riskAtLeast(assessment.risk, emailsecConfig.phishAlertMinRisk()) && !['false_positive', 'resolved'].includes(updated?.status ?? row.status)) {
        // Look up by the domain only — hosting IPs are often shared (CDNs), so they are recorded
        // on the alert but never used to merge it with another.
        const alert = await correlateOrRaise(db, row.org_id, [{ type: 'domain', value: row.domain }], {
            correlation_key: `phish:${row.domain}`, severity: severityForRisk(assessment.risk), module: 'phishid', detection_type: 'brand_impersonation',
            entity: row.domain, title: `Possible phishing domain impersonating ${row.brand_domain ?? brand?.organization_name ?? 'your brand'}: ${row.domain}`,
            description: assessment.summary, evidence: { summary: assessment.summary, ref: { kind: 'phishing_domain', id: row.id }, data: { signals: assessment.signals.map((s) => s.label) } },
            indicators,
        });
        if (alert && alert.id !== row.alert_id) await db.update('phishing_domains', [f.eq('id', row.id)], { alert_id: alert.id });
    } else {
        await recordIndicators(db, row.org_id, indicators, { module: 'phishid', kind: 'phishing_domain', id: row.id });
    }
    return updated ?? row;
}

// ── Analyst actions ────────────────────────────────────────────────────────────────────────

export async function setPhishStatus(db: Db, orgId: string, id: string, actor: string, patch: { status?: PhishStatus; assigned_to?: string | null }): Promise<PhishingDomain | null> {
    const [row] = await db.select<PhishingDomain>('phishing_domains', { filters: [f.eq('org_id', orgId), f.eq('id', id)], limit: 1 });
    if (!row) return null;
    const upd: Record<string, unknown> = { updated_at: new Date().toISOString() };
    const notes: string[] = [];
    if (patch.status && patch.status !== row.status) { upd.status = patch.status; notes.push(`Status: ${row.status.replace(/_/g, ' ')} → ${patch.status.replace(/_/g, ' ')}`); }
    if (patch.assigned_to !== undefined && patch.assigned_to !== row.assigned_to) { upd.assigned_to = patch.assigned_to; notes.push(patch.assigned_to ? `Assigned to ${patch.assigned_to}` : 'Unassigned'); }
    if (!notes.length) return row;
    const [updated] = await db.update<PhishingDomain>('phishing_domains', [f.eq('id', row.id)], upd);
    await db.insert('phishing_observations', { org_id: orgId, phishing_domain_id: row.id, kind: 'status', actor, summary: notes.join('; ') });
    // Keep the linked alert consistent with the analyst's decision.
    if (row.alert_id && patch.status) {
        const map: Partial<Record<PhishStatus, 'investigating' | 'resolved' | 'false_positive'>> = {
            under_investigation: 'investigating', suspicious: 'investigating', confirmed_phishing: 'investigating', false_positive: 'false_positive', resolved: 'resolved',
        };
        const s = map[patch.status];
        if (s) await updateAlert(db, orgId, row.alert_id, actor, { status: s, note: `Phish ID: ${row.domain} marked ${patch.status.replace(/_/g, ' ')}` });
    }
    return updated ?? row;
}

export async function addPhishNote(db: Db, orgId: string, id: string, actor: string, body: string): Promise<boolean> {
    const [row] = await db.select<PhishingDomain>('phishing_domains', { filters: [f.eq('org_id', orgId), f.eq('id', id)], limit: 1 });
    if (!row) return false;
    await db.insert('phishing_observations', { org_id: orgId, phishing_domain_id: id, kind: 'note', actor, summary: body.slice(0, 4000) });
    return true;
}
