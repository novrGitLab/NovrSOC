// CNII passive collection (phase P9): runs passive_osint jobs from the VMS queue. Everything here
// asks a third party about a target; nothing connects to the target itself:
//
//   SpiderFoot   passive modules only (lib/spiderfoot.ts SPIDERFOOT_MODULES): registry, reverse
//                DNS, geo, Shodan/Censys open ports and CVEs, VirusTotal, CT logs
//   crt.sh       certificate-transparency names and certificates for a domain
//   DNS          A / AAAA / CNAME through the platform's resolver
//   RIPE Stat    an autonomous system's holder and announced prefixes
//   OpenCTI      what the organisation's own OpenCTI knows about an IP (OPENCTI_URL/TOKEN)
//
// Scope: a job's targets were checked when it was queued (routes/vms.ts validateScan); each is
// checked again here against the organisation's active scope for the passive activity before
// anything is looked up or stored. A name a source reports is added to the inventory only when an
// authorised domain entry covers it (confidence "probable"); otherwise it is recorded as a related
// host on the asset it came from — never as the organisation's asset.
//
// What is stored: observations (vms_observations) with source, confidence, first/last seen and a
// sighting count; CVEs a source attributes to an address become version_match findings through
// services/vmsFindings.ts ingestPassiveClaims (unconfirmed, at most P3). E-mail addresses and phone
// numbers SpiderFoot finds are personal data and are not stored. A source that is not configured
// or fails is reported in the job summary; the others still run.

import { isIP } from 'net';
import { promises as dnsp } from 'dns';
import { getSupabase } from './geoEnrichment';
import { redactValue } from '../lib/redact';
import { coveringScope, normalizeHostname, parseTarget, type ScopeEntry } from '../lib/vmsScope';
import { scanTarget, spiderfootConfigured, type SpiderFootResult } from '../lib/spiderfoot';
import { lookupIP, openctiConfigured, type OpenCTIResult } from '../lib/opencti';
import { lookupASN, type ASNInfo } from './ripeStat';
import { ingestPassiveClaims, type PassiveClaim } from './vmsFindings';

export type SourceStatus = 'ok' | 'not_configured' | 'failed' | 'skipped';
export type ObsKind = 'dns' | 'certificate' | 'service' | 'registry' | 'geo' | 'reputation' | 'vulnerability_claim' | 'related_host' | 'announced_prefix';
export interface Obs { source: string; kind: ObsKind; key: string; value: Record<string, unknown>; confidence: 'high' | 'medium' | 'low' }
export interface CtCert { id: number; name_value?: string; common_name?: string; issuer_name?: string; not_before?: string; not_after?: string; serial_number?: string }
export interface DnsAnswer { a: string[]; aaaa: string[]; cname: string[] }

/** The outside world, injectable for tests. A missing optional source means "not configured". */
export interface PassiveDeps {
    spiderfoot?: (target: string) => Promise<SpiderFootResult>;
    opencti?: (ip: string) => Promise<OpenCTIResult>;
    crtsh: (domain: string) => Promise<CtCert[]>;
    resolve: (host: string) => Promise<DnsAnswer>;
    asn: (asn: string) => Promise<ASNInfo>;
}

const num = (v: string | undefined, d: number) => (Number(v) > 0 ? Number(v) : d);
/** SpiderFoot scans are slow and heavy: at most this many targets per job get one. */
export const SPIDERFOOT_MAX_TARGETS = () => num(process.env.CNII_SPIDERFOOT_MAX_TARGETS, 20);
const SPIDERFOOT_TIMEOUT_MS = () => num(process.env.CNII_SPIDERFOOT_TIMEOUT_SECONDS, 300) * 1000;
const MAX_CT_NAMES = 500;

export async function fetchCrtsh(domain: string): Promise<CtCert[]> {
    const r = await fetch(`https://crt.sh/?${new URLSearchParams({ q: `%.${domain}`, output: 'json', exclude: 'expired' })}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(45_000) });
    if (!r.ok) throw new Error(`crt.sh answered HTTP ${r.status}`);
    const j = await r.json().catch(() => { throw new Error('crt.sh returned no JSON'); });
    if (!Array.isArray(j)) throw new Error('crt.sh: unexpected response');
    return (j as CtCert[]).slice(0, 5000);
}

async function resolveAll(host: string): Promise<DnsAnswer> {
    const q = async (fn: () => Promise<string[]>) => {
        try { return await fn(); } catch (e) { if (['ENODATA', 'ENOTFOUND', 'ESERVFAIL', 'ENOTIMP', 'EREFUSED'].includes((e as NodeJS.ErrnoException).code ?? '')) return []; throw e; }
    };
    const [a, aaaa, cname] = await Promise.all([q(() => dnsp.resolve4(host)), q(() => dnsp.resolve6(host)), q(() => dnsp.resolveCname(host))]);
    return { a, aaaa, cname };
}

export const defaultDeps = (): PassiveDeps => ({
    ...(spiderfootConfigured() ? { spiderfoot: (t: string) => scanTarget(t, { timeoutMs: SPIDERFOOT_TIMEOUT_MS() }) } : {}),
    ...(openctiConfigured() ? { opencti: lookupIP } : {}),
    crtsh: fetchCrtsh,
    resolve: resolveAll,
    asn: lookupASN,
});

const isPublic = (ip: string): boolean => {
    if (isIP(ip) === 6) return !/^(::1|fc|fd|fe80)/i.test(ip);
    const [a, b] = ip.split('.').map(Number);
    return !(a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0);
};

// ── Turning source output into observations ───────────────────────────────────────────────────
const sfSource = 'spiderfoot';

/** Observations, claims and related names from one SpiderFoot result. Personal data is dropped. */
export function fromSpiderFoot(r: SpiderFootResult): { obs: Obs[]; claims: PassiveClaim[]; related: string[] } {
    const obs: Obs[] = [];
    if (r.owner || r.org || r.asn) obs.push({ source: sfSource, kind: 'registry', key: 'holder', value: { owner: r.owner ?? null, org: r.org ?? null, asn: r.asn ?? null }, confidence: 'high' });
    if (r.country || r.city) obs.push({ source: sfSource, kind: 'geo', key: 'location', value: { country: r.country ?? null, region: r.region ?? null, city: r.city ?? null }, confidence: 'medium' });
    if (r.hostname) obs.push({ source: sfSource, kind: 'dns', key: `name:${r.hostname}`, value: { hostname: r.hostname }, confidence: 'high' });
    // Open ports here are what Shodan/Censys reported, not our own observation.
    for (const p of r.openPorts) obs.push({ source: `${sfSource}:third_party_scan`, kind: 'service', key: `tcp/${p}`, value: { port: p, protocol: 'tcp', reported_by: 'Shodan/Censys via SpiderFoot' }, confidence: 'medium' });
    for (const b of (r.banners ?? []).slice(0, 20)) obs.push({ source: sfSource, kind: 'service', key: `banner:${b.slice(0, 120)}`, value: { banner: b.slice(0, 300) }, confidence: 'medium' });
    for (const c of (r.sslCerts ?? []).slice(0, 50)) obs.push({ source: sfSource, kind: 'certificate', key: `sf:${c.slice(0, 160)}`, value: { certificate: c.slice(0, 500) }, confidence: 'medium' });
    for (const f of r.maliciousFlags ?? []) obs.push({ source: sfSource, kind: 'reputation', key: f.slice(0, 200), value: { claim: f.slice(0, 500) }, confidence: 'low' });
    const claims: PassiveClaim[] = r.vulns.map((v) => ({ source: 'spiderfoot:sfp_shodan', cve: v.cve, cvss: v.cvss, severity: v.severity, evidence: { service: v.service ?? null } }));
    return { obs, claims, related: [...new Set([...r.domains, ...r.subdomains])] };
}

/** Names and certificates from crt.sh rows for a domain. Wildcards are not names. */
export function fromCrtsh(domain: string, rows: CtCert[]): { obs: Obs[]; names: string[] } {
    const names = new Set<string>();
    const obs: Obs[] = [];
    for (const r of rows) {
        for (const n of String(r.name_value ?? r.common_name ?? '').split('\n')) {
            const h = normalizeHostname(n);
            if (h && (h === domain || h.endsWith(`.${domain}`)) && names.size < MAX_CT_NAMES) names.add(h);
        }
        if (obs.length < 100 && r.serial_number) {
            obs.push({ source: 'crtsh', kind: 'certificate', key: `serial:${r.serial_number}`, value: { crtsh_id: r.id, common_name: r.common_name ?? null, issuer: r.issuer_name ?? null, not_before: r.not_before ?? null, not_after: r.not_after ?? null }, confidence: 'high' });
        }
    }
    return { obs, names: [...names].sort() };
}

// ── Storage ───────────────────────────────────────────────────────────────────────────────────
function cap(v: Record<string, unknown>): unknown {
    const r = redactValue(v);
    const json = JSON.stringify(r ?? {});
    return json.length > 4000 ? { truncated: true, preview: json.slice(0, 4000) } : r;
}

type AssetType = 'host' | 'ip' | 'asn' | 'cidr';
interface AssetRef { id: string; type: AssetType; value: string; isNew: boolean }

async function upsertAsset(org: string, type: AssetType, value: string, scopeId: string, source: string, confidence: 'confirmed' | 'probable', jobId: string, now: string): Promise<AssetRef> {
    const supabase = getSupabase()!;
    const { data: existing, error } = await supabase.from('vms_assets').select('id, discovery_sources, status, confidence').eq('org_id', org).eq('asset_type', type).eq('value', value).maybeSingle();
    if (error) throw new Error(`asset read failed: ${error.message}`);
    if (existing) {
        await supabase.from('vms_assets').update({
            last_seen: now, status: 'active', discovery_sources: [...new Set([...(existing.discovery_sources ?? []), source])],
            // A name seen again by a passive source stays probable; the scope entry itself is confirmed.
            ...(confidence === 'confirmed' && existing.confidence !== 'confirmed' ? { confidence } : {}),
        }).eq('id', existing.id);
        return { id: existing.id, type, value, isNew: false };
    }
    const exposure = type === 'ip' ? (isPublic(value) ? 'internet' : 'internal') : 'unknown';
    const ins = await supabase.from('vms_assets').insert({
        org_id: org, asset_type: type, value, hostnames: type === 'host' ? [value] : [], ips: type === 'ip' ? [value] : [],
        discovery_sources: [source], scope_id: scopeId, exposure, confidence, first_seen: now, last_seen: now,
    }).select('id').single();
    if (ins.error) throw new Error(`asset insert failed: ${ins.error.message}`);
    await supabase.from('vms_asset_events').insert({ org_id: org, asset_id: ins.data.id, job_id: jobId, event: 'asset_new', details: { value, source, confidence } });
    return { id: ins.data.id, type, value, isNew: true };
}

/** Upserts observations for an asset; returns how many were new. */
export async function storeObservations(org: string, assetId: string, jobId: string | null, list: Obs[], now = new Date().toISOString()): Promise<number> {
    const supabase = getSupabase()!;
    let added = 0;
    const seen = new Set<string>();
    for (const o of list) {
        const id = `${o.source}|${o.kind}|${o.key}`;
        if (seen.has(id)) continue;
        seen.add(id);
        const key = o.key.slice(0, 300);
        const { data: prev } = await supabase.from('vms_observations').select('id, seen_count').eq('asset_id', assetId).eq('source', o.source).eq('kind', o.kind).eq('key', key).maybeSingle();
        if (prev) {
            await supabase.from('vms_observations').update({ last_seen: now, seen_count: Number(prev.seen_count ?? 1) + 1, value: cap(o.value), confidence: o.confidence, last_job_id: jobId }).eq('id', prev.id);
        } else {
            const ins = await supabase.from('vms_observations').insert({ org_id: org, asset_id: assetId, source: o.source, kind: o.kind, key, value: cap(o.value), confidence: o.confidence, first_seen: now, last_seen: now, seen_count: 1, last_job_id: jobId });
            if (ins.error) throw new Error(`observation insert failed: ${ins.error.message}`);
            added++;
        }
    }
    return added;
}

// ── One job ───────────────────────────────────────────────────────────────────────────────────
export interface PassiveJob { id: string; org_id: string; targets: unknown }
export interface PassiveSummary {
    targets: number; out_of_scope: number; assets_new: number; observations_new: number; related_in_scope: number; related_outside_scope: number;
    findings_new: number; spiderfoot_skipped: number; sources: Record<string, { ok: number; failed: number; not_configured: number; skipped: number; errors: string[] }>;
}

const SOURCES = ['spiderfoot', 'crtsh', 'dns', 'ripestat', 'opencti'] as const;

/**
 * Runs one passive_osint job. `shouldStop` is polled between targets (cancel or revoked scope).
 * Throws only on storage errors; source failures are counted in the summary.
 */
export async function runPassiveJob(job: PassiveJob, scopes: ScopeEntry[], deps: PassiveDeps, shouldStop: () => Promise<boolean> = async () => false, onProgress: (done: number, total: number) => Promise<void> = async () => undefined): Promise<PassiveSummary> {
    const targets = Array.isArray(job.targets) ? job.targets.map(String) : [];
    const sum: PassiveSummary = { targets: targets.length, out_of_scope: 0, assets_new: 0, observations_new: 0, related_in_scope: 0, related_outside_scope: 0, findings_new: 0, spiderfoot_skipped: 0, sources: Object.fromEntries(SOURCES.map((s) => [s, { ok: 0, failed: 0, not_configured: 0, skipped: 0, errors: [] as string[] }])) };
    const mark = (s: (typeof SOURCES)[number], st: SourceStatus, err?: string) => {
        const b = sum.sources[s];
        b[st === 'not_configured' ? 'not_configured' : st]++;
        if (err && b.errors.length < 5) b.errors.push(err.slice(0, 200));
    };
    const attempt = async <T>(s: (typeof SOURCES)[number], fn: (() => Promise<T>) | undefined): Promise<T | null> => {
        if (!fn) { mark(s, 'not_configured'); return null; }
        try { const v = await fn(); mark(s, 'ok'); return v; } catch (e) { mark(s, 'failed', e instanceof Error ? e.message : String(e)); return null; }
    };
    let sfUsed = 0;
    const now = () => new Date().toISOString();

    for (let i = 0; i < targets.length; i++) {
        if (await shouldStop()) break;
        await onProgress(i, targets.length);
        const raw = targets[i];
        const t = parseTarget(raw);
        const asn = /^AS\d+$/.test(raw) ? raw : null;
        const cidr = !t && !asn && raw.includes('/') ? raw : null;
        // Re-check scope for the passive activity: an exact AS or CIDR entry, or a covering entry.
        const entry = asn || cidr
            ? scopes.find((s) => s.status === 'active' && Date.parse(s.expires_at) > Date.now() && s.value === raw) ?? null
            : t ? coveringScope(t, scopes, 'passive') : null;
        if (!entry) { sum.out_of_scope++; continue; }
        const type: AssetType = asn ? 'asn' : cidr ? 'cidr' : t!.type;
        const value = asn ?? cidr ?? t!.value;
        const asset = await upsertAsset(job.org_id, type, value, entry.id, 'passive', 'confirmed', job.id, now());
        if (asset.isNew) sum.assets_new++;
        const obs: Obs[] = [];
        const related: { name: string; source: string }[] = [];

        if (type === 'asn') {
            const info = await attempt('ripestat', () => deps.asn(value));
            if (info) {
                obs.push({ source: 'ripestat', kind: 'registry', key: 'holder', value: { holder: info.holder, rir: info.authoritative_rir, announced: info.is_announced, country: info.top_country, prefix_count: info.prefix_count }, confidence: 'high' });
                for (const p of info.prefixes) obs.push({ source: 'ripestat', kind: 'announced_prefix', key: p, value: { prefix: p }, confidence: 'high' });
            }
        } else if (type === 'cidr') {
            // A range is not looked up address by address; register its addresses as IP entries for that.
            mark('ripestat', 'skipped');
        } else {
            if (deps.spiderfoot && sfUsed >= SPIDERFOOT_MAX_TARGETS()) { mark('spiderfoot', 'skipped'); sum.spiderfoot_skipped++; }
            else {
                const sf = await attempt('spiderfoot', deps.spiderfoot && (() => { sfUsed++; return deps.spiderfoot!(value); }));
                if (sf) {
                    const f = fromSpiderFoot(sf);
                    obs.push(...f.obs);
                    for (const n of f.related) related.push({ name: n, source: 'spiderfoot' });
                    if (f.claims.length) {
                        const r = await ingestPassiveClaims(job.org_id, job.id, { id: asset.id, type, value }, f.claims);
                        sum.findings_new += r.new_findings;
                    }
                }
            }
            if (type === 'host') {
                const d = await attempt('dns', () => deps.resolve(value));
                if (d) {
                    if (d.a.length || d.aaaa.length || d.cname.length) obs.push({ source: 'dns', kind: 'dns', key: 'resolution', value: { a: d.a, aaaa: d.aaaa, cname: d.cname }, confidence: 'high' });
                    const ips = [...new Set([...d.a, ...d.aaaa].filter((x) => isIP(x)).map((x) => x.toLowerCase()))].sort();
                    if (ips.length) await getSupabase()!.from('vms_assets').update({ ips, dns: { a: d.a, aaaa: d.aaaa, cname: d.cname }, exposure: ips.some(isPublic) ? 'internet' : 'internal' }).eq('id', asset.id);
                }
                // CT logs are asked about the registered domain itself, not every name under it.
                if (entry.kind === 'domain' && value === entry.value) {
                    const ct = await attempt('crtsh', () => deps.crtsh(value));
                    if (ct) {
                        const c = fromCrtsh(value, ct);
                        obs.push(...c.obs);
                        for (const n of c.names) related.push({ name: n, source: 'crtsh' });
                    }
                } else mark('crtsh', 'skipped');
                mark('opencti', 'skipped');
            } else {
                const o = await attempt('opencti', deps.opencti && (() => deps.opencti!(value)));
                for (const ti of o?.threatIntel ?? []) obs.push({ source: 'opencti', kind: 'reputation', key: ti.description.slice(0, 200), value: { claim: ti.description, severity: ti.severity }, confidence: 'medium' });
                mark('dns', 'skipped'); mark('crtsh', 'skipped');
            }
        }

        // Names a source reported: our asset only when an authorised domain entry covers them.
        for (const { name, source } of related) {
            const h = normalizeHostname(name);
            if (!h || h === value) continue;
            const covering = coveringScope({ type: 'host', value: h }, scopes, 'passive');
            if (covering) {
                const r = await upsertAsset(job.org_id, 'host', h, covering.id, source, 'probable', job.id, now());
                if (r.isNew) { sum.assets_new++; sum.related_in_scope++; }
            } else {
                obs.push({ source, kind: 'related_host', key: h, value: { hostname: h, note: 'reported by the source; not inside this organisation\'s authorised scope' }, confidence: 'low' });
                sum.related_outside_scope++;
            }
        }
        sum.observations_new += await storeObservations(job.org_id, asset.id, job.id, obs, now());
    }
    return sum;
}

/** Job outcome: succeeded when at least one source answered for at least one target. */
export function passiveOutcome(sum: PassiveSummary): { status: 'succeeded' | 'failed'; error: string | null } {
    const ok = Object.values(sum.sources).reduce((n, s) => n + s.ok, 0);
    if (ok > 0) return { status: 'succeeded', error: null };
    if (sum.targets > 0 && sum.out_of_scope === sum.targets) return { status: 'failed', error: 'No target is inside an active scope any more' };
    const errs = Object.entries(sum.sources).flatMap(([k, s]) => (s.errors.length ? [`${k}: ${s.errors[0]}`] : s.not_configured ? [`${k}: not configured`] : []));
    return { status: 'failed', error: `No passive source answered${errs.length ? ` (${errs.join('; ')})` : ''}`.slice(0, 1000) };
}
