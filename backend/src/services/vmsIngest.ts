// VMS result ingestion (phase P4): turns worker observations into inventory rows.
//
// The worker (infra/vms-worker) runs the tools and sends normalised observations; it is not
// trusted to decide scope. Every observation is validated here and checked against the job's
// organisation's ACTIVE scope for the job's activity. Anything outside scope is dropped and
// counted, never stored. Changes are recorded in vms_asset_events so the attack-surface view can
// show what is new, what changed and what disappeared.

import { z } from 'zod';
import { isIP } from 'net';
import { getSupabase } from './geoEnrichment';
import { coveringScope, parseTarget, type Activity, type ScopeEntry } from '../lib/vmsScope';

const str = (max: number) => z.string().trim().min(1).max(max);
const Tech = z.object({ name: str(80), version: z.string().trim().max(60).optional().nullable() });
export const HostObservation = z.object({
    type: z.literal('host'),
    host: str(253),                                  // hostname or IP
    ips: z.array(z.string().max(45)).max(64).default([]),
    dns: z.object({ a: z.array(z.string().max(45)).max(64).optional(), aaaa: z.array(z.string().max(45)).max(64).optional(), cname: z.array(z.string().max(253)).max(16).optional() }).optional(),
    alive: z.boolean().optional(),
    http: z.object({ url: z.string().max(2048), status: z.number().int().min(100).max(599).nullable().optional(), title: z.string().max(300).nullable().optional(), webserver: z.string().max(200).nullable().optional(), cdn: z.string().max(80).nullable().optional() }).optional(),
    technologies: z.array(Tech).max(100).default([]),
    source: z.enum(['subfinder', 'amass', 'dnsx', 'httpx', 'nmap', 'naabu', 'manual', 'wazuh']),
});
export const ServiceObservation = z.object({
    type: z.literal('service'),
    host: str(253),
    port: z.number().int().min(0).max(65535),
    protocol: z.enum(['tcp', 'udp']),
    state: z.enum(['open', 'filtered', 'closed']).default('open'),
    service: z.string().trim().max(80).nullable().optional(),
    product: z.string().trim().max(120).nullable().optional(),
    version: z.string().trim().max(80).nullable().optional(),
    cpe: z.array(z.string().max(200)).max(10).optional(),
    source: z.enum(['nmap', 'naabu', 'httpx']),
});
export const Observation = z.discriminatedUnion('type', [HostObservation, ServiceObservation]);
export type ObservationT = z.infer<typeof Observation>;

export const activityForJob = (kind: string): Activity => (kind === 'passive_osint' ? 'passive' : kind === 'ports' ? 'ports' : kind.startsWith('vuln') ? 'vuln' : 'discovery');

const isPublic = (ip: string): boolean => {
    if (isIP(ip) === 6) return !/^(::1|fc|fd|fe80)/i.test(ip);
    const [a, b] = ip.split('.').map(Number);
    return !(a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0);
};

export interface IngestResult { accepted: number; rejected_out_of_scope: number; rejected_invalid: number; events: number }

/** Validates, scope-checks and stores one batch of observations for a running job. */
export async function ingestObservations(job: { id: string; org_id: string; kind: string; started_at: string | null }, raw: unknown[], scopes: ScopeEntry[]): Promise<IngestResult> {
    const supabase = getSupabase();
    if (!supabase) throw new Error('Database not configured');
    const activity = activityForJob(job.kind);
    const out: IngestResult = { accepted: 0, rejected_out_of_scope: 0, rejected_invalid: 0, events: 0 };
    const now = new Date().toISOString();
    const events: Record<string, unknown>[] = [];

    for (const item of raw) {
        const parsed = Observation.safeParse(item);
        if (!parsed.success) { out.rejected_invalid++; continue; }
        const o = parsed.data;
        // A result must match what the job was allowed to do: discovery never adds services.
        if (o.type === 'service' && activity === 'discovery') { out.rejected_invalid++; continue; }
        const target = parseTarget(o.host);
        if (!target) { out.rejected_invalid++; continue; }
        const scope = coveringScope(target, scopes, activity);
        if (!scope) { out.rejected_out_of_scope++; continue; }

        const assetType = target.type === 'host' ? 'host' : 'ip';
        const { data: existing, error: readErr } = await supabase.from('vms_assets').select('*').eq('org_id', job.org_id).eq('asset_type', assetType).eq('value', target.value).maybeSingle();
        if (readErr) throw new Error(`asset read failed: ${readErr.message}`);

        let assetId: string;
        if (o.type === 'host') {
            const ips = [...new Set(o.ips.filter((ip) => isIP(ip)).map((ip) => ip.toLowerCase()))].sort();
            const exposure = ips.length ? (ips.some(isPublic) ? 'internet' : 'internal') : target.type === 'ip' ? (isPublic(target.value) ? 'internet' : 'internal') : 'unknown';
            const fields: Record<string, unknown> = {
                last_seen: now, status: 'active', scope_id: scope.id,
                ...(ips.length ? { ips } : {}),
                ...(o.dns ? { dns: o.dns } : {}),
                ...(o.alive !== undefined ? { alive: o.alive } : {}),
                ...(o.http ? { http: o.http } : {}),
                ...(exposure !== 'unknown' ? { exposure } : {}),
            };
            if (!existing) {
                const ins = await supabase.from('vms_assets').insert({ org_id: job.org_id, asset_type: assetType, value: target.value, hostnames: target.type === 'host' ? [target.value] : [], discovery_sources: [o.source], first_seen: now, ...fields }).select('id').single();
                if (ins.error) throw new Error(`asset insert failed: ${ins.error.message}`);
                assetId = ins.data.id;
                events.push({ org_id: job.org_id, asset_id: assetId, job_id: job.id, event: 'asset_new', details: { value: target.value, source: o.source } });
            } else {
                assetId = existing.id;
                const changes: Record<string, unknown> = {};
                if (ips.length && JSON.stringify([...(existing.ips ?? [])].sort()) !== JSON.stringify(ips)) changes.ips = { from: existing.ips, to: ips };
                if (o.http && (existing.http?.status ?? null) !== (o.http.status ?? null)) changes.http_status = { from: existing.http?.status ?? null, to: o.http.status ?? null };
                if (o.http && (existing.http?.title ?? null) !== (o.http.title ?? null)) changes.http_title = { from: existing.http?.title ?? null, to: o.http.title ?? null };
                if (existing.status === 'gone') changes.status = { from: 'gone', to: 'active' };
                const sources = [...new Set([...(existing.discovery_sources ?? []), o.source])];
                const upd = await supabase.from('vms_assets').update({ ...fields, discovery_sources: sources }).eq('id', assetId);
                if (upd.error) throw new Error(`asset update failed: ${upd.error.message}`);
                if (Object.keys(changes).length) events.push({ org_id: job.org_id, asset_id: assetId, job_id: job.id, event: 'asset_changed', details: changes });
            }
            for (const t of o.technologies) {
                const name = t.name.toLowerCase();
                const version = t.version?.trim() ?? '';
                const { data: tech } = await supabase.from('vms_technologies').select('id').eq('asset_id', assetId).eq('name', name).eq('version', version).maybeSingle();
                if (tech) await supabase.from('vms_technologies').update({ last_seen: now }).eq('id', tech.id);
                else {
                    const ti = await supabase.from('vms_technologies').insert({ org_id: job.org_id, asset_id: assetId, name, version, source: o.source, first_seen: now, last_seen: now });
                    if (!ti.error) events.push({ org_id: job.org_id, asset_id: assetId, job_id: job.id, event: 'technology_new', details: { name, version: version || null } });
                }
            }
        } else {
            if (!existing) {
                const ins = await supabase.from('vms_assets').insert({ org_id: job.org_id, asset_type: assetType, value: target.value, hostnames: target.type === 'host' ? [target.value] : [], ips: target.type === 'ip' ? [target.value] : [], discovery_sources: [o.source], exposure: target.type === 'ip' ? (isPublic(target.value) ? 'internet' : 'internal') : 'unknown', scope_id: scope.id, first_seen: now, last_seen: now }).select('id').single();
                if (ins.error) throw new Error(`asset insert failed: ${ins.error.message}`);
                assetId = ins.data.id;
                events.push({ org_id: job.org_id, asset_id: assetId, job_id: job.id, event: 'asset_new', details: { value: target.value, source: o.source } });
            } else {
                assetId = existing.id;
                await supabase.from('vms_assets').update({ last_seen: now, status: 'active' }).eq('id', assetId);
            }
            if (o.state !== 'open') { out.accepted++; continue; } // only open services are inventory
            const svc = { service: o.service ?? null, product: o.product ?? null, version: o.version ?? null };
            const { data: prev } = await supabase.from('vms_services').select('id, service, product, version, status').eq('asset_id', assetId).eq('port', o.port).eq('protocol', o.protocol).maybeSingle();
            if (!prev) {
                const si = await supabase.from('vms_services').insert({ org_id: job.org_id, asset_id: assetId, port: o.port, protocol: o.protocol, state: 'open', ...svc, cpe: o.cpe ?? null, source: o.source, first_seen: now, last_seen: now });
                if (si.error) throw new Error(`service insert failed: ${si.error.message}`);
                events.push({ org_id: job.org_id, asset_id: assetId, job_id: job.id, event: 'service_new', details: { port: o.port, protocol: o.protocol, ...svc } });
            } else {
                const changed = (['service', 'product', 'version'] as const).filter((k) => svc[k] !== null && (prev[k] ?? null) !== svc[k]);
                await supabase.from('vms_services').update({ last_seen: now, status: 'active', state: 'open', ...Object.fromEntries(Object.entries(svc).filter(([, v]) => v !== null)), ...(o.cpe ? { cpe: o.cpe } : {}) }).eq('id', prev.id);
                if (changed.length || prev.status === 'gone') events.push({ org_id: job.org_id, asset_id: assetId, job_id: job.id, event: 'service_changed', details: { port: o.port, protocol: o.protocol, ...Object.fromEntries(changed.map((k) => [k, { from: prev[k], to: svc[k] }])), ...(prev.status === 'gone' ? { reappeared: true } : {}) } });
            }
        }
        out.accepted++;
    }
    if (events.length) {
        const ev = await supabase.from('vms_asset_events').insert(events);
        if (ev.error) throw new Error(`event insert failed: ${ev.error.message}`);
        out.events = events.length;
    }
    return out;
}

/**
 * Which ports a job's port specification definitely covered: "1-65535", "22,80,443", "8000-8100".
 * "top-N" covers an nmap-chosen set, so nothing is assumed covered by it.
 */
export function portsCovered(spec: unknown): (port: number) => boolean {
    if (typeof spec !== 'string' || /^top-/i.test(spec)) return () => false;
    const ranges: [number, number][] = [];
    for (const part of spec.split(',')) {
        const m = /^\s*(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s*$/.exec(part);
        if (!m) return () => false;
        const lo = Number(m[1]); const hi = m[2] ? Number(m[2]) : lo;
        if (lo > hi || hi > 65535) return () => false;
        ranges.push([lo, hi]);
    }
    return (port) => ranges.some(([lo, hi]) => port >= lo && port <= hi);
}

/**
 * After a completed port scan: an active service on a scanned target that the job did not see is
 * gone — but only when the job's port list explicitly covered that port.
 */
export async function markGoneServices(job: { id: string; org_id: string; started_at: string | null; targets: unknown; options?: unknown }): Promise<number> {
    const supabase = getSupabase();
    if (!supabase || !job.started_at || !Array.isArray(job.targets)) return 0;
    const covered = portsCovered((job.options as { ports?: unknown } | undefined)?.ports);
    let gone = 0;
    for (const raw of job.targets) {
        const t = parseTarget(String(raw));
        if (!t) continue;
        const { data: asset } = await supabase.from('vms_assets').select('id').eq('org_id', job.org_id).eq('asset_type', t.type === 'host' ? 'host' : 'ip').eq('value', t.value).maybeSingle();
        if (!asset) continue;
        const { data: stale } = await supabase.from('vms_services').select('id, port, protocol').eq('asset_id', asset.id).eq('status', 'active').lt('last_seen', job.started_at);
        for (const s of stale ?? []) {
            if (!covered(s.port)) continue;
            await supabase.from('vms_services').update({ status: 'gone' }).eq('id', s.id);
            await supabase.from('vms_asset_events').insert({ org_id: job.org_id, asset_id: asset.id, job_id: job.id, event: 'service_gone', details: { port: s.port, protocol: s.protocol } });
            gone++;
        }
    }
    return gone;
}
