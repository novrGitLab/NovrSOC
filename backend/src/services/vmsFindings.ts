// VMS findings (phase P5): one finding model for Nuclei, OpenVAS and Wazuh.
//
// Normalising: every scanner result becomes { asset, port, rule, title, severity, CVEs, CVSS,
// evidence }. Dedupe: one finding per (organisation, asset, port, issue), where the issue is the
// lowest CVE id when the result names CVEs (so Nuclei and OpenVAS reporting the same CVE meet),
// else the scanner's own rule id. Every sighting is kept as evidence, with its source and job.
// Risk: lib/riskScore.ts, from the scanner severity / NVD CVSS, CISA KEV, EPSS, the asset's
// exposure and its criticality; recomputed when intelligence or the asset changes.
//
// Lifecycle (people move a finding; scans only reopen or verify it):
//   open → acknowledged → in_progress → fixed_pending_verification → verified
//   any of those, seen again by a scan after being marked fixed or verified → reopened
//   risk_accepted / false_positive: a person's decision, kept even if seen again (each sighting is
//   still recorded).
// Verified means a verification scan that ran the same check on the same target finished
// successfully without detecting it (or, for Wazuh, a newer Wazuh report no longer lists it).
//
// Evidence class (phase P9, lib/riskScore.ts): scanner_check (Nuclei/OpenVAS fired), package_inventory
// (Wazuh), version_match (a third party saw a vulnerable-looking version: unconfirmed), exposure,
// intelligence (a third-party claim: unconfirmed). Passive claims (ingestPassiveClaims) never
// reopen a finding and never overwrite stronger evidence; a scanner detection upgrades a passive
// finding to scanner_check.

import { z } from 'zod';
import { getSupabase } from './geoEnrichment';
import { redactValue } from '../lib/redact';
import { riskScore, DUE_DAYS, type Severity, type Priority, type EvidenceClass } from '../lib/riskScore';
import { coveringScope, parseTarget, type ScopeEntry } from '../lib/vmsScope';
import { ensureCves, CVE_RE } from './cveIntel';
import { InvalidReasons } from './vmsIngest';

export const FINDING_STATUSES = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'verified', 'reopened', 'risk_accepted', 'false_positive'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];
/** Status changes a person may make; verified and reopened are set by scan evidence only. */
export const MANUAL_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
    open: ['acknowledged', 'in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive'],
    reopened: ['acknowledged', 'in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive'],
    acknowledged: ['in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive', 'open'],
    in_progress: ['fixed_pending_verification', 'acknowledged', 'risk_accepted', 'false_positive', 'open'],
    fixed_pending_verification: ['in_progress', 'open'],
    verified: [],
    risk_accepted: ['open'],
    false_positive: ['open'],
};

export const FindingObservation = z.object({
    type: z.literal('finding'),
    host: z.string().trim().min(1).max(253),
    port: z.number().int().min(0).max(65535).nullable().optional(),
    protocol: z.enum(['tcp', 'udp']).nullable().optional(),
    scanner: z.enum(['nuclei', 'openvas']),
    rule_id: z.string().trim().min(1).max(200),
    title: z.string().trim().min(1).max(300),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    cve_ids: z.array(z.string()).max(50).default([]),
    cvss: z.number().min(0).max(10).nullable().optional(),
    // P22: as the scanner reported them (worker 1.8.1, OpenVAS); kept with the evidence.
    cvss_version: z.string().trim().max(10).nullable().optional(),
    cvss_vector: z.string().trim().max(200).nullable().optional(),
    description: z.string().max(8000).nullable().optional(),
    remediation: z.string().max(8000).nullable().optional(),
    references: z.array(z.string().max(1000)).max(50).default([]),
    matched_at: z.string().max(2048).nullable().optional(),
    finding_type: z.enum(['vulnerability', 'misconfiguration', 'exposure', 'information']).default('vulnerability'),
    evidence: z.unknown().optional(),
});
export type FindingObs = z.infer<typeof FindingObservation>;

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const cleanCves = (ids: string[]) => [...new Set(ids.map((c) => c.trim().toUpperCase()).filter((c) => CVE_RE.test(c)))].sort();

export function dedupeKey(asset: { type: string; value: string }, port: number | null | undefined, scanner: string, ruleId: string, cves: string[]): string {
    const issue = cves.length ? cves[0] : `${scanner}:${ruleId}`;
    return `${asset.type}:${asset.value}|${port ?? '-'}|${issue}`;
}

function capEvidence(v: unknown): unknown {
    const r = redactValue(v ?? {});
    const json = JSON.stringify(r ?? {});
    return json.length > 8000 ? { truncated: true, preview: json.slice(0, 8000) } : r;
}

async function event(org: string, findingId: string, actor: string, action: string, from: string | null, to: string | null, details?: string) {
    await getSupabase()!.from('vms_finding_events').insert({ org_id: org, finding_id: findingId, actor, action, from_value: from, to_value: to, details: details?.slice(0, 2000) ?? null });
}

/** Risk for a finding from current intelligence and its asset. */
export async function computeRisk(f: { cve_ids: string[]; scanner_severity: Severity; scanner_cvss: number | null; asset_id: string | null; evidence_class?: EvidenceClass | null }) {
    const supabase = getSupabase()!;
    let cvss = f.scanner_cvss, kev: boolean | null = null, epss: number | null = null;
    if (f.cve_ids.length) {
        const { data } = await supabase.from('cve_intel').select('cve_id, cvss_score, kev, epss_score, kev_checked_at').in('cve_id', f.cve_ids);
        for (const c of data ?? []) {
            const s = c.cvss_score !== null ? Number(c.cvss_score) : null;
            if (s !== null && (cvss === null || s > cvss)) cvss = s;
            if (c.kev_checked_at) kev = (kev ?? false) || !!c.kev;
            const e = c.epss_score !== null ? Number(c.epss_score) : null;
            if (e !== null && (epss === null || e > epss)) epss = e;
        }
    }
    let exposure: 'internet' | 'internal' | 'unknown' = 'unknown', criticality: 'low' | 'medium' | 'high' | 'critical' = 'medium';
    if (f.asset_id) {
        const { data: a } = await supabase.from('vms_assets').select('exposure, criticality').eq('id', f.asset_id).maybeSingle();
        if (a) { exposure = a.exposure; criticality = a.criticality; }
    }
    return riskScore({ scanner_severity: f.scanner_severity, cvss, kev, epss, exposure, criticality, evidence_class: f.evidence_class ?? undefined });
}

const dueFrom = (firstSeen: string, p: Priority) => new Date(Date.parse(firstSeen) + DUE_DAYS[p] * 86_400_000).toISOString();

/** Recomputes risk (and the policy deadline, unless a person set one) for the given findings. */
export async function recomputeRisk(filter: { org?: string; ids?: string[]; cve?: string; assetId?: string }): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    // '*' rather than a column list: evidence_class exists only once sql/2026-10-17_p9_cnii.sql ran.
    let q = supabase.from('vms_findings').select('*');
    if (filter.org) q = q.eq('org_id', filter.org);
    if (filter.ids) q = q.in('id', filter.ids);
    if (filter.cve) q = q.contains('cve_ids', [filter.cve]);
    if (filter.assetId) q = q.eq('asset_id', filter.assetId);
    const { data } = await q.limit(5000);
    let changed = 0;
    for (const f of data ?? []) {
        const r = await computeRisk({ cve_ids: f.cve_ids ?? [], scanner_severity: f.scanner_severity, scanner_cvss: f.scanner_cvss !== null ? Number(f.scanner_cvss) : null, asset_id: f.asset_id, evidence_class: f.evidence_class });
        if (r.score === f.risk_score && r.priority === f.priority) continue;
        await supabase.from('vms_findings').update({ risk_score: r.score, priority: r.priority, risk_factors: r.factors, ...(f.due_manual ? {} : { due_at: dueFrom(f.first_seen, r.priority) }), updated_at: new Date().toISOString() }).eq('id', f.id);
        if (r.priority !== f.priority) await event(f.org_id, f.id, 'NovrSOC risk engine', 'risk', f.priority, r.priority, String(r.factors.rule));
        changed++;
    }
    return changed;
}

export interface FindingIngestResult { accepted: number; new_findings: number; reopened: number; rejected_out_of_scope: number; rejected_invalid: number; invalid_reasons?: string[] }

/** Stores scanner findings for a running vulnerability job. Every target is re-checked against vuln scope. */
export async function ingestFindings(job: { id: string; org_id: string }, raw: unknown[], scopes: ScopeEntry[]): Promise<FindingIngestResult> {
    const supabase = getSupabase();
    if (!supabase) throw new Error('Database not configured');
    const out: FindingIngestResult = { accepted: 0, new_findings: 0, reopened: 0, rejected_out_of_scope: 0, rejected_invalid: 0 };
    const now = new Date().toISOString();
    const reasons = new InvalidReasons();
    for (const item of raw) {
        const p = FindingObservation.safeParse(item);
        if (!p.success) { out.rejected_invalid++; reasons.add('finding', p.error.issues); continue; }
        const o = p.data;
        const target = parseTarget(o.host);
        if (!target) { out.rejected_invalid++; reasons.add('finding', 'host: not a hostname or IP address'); continue; }
        const scope = coveringScope(target, scopes, 'vuln');
        if (!scope) { out.rejected_out_of_scope++; continue; }
        const assetType = target.type === 'host' ? 'host' : 'ip';
        let { data: asset } = await supabase.from('vms_assets').select('id').eq('org_id', job.org_id).eq('asset_type', assetType).eq('value', target.value).maybeSingle();
        if (!asset) {
            const ins = await supabase.from('vms_assets').insert({ org_id: job.org_id, asset_type: assetType, value: target.value, hostnames: target.type === 'host' ? [target.value] : [], ips: target.type === 'ip' ? [target.value] : [], discovery_sources: [o.scanner], scope_id: scope.id, first_seen: now, last_seen: now }).select('id').single();
            if (ins.error) throw new Error(`asset insert failed: ${ins.error.message}`);
            asset = ins.data;
        }
        const cves = cleanCves(o.cve_ids);
        const key = dedupeKey({ type: assetType, value: target.value }, o.port, o.scanner, o.rule_id, cves);
        if (cves.length) await ensureCves(cves);
        const { data: existing } = await supabase.from('vms_findings').select('*').eq('org_id', job.org_id).eq('dedupe_key', key).maybeSingle();
        let findingId: string;
        if (!existing) {
            const r = await computeRisk({ cve_ids: cves, scanner_severity: o.severity, scanner_cvss: o.cvss ?? null, asset_id: asset!.id });
            const ins = await supabase.from('vms_findings').insert({
                org_id: job.org_id, dedupe_key: key, asset_id: asset!.id, asset_value: target.value, port: o.port ?? null, protocol: o.protocol ?? null,
                source_class: 'active_scan', detected_by: [o.scanner], rule_id: o.rule_id, title: o.title, description: o.description ?? null,
                finding_type: o.finding_type, cve_ids: cves, scanner_severity: o.severity, scanner_cvss: o.cvss ?? null, remediation: o.remediation ?? null,
                references_urls: o.references.filter((u) => /^https?:\/\//.test(u)).slice(0, 25),
                risk_score: r.score, priority: r.priority, risk_factors: r.factors, status: 'open', first_seen: now, last_seen: now, last_job_id: job.id, due_at: dueFrom(now, r.priority),
            }).select('id').single();
            if (ins.error) throw new Error(`finding insert failed: ${ins.error.message}`);
            findingId = ins.data.id;
            out.new_findings++;
            await event(job.org_id, findingId, `scanner:${o.scanner}`, 'detected', null, 'open', `${o.title}${o.port ? ` on port ${o.port}` : ''}`);
        } else {
            findingId = existing.id;
            const reopen = existing.status === 'verified' || existing.status === 'fixed_pending_verification';
            const severity = SEV_RANK[o.severity] > SEV_RANK[existing.scanner_severity as Severity] ? o.severity : existing.scanner_severity;
            // A scanner check now confirms what a passive source only claimed.
            const confirms = existing.evidence_class === 'version_match' || existing.evidence_class === 'intelligence';
            // What the first detection did not report is filled in from a later one; reported values are never replaced.
            const fills = {
                ...(existing.scanner_cvss === null && typeof o.cvss === 'number' ? { scanner_cvss: o.cvss } : {}),
                ...(!existing.description && o.description ? { description: o.description } : {}),
                ...(!existing.remediation && o.remediation ? { remediation: o.remediation } : {}),
                ...(!(existing.references_urls ?? []).length && o.references.length ? { references_urls: o.references.filter((u) => /^https?:\/\//.test(u)).slice(0, 25) } : {}),
            };
            await supabase.from('vms_findings').update({
                ...fills,
                last_seen: now, last_job_id: job.id, detected_by: [...new Set([...(existing.detected_by ?? []), o.scanner])], scanner_severity: severity,
                cve_ids: [...new Set([...(existing.cve_ids ?? []), ...cves])].sort(), updated_at: now,
                ...(reopen ? { status: 'reopened', verified_at: null, closed_at: null } : {}),
                ...(confirms ? { evidence_class: 'scanner_check', source_class: 'active_scan' } : {}),
            }).eq('id', findingId);
            if (reopen) { out.reopened++; await event(job.org_id, findingId, `scanner:${o.scanner}`, 'reopened', existing.status, 'reopened', 'Detected again after being marked fixed'); }
            if (confirms) await event(job.org_id, findingId, `scanner:${o.scanner}`, 'evidence', existing.evidence_class, 'scanner_check', `Confirmed by ${o.scanner} (${o.rule_id})`);
            // New evidence can change the risk: a CVE or a CVSS score now known, a higher severity.
            const newCves = cves.some((c) => !(existing.cve_ids ?? []).includes(c));
            if (confirms || 'scanner_cvss' in fills || newCves || severity !== existing.scanner_severity) await recomputeRisk({ ids: [findingId] });
        }
        // One evidence row per detection: the finding's history across scans.
        const ev = o.cvss_version || o.cvss_vector ? { ...(typeof o.evidence === 'object' && o.evidence ? o.evidence as Record<string, unknown> : {}), cvss: o.cvss ?? null, cvss_version: o.cvss_version ?? null, cvss_vector: o.cvss_vector ?? null } : o.evidence;
        await supabase.from('vms_finding_evidence').insert({ org_id: job.org_id, finding_id: findingId, source: o.scanner, job_id: job.id, observed_at: now, matched_at: o.matched_at ?? null, evidence: capEvidence(ev) });
        out.accepted++;
    }
    if (reasons.size) {
        out.invalid_reasons = reasons.list();
        console.warn(`[vms] job ${job.id}: ${out.rejected_invalid} finding(s) rejected as invalid: ${out.invalid_reasons.join('; ')}`);
    }
    return out;
}

/** A CVE a passive source attributes to an asset (e.g. Shodan via SpiderFoot): unconfirmed. */
export interface PassiveClaim { source: string; cve: string; cvss: number | null; severity: 'critical' | 'high' | 'medium' | 'low'; evidence?: unknown }
export interface PassiveClaimResult { new_findings: number; sightings: number; rejected_invalid: number }

/**
 * Stores passive CVE claims for an asset already in this organisation's inventory (the caller has
 * checked scope). Each claim becomes, or adds evidence to, a version_match finding. A claim never
 * reopens a finding, never moves a scanner-confirmed finding's last_seen, and never changes a
 * person's decision on it.
 */
export async function ingestPassiveClaims(org: string, jobId: string | null, asset: { id: string; type: string; value: string }, claims: PassiveClaim[]): Promise<PassiveClaimResult> {
    const supabase = getSupabase();
    if (!supabase) throw new Error('Database not configured');
    const out: PassiveClaimResult = { new_findings: 0, sightings: 0, rejected_invalid: 0 };
    const now = new Date().toISOString();
    for (const c of claims) {
        const cve = cleanCves([c.cve])[0];
        if (!cve || !['critical', 'high', 'medium', 'low'].includes(c.severity)) { out.rejected_invalid++; continue; }
        const cvss = typeof c.cvss === 'number' && c.cvss >= 0 && c.cvss <= 10 ? c.cvss : null;
        await ensureCves([cve]);
        const key = dedupeKey(asset, null, 'passive', cve, [cve]);
        const { data: existing } = await supabase.from('vms_findings').select('*').eq('org_id', org).eq('dedupe_key', key).maybeSingle();
        let findingId: string;
        if (!existing) {
            const r = await computeRisk({ cve_ids: [cve], scanner_severity: c.severity, scanner_cvss: cvss, asset_id: asset.id, evidence_class: 'version_match' });
            const ins = await supabase.from('vms_findings').insert({
                org_id: org, dedupe_key: key, asset_id: asset.id, asset_value: asset.value, port: null, protocol: null,
                source_class: 'passive_intel', evidence_class: 'version_match', detected_by: [c.source], rule_id: cve,
                title: `${cve} reported by ${c.source}: version match, not confirmed`,
                description: 'A third-party source reports this CVE for the asset from the product version it observed. No scanner check has confirmed it; confirm it with an authorised scan before treating the system as vulnerable.',
                finding_type: 'vulnerability', cve_ids: [cve], scanner_severity: c.severity, scanner_cvss: cvss,
                risk_score: r.score, priority: r.priority, risk_factors: r.factors, status: 'open', first_seen: now, last_seen: now, last_job_id: jobId, due_at: dueFrom(now, r.priority),
            }).select('id').single();
            if (ins.error) throw new Error(`finding insert failed: ${ins.error.message}`);
            findingId = ins.data.id;
            out.new_findings++;
            await event(org, findingId, `passive:${c.source}`, 'detected', null, 'open', `${cve} claimed by ${c.source} (unconfirmed)`);
        } else {
            findingId = existing.id;
            out.sightings++;
            const passiveOnly = existing.evidence_class === 'version_match' || existing.evidence_class === 'intelligence';
            if (passiveOnly) {
                await supabase.from('vms_findings').update({ last_seen: now, last_job_id: jobId, detected_by: [...new Set([...(existing.detected_by ?? []), c.source])], updated_at: now }).eq('id', findingId);
            }
        }
        await supabase.from('vms_finding_evidence').insert({ org_id: org, finding_id: findingId, source: c.source, job_id: jobId, observed_at: now, matched_at: asset.value, evidence: capEvidence({ claim: 'version_match', cvss, severity: c.severity, ...(c.evidence !== undefined ? { detail: c.evidence } : {}) }) });
    }
    return out;
}

/**
 * Whether a finished scan shows that it reached a target (P16). "Not detected" only means something
 * if the check got an answer: a scanner that could not reach the host also detects nothing. The
 * worker reports per-target outcomes (reachable_open / reachable_no_open / unreachable / no_route /
 * insufficient_evidence); a scan that reports none proves nothing about reachability.
 */
export function verificationReach(summary: unknown, target: string, jobTargets?: unknown[]): { reached: boolean; detail: string } {
    const s = (summary ?? {}) as { outcome?: unknown; target_outcomes?: Record<string, { outcome?: unknown }> };
    const per = s.target_outcomes?.[target]?.outcome ?? s.target_outcomes?.[target.toLowerCase()]?.outcome;
    if (typeof per === 'string') return { reached: per.startsWith('reachable'), detail: per.replace(/_/g, ' ') };
    // The job-level "assessed" means every target that REPORTED an outcome answered; it says
    // nothing about a submitted target that reported none. Trust it only when the job had a
    // single target (phase P26) — otherwise one reached host could verify another's findings.
    if (s.outcome === 'assessed' && jobTargets !== undefined && jobTargets.length !== 1) {
        return { reached: false, detail: `the job reported its answering targets as reachable, but no outcome for ${target} itself` };
    }
    if (s.outcome === 'assessed') return { reached: true, detail: 'assessed' };
    return { reached: false, detail: typeof s.outcome === 'string' ? `job outcome ${s.outcome.replace(/_/g, ' ')}` : 'the scan did not report whether it reached the target (worker before 1.6.0)' };
}

/**
 * After a verification scan finishes: each finding it was asked to verify and did not detect is
 * verified — only if the job succeeded AND it shows it reached the finding's target. A failed or
 * cancelled job, or one that cannot show it reached the target, verifies nothing: the finding
 * stays fixed-pending-verification and the history says why.
 */
export async function concludeVerification(job: { id: string; org_id: string; options: unknown; targets?: unknown }, status: 'succeeded' | 'failed' | 'cancelled', summary: unknown = null): Promise<{ verified: number; still_present: number; inconclusive: number }> {
    const supabase = getSupabase()!;
    const ids = ((job.options as { finding_ids?: unknown })?.finding_ids);
    const out = { verified: 0, still_present: 0, inconclusive: 0 };
    if (!Array.isArray(ids)) return out;
    const { data } = await supabase.from('vms_findings').select('id, status, last_job_id, asset_value').eq('org_id', job.org_id).in('id', ids.filter((x): x is string => typeof x === 'string'));
    const now = new Date().toISOString();
    for (const f of data ?? []) {
        if (f.last_job_id === job.id) { out.still_present++; continue; } // ingest already reopened it
        if (status !== 'succeeded') {
            out.inconclusive++;
            await event(job.org_id, f.id, 'NovrSOC verification', 'verification', null, null, `Verification scan ${status}; the finding stays ${f.status}`);
            continue;
        }
        if (f.status !== 'fixed_pending_verification') { out.inconclusive++; continue; }
        const reach = verificationReach(summary, String(f.asset_value ?? ''), Array.isArray(job.targets) ? job.targets : undefined);
        if (!reach.reached) {
            out.inconclusive++;
            await event(job.org_id, f.id, 'NovrSOC verification', 'verification', null, null, `Verification scan ${job.id} detected nothing but did not show it reached ${f.asset_value} (${reach.detail}); the finding stays fixed pending verification`);
            continue;
        }
        await supabase.from('vms_findings').update({ status: 'verified', verified_at: now, closed_at: now, verification_job_id: job.id, updated_at: now }).eq('id', f.id).eq('status', 'fixed_pending_verification');
        await event(job.org_id, f.id, 'NovrSOC verification', 'verified', 'fixed_pending_verification', 'verified', `Not detected by verification scan ${job.id}, which reached ${f.asset_value} (${reach.detail})`);
        out.verified++;
    }
    return out;
}

/** A person's status change, checked against MANUAL_TRANSITIONS. */
export async function setFindingStatus(org: string, id: string, actor: string, next: FindingStatus, note: string | null): Promise<{ ok: true; finding: Record<string, unknown> } | { ok: false; status: number; error: string }> {
    const supabase = getSupabase()!;
    const { data: f } = await supabase.from('vms_findings').select('id, status').eq('id', id).eq('org_id', org).maybeSingle();
    if (!f) return { ok: false, status: 404, error: 'Finding not found' };
    const allowed = MANUAL_TRANSITIONS[f.status as FindingStatus] ?? [];
    if (!allowed.includes(next)) return { ok: false, status: 409, error: `Cannot move a ${f.status.replace(/_/g, ' ')} finding to ${next.replace(/_/g, ' ')}${next === 'verified' ? ' — verification needs a rescan' : ''}` };
    if ((next === 'risk_accepted' || next === 'false_positive') && !note) return { ok: false, status: 400, error: 'A reason is required' };
    const now = new Date().toISOString();
    const { data } = await supabase.from('vms_findings').update({
        status: next, updated_at: now,
        ...(next === 'fixed_pending_verification' ? { fixed_marked_at: now } : {}),
        ...(next === 'risk_accepted' || next === 'false_positive' ? { closed_at: now } : next === 'open' ? { closed_at: null } : {}),
    }).eq('id', id).eq('org_id', org).select('*').maybeSingle();
    await event(org, id, actor, 'status', f.status, next, note ?? undefined);
    return { ok: true, finding: data ?? {} };
}
