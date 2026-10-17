// CNII Watch AI purpose (phase P9): a sector briefing for SOC staff. Unlike the other purposes it
// reads several organisations — only those classified into the requested sector — so it needs
// cnii:sector, which client roles never hold. It receives figures and records, never raw scanner
// output or source payloads: per-organisation measured figures and gaps, findings first seen in
// the period (with their evidence class), the CVE intelligence behind them, new indicator matches,
// counts of inventory changes, and feed / collection health. The answer must keep confirmed and
// unconfirmed findings apart, name stale or missing data, and recommend — never act.

import { z } from 'zod';
import { getSupabase } from './geoEnrichment';
import { registerAiPurpose, Confidence, type BuiltContext } from './aiPurposes';
import type { SourceRef } from './ai';
import { SECTOR_BY_ID } from '../lib/cnii-sectors';
import { orgStats } from '../routes/cnii';
import { feedConfigured, FEED_STALE_HOURS } from './threatInfo';
import { spiderfootConfigured } from '../lib/spiderfoot';
import { openctiConfigured } from '../lib/opencti';

const OPEN = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];

function push(records: Record<string, unknown>[], refs: SourceRef[], kind: string, id: string, row: Record<string, unknown>, label?: string) {
    const ref = `${kind}:${id}`;
    records.push({ ref, kind, ...row });
    refs.push({ ref, type: kind, id, label });
}

/** subject id: "<sector>:7d" or "<sector>:30d". The requester's own organisation is not used. */
export async function buildSectorBriefing(_org: string, subject: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const [sectorId, period] = subject.split(':');
    const sector = SECTOR_BY_ID[sectorId];
    const days = period === '7d' ? 7 : period === '30d' ? 30 : 0;
    if (!sector || !days) return null;
    const until = new Date();
    const since = new Date(until.getTime() - days * 86_400_000).toISOString();
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    const limitations: string[] = [];

    const { data: profs } = await supabase.from('cnii_org_profiles').select('org_id, sector_id, subfield, designation').eq('sector_id', sector.id);
    const orgs = (profs ?? []).map((p) => p.org_id as string);
    push(records, refs, 'period', `${sector.id}:${period}`, { sector: sector.id, compliance_frameworks: sector.compliance, from: since, to: until.toISOString(), organisations_classified: orgs.length });
    if (!orgs.length) limitations.push('No organisation is classified into this sector, so there is nothing to brief on.');

    const stats = await orgStats(orgs);
    for (const p of profs ?? []) {
        const s = stats[p.org_id];
        push(records, refs, 'organisation', p.org_id, { org_id: p.org_id, subfield: p.subfield, designation: p.designation, measured: s }, p.org_id);
        if (!s.active_scopes) limitations.push(`${p.org_id}: no active authorised scope, so nothing about it is monitored.`);
        else if (!s.last_collection) limitations.push(`${p.org_id}: passive collection has never run.`);
        else if (s.last_collection.status === 'failed') limitations.push(`${p.org_id}: the last passive collection failed.`);
    }

    if (orgs.length) {
        const [findings, events, matches] = await Promise.all([
            supabase.from('vms_findings').select('id, org_id, asset_value, title, cve_ids, priority, risk_score, evidence_class, status, first_seen').in('org_id', orgs).in('status', OPEN).gte('first_seen', since).in('priority', ['P1', 'P2', 'P3']).order('risk_score', { ascending: false }).limit(60),
            supabase.from('vms_asset_events').select('org_id, event').in('org_id', orgs).gte('at', since).limit(20_000),
            supabase.from('ti_matches').select('id, org_id, entity_type, matched_field, status, first_matched_at, ti_indicators(type, value, malware_families, threat_types, max_confidence, source_count)').in('org_id', orgs).gte('first_matched_at', since).limit(40),
        ]);
        const cves = new Set<string>();
        for (const f of findings.data ?? []) {
            push(records, refs, 'finding', f.id, { ...f, confirmed: f.evidence_class !== 'version_match' && f.evidence_class !== 'intelligence' }, f.title);
            for (const c of f.cve_ids ?? []) cves.add(c);
        }
        if ((findings.data ?? []).length === 60) limitations.push('Only the 60 highest-risk new findings are included.');
        if (cves.size) {
            const { data: intel } = await supabase.from('cve_intel').select('cve_id, cvss_score, kev, kev_date_added, epss_score, kev_checked_at').in('cve_id', [...cves].slice(0, 200));
            for (const c of intel ?? []) push(records, refs, 'cve', c.cve_id, c, c.cve_id);
        }
        const tally: Record<string, Record<string, number>> = {};
        for (const e of events.data ?? []) { tally[e.org_id] ??= {}; tally[e.org_id][e.event] = (tally[e.org_id][e.event] ?? 0) + 1; }
        for (const [o, t] of Object.entries(tally)) push(records, refs, 'inventory_changes', o, { org_id: o, counts: t, description: 'Inventory change events in the period (new/changed/gone assets and services), counted' });
        for (const m of matches.data ?? []) push(records, refs, 'match', m.id, m as unknown as Record<string, unknown>);
    }

    const { data: feeds } = await supabase.from('ti_feeds').select('id, name, enabled, last_success_at, last_error');
    for (const f of feeds ?? []) {
        const configured = feedConfigured(f.id);
        const stale = configured && f.enabled && (!f.last_success_at || Date.now() - Date.parse(f.last_success_at) > (FEED_STALE_HOURS[f.id] ?? 24) * 3_600_000);
        push(records, refs, 'feed', f.id, { ...f, configured, stale }, f.name);
        if (!configured) limitations.push(`Threat feed ${f.id} is not configured: indicators from it are absent.`);
        else if (f.last_error || stale) limitations.push(`Threat feed ${f.id} is failing or stale: matches from it may be missing.`);
    }
    push(records, refs, 'connectors', 'passive', { spiderfoot_configured: spiderfootConfigured(), opencti_configured: openctiConfigured() });
    if (!spiderfootConfigured()) limitations.push('SpiderFoot is not configured: passive collection has no registry/Shodan/CT data from it.');
    push(records, refs, 'limitations', 'all', { limitations });
    return { records, refs };
}

const Claim = z.object({ statement: z.string(), basis: z.enum(['platform_record', 'source_claim', 'ai_assessment']), evidence_refs: z.array(z.string()) });

registerAiPurpose('cnii_sector_briefing', {
    permission: 'cnii:sector', subjectType: 'cnii_sector', build: buildSectorBriefing,
    task: 'Write a briefing for SOC staff on this critical-infrastructure sector for the stated period only, from the records given. Cover: the sector\'s posture from the measured figures; what changed in the period (new findings, inventory changes, new indicator matches); emerging risks; and per organisation the most useful next actions. '
        + 'Keep confirmed and unconfirmed apart: a finding whose evidence_class is version_match or intelligence (confirmed: false) is a third-party claim that has not been checked — never say a system IS vulnerable on that basis; recommend confirming it with an authorised scan. '
        + 'Exploitation evidence comes only from the cve records (KEV, EPSS). Do not name threat actors, campaigns, CVEs, assets or sources that are not in the records. Every statement is platform_record, source_claim or ai_assessment and cites refs. '
        + 'Recommendations are advice for people to decide on: anything that blocks, isolates or changes a system needs approval (requires_approval true). Put every limitation, unmonitored organisation, failed or stale feed and unconfigured source in data_gaps, and say figures may be low because of missing data. If there is little in the records, say so plainly.',
    schema: z.object({
        period: z.string(),
        sector: z.string(),
        headline: z.string(),
        posture_summary: z.string(),
        statements: z.array(Claim),
        emerging_risks: z.array(z.object({ risk: z.string(), confirmed: z.boolean(), evidence_refs: z.array(z.string()) })),
        organisation_actions: z.array(z.object({ org_id: z.string(), action: z.string(), priority: z.enum(['high', 'medium', 'low']), requires_approval: z.boolean(), evidence_refs: z.array(z.string()) })),
        data_gaps: z.array(z.string()),
        confidence: Confidence,
    }),
});

// ── Intake classification assistance (P17) ────────────────────────────────────────────────────
// For an ambiguous submission: which organisation and sector the gathered evidence points to, and
// what the analyst should verify. A suggestion only — the submission's status changes solely by a
// manager's decision or trusted records (services/cniiIntake.ts). The model sees the submission's
// stored evidence and the list of classified organisations, nothing else.
export async function buildIntakeClassification(_org: string, id: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: s } = await supabase.from('cnii_submissions').select('id, value, kind, status, reason, ips, resolution, evidence, suggestion').eq('id', id).maybeSingle();
    if (!s) return null;
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    const res = (s.resolution ?? {}) as { addresses?: { ip: string; ptr: string[]; asn: string | null; holder: string | null; public: boolean; covered_by: unknown[] }[]; errors?: string[] };
    // Row fields never named `kind`: push() keeps the record kind in that field.
    push(records, refs, 'submission', s.id, { value: s.value, value_type: s.kind, status: s.status, reason: s.reason, dns_errors: res.errors ?? [], keyword_hint: s.suggestion ?? null }, s.value);
    for (const a of res.addresses ?? []) push(records, refs, 'address', a.ip, { ip: a.ip, reverse_dns: a.ptr, asn: a.asn, registry_holder: a.holder, public: a.public, in_authorised_scope_of: a.covered_by }, a.ip);
    for (const [i, e] of ((s.evidence ?? []) as { kind?: string; detail?: string; source?: string; strength?: string }[]).entries()) push(records, refs, 'evidence', `${s.id}:${i}`, { evidence_type: e.kind, detail: e.detail, source: e.source, strength: e.strength });
    const [{ data: profs }, { data: orgs }] = await Promise.all([
        supabase.from('cnii_org_profiles').select('org_id, sector_id, subfield, designation').limit(300),
        supabase.from('organisations').select('slug, name').limit(2000),
    ]);
    const names = new Map((orgs ?? []).map((o) => [o.slug as string, o.name as string]));
    for (const p of profs ?? []) push(records, refs, 'organisation', p.org_id, { org_id: p.org_id, name: names.get(p.org_id) ?? p.org_id, sector_id: p.sector_id, subfield: p.subfield, designation: p.designation }, names.get(p.org_id) ?? p.org_id);
    return { records, refs };
}

const SECTOR_IDS = Object.keys(SECTOR_BY_ID) as [string, ...string[]];
registerAiPurpose('cnii_intake_classification', {
    permission: 'cnii:sector', subjectType: 'cnii_submission', build: buildIntakeClassification,
    task: 'Help an analyst decide which classified organisation (if any) operates the submitted domain or IP, and its CNII sector, from the records given only. '
        + 'Registry holders and AS names identify the network operator, not the owner; reverse DNS and keyword hints are weak; an address in an organisation\'s authorised scope does not prove it operates a domain hosted there. '
        + 'suggested_org_id must be the org_id of one of the organisation records, or null when the records do not support one; never invent an organisation. suggested_sector_id is null unless supported. '
        + 'This is a suggestion: list in verify_before_confirming what a person must check (e.g. a designation letter, WHOIS registrant, the organisation confirming the asset). Every statement cites refs. If the evidence is thin, say so and lower confidence.',
    schema: z.object({
        suggested_org_id: z.string().nullable(),
        suggested_sector_id: z.enum(SECTOR_IDS).nullable(),
        summary: z.string(),
        statements: z.array(Claim),
        verify_before_confirming: z.array(z.string()),
        data_gaps: z.array(z.string()),
        confidence: Confidence,
    }),
});
