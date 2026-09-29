// Email Security alerts, indicators and correlation.
//
// One alert per incident, keyed by `correlation_key` (e.g. "phish:company-login.com"). When
// another observation of the same thing arrives — from the same module or a different one —
// it is attached to that alert as evidence instead of opening a new one. Indicators
// (domain / URL / IP / hash / address) are the join: every alert registers its indicators, and
// a new observation that shares one finds the open alert through them.
//
// Cases go through the existing SOC case system (services/cases.ts). createCase() already
// de-duplicates on (source, source_id), so escalating the same alert twice returns the same case.
import type { Db } from './db';
import { f } from './db';
import { createCase, addTimeline, isUuid, type CaseSeverity } from '../cases';
import { getSupabase } from '../geoEnrichment';

export type AlertStatus = 'new' | 'investigating' | 'resolved' | 'false_positive' | 'suppressed';
export const ALERT_STATUSES: AlertStatus[] = ['new', 'investigating', 'resolved', 'false_positive', 'suppressed'];
export type Module = 'dmarc' | 'phishid' | 'messaging';
export type AlertSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
const SEV_ORDER: AlertSeverity[] = ['informational', 'low', 'medium', 'high', 'critical'];
export const maxSeverity = (a: AlertSeverity, b: AlertSeverity) => (SEV_ORDER.indexOf(a) >= SEV_ORDER.indexOf(b) ? a : b);

export type IndicatorType = 'domain' | 'url' | 'ip' | 'sha256' | 'email';
export interface Indicator { type: IndicatorType; value: string }
export interface Evidence { at: string; module: Module; summary: string; ref?: { kind: string; id: string }; data?: Record<string, unknown> }
export interface TimelineEntry { at: string; actor: string; action: string; detail?: string }

export interface EmailAlert {
    id: string; org_id: string; correlation_key: string; severity: AlertSeverity; source_module: Module; modules: Module[];
    detection_type: string; entity: string; title: string; description: string | null; evidence: Evidence[]; timeline: TimelineEntry[];
    indicators: Indicator[]; related_events: string[]; occurrences: number; status: AlertStatus; assigned_to: string | null;
    case_id: string | null; case_number: string | null; first_seen: string; last_seen: string; created_at: string; updated_at: string;
}

const CLOSED: AlertStatus[] = ['resolved', 'false_positive'];

// The SOC case system. Swappable for tests only — production always uses services/cases.ts.
let caseApi = { createCase, addTimeline };
export function setCaseApi(api: Partial<typeof caseApi> | null): void { caseApi = { createCase, addTimeline, ...(api ?? {}) }; }
const cap = <T>(arr: T[], n: number) => arr.slice(-n);
const uniqInd = (xs: Indicator[]) => [...new Map(xs.map((x) => [`${x.type}|${x.value}`, x])).values()];

// ── Indicators ─────────────────────────────────────────────────────────────────────────────

export interface IndicatorRef { module: string; kind: string; id: string }

export async function recordIndicators(db: Db, orgId: string, items: Indicator[], ref: IndicatorRef): Promise<void> {
    const list = uniqInd(items.filter((i) => i.value).map((i) => ({ type: i.type, value: i.value.toLowerCase().slice(0, 2000) })));
    if (!list.length) return;
    const existing = await db.select<{ type: string; value: string; refs: IndicatorRef[]; first_seen: string }>('email_indicators', {
        filters: [f.eq('org_id', orgId), f.in('value', list.map((i) => i.value))], limit: 1000,
    });
    const now = new Date().toISOString();
    const rows = list.map((i) => {
        const e = existing.find((x) => x.type === i.type && x.value === i.value);
        const refs = [...(e?.refs ?? []).filter((r) => !(r.kind === ref.kind && r.id === ref.id)), ref];
        return { org_id: orgId, type: i.type, value: i.value, refs: cap(refs, 100), first_seen: e?.first_seen ?? now, last_seen: now };
    });
    await db.upsert('email_indicators', rows, ['org_id', 'type', 'value']);
}

/** Every recorded sighting of these values, across all three modules. */
export async function indicatorSightings(db: Db, orgId: string, values: string[]) {
    if (!values.length) return [];
    return db.select<{ type: string; value: string; refs: IndicatorRef[]; first_seen: string; last_seen: string }>('email_indicators', {
        filters: [f.eq('org_id', orgId), f.in('value', [...new Set(values.map((v) => v.toLowerCase()))])], limit: 1000,
    });
}

/** Open alerts that already hold any of these indicators. */
export async function openAlertsFor(db: Db, orgId: string, values: string[]): Promise<EmailAlert[]> {
    const sightings = await indicatorSightings(db, orgId, values);
    const ids = [...new Set(sightings.flatMap((s) => s.refs.filter((r) => r.kind === 'alert').map((r) => r.id)))];
    if (!ids.length) return [];
    const alerts = await db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', orgId), f.in('id', ids)] });
    return alerts.filter((a) => !CLOSED.includes(a.status)).sort((a, b) => SEV_ORDER.indexOf(b.severity) - SEV_ORDER.indexOf(a.severity));
}

// ── Raising / attaching ────────────────────────────────────────────────────────────────────

export interface AlertInput {
    org_id: string;
    correlation_key: string;
    severity: AlertSeverity;
    module: Module;
    detection_type: string;
    entity: string;
    title: string;
    description: string;
    evidence: Omit<Evidence, 'at' | 'module'>;
    indicators: Indicator[];
    related_event?: string;
}

export async function raiseAlert(db: Db, input: AlertInput): Promise<{ alert: EmailAlert; created: boolean }> {
    const now = new Date().toISOString();
    const ev: Evidence = { at: now, module: input.module, ...input.evidence };
    const [existing] = await db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', input.org_id), f.eq('correlation_key', input.correlation_key)], limit: 1 });

    if (!existing) {
        const [alert] = await db.insert<EmailAlert>('email_alerts', {
            org_id: input.org_id, correlation_key: input.correlation_key, severity: input.severity, source_module: input.module, modules: [input.module],
            detection_type: input.detection_type, entity: input.entity, title: input.title, description: input.description,
            evidence: [ev], timeline: [{ at: now, actor: 'system', action: 'Alert opened', detail: input.evidence.summary }],
            indicators: uniqInd(input.indicators), related_events: input.related_event ? [input.related_event] : [], occurrences: 1,
            status: 'new', first_seen: now, last_seen: now, updated_at: now,
        });
        await recordIndicators(db, input.org_id, input.indicators, { module: input.module, kind: 'alert', id: alert.id });
        return { alert, created: true };
    }
    return { alert: await attachEvidence(db, existing, input, ev), created: false };
}

async function attachEvidence(db: Db, a: EmailAlert, input: AlertInput, ev: Evidence): Promise<EmailAlert> {
    const now = ev.at;
    const timeline = [...a.timeline];
    let status = a.status;
    if (a.status === 'resolved') { status = 'new'; timeline.push({ at: now, actor: 'system', action: 'Reopened — observed again after resolution', detail: ev.summary }); }
    else if (a.status === 'false_positive' || a.status === 'suppressed') timeline.push({ at: now, actor: 'system', action: `Observed again (still ${a.status.replace('_', ' ')})`, detail: ev.summary });
    else if (!a.modules.includes(input.module)) timeline.push({ at: now, actor: 'system', action: `Correlated with ${input.module} evidence`, detail: ev.summary });
    const [updated] = await db.update<EmailAlert>('email_alerts', [f.eq('id', a.id)], {
        severity: status === 'false_positive' || status === 'suppressed' ? a.severity : maxSeverity(a.severity, input.severity),
        modules: [...new Set([...a.modules, input.module])],
        evidence: cap([...a.evidence, ev], 50),
        timeline: cap(timeline, 200),
        indicators: uniqInd([...a.indicators, ...input.indicators]).slice(0, 200),
        related_events: input.related_event ? cap([...new Set([...a.related_events, input.related_event])], 200) : a.related_events,
        occurrences: a.occurrences + 1,
        status,
        last_seen: now,
        updated_at: now,
    });
    await recordIndicators(db, a.org_id, input.indicators, { module: input.module, kind: 'alert', id: a.id });
    // Keep a linked case's timeline in step with new evidence.
    if (a.case_id && isUuid(a.case_id)) await caseApi.addTimeline(a.case_id, 'Email Security', `New ${input.module} evidence`, { details: ev.summary, automated: true });
    return updated ?? a;
}

/**
 * Attach an observation to whichever open alert already holds one of its indicators; if none
 * does, open one with `fallback` (when given). This is the single entry point modules use, so
 * the same phishing domain seen by Phish ID, in a DMARC report and in a delivered email ends up
 * as one alert.
 */
export async function correlateOrRaise(db: Db, orgId: string, observed: Indicator[], obs: Omit<AlertInput, 'org_id' | 'correlation_key'> & { correlation_key?: string }): Promise<EmailAlert | null> {
    const related = await openAlertsFor(db, orgId, observed.map((i) => i.value));
    if (related[0]) {
        const ev: Evidence = { at: new Date().toISOString(), module: obs.module, ...obs.evidence };
        return attachEvidence(db, related[0], { ...obs, org_id: orgId, correlation_key: related[0].correlation_key }, ev);
    }
    if (!obs.correlation_key) return null;
    return (await raiseAlert(db, { ...obs, org_id: orgId, correlation_key: obs.correlation_key })).alert;
}

// ── Analyst actions ────────────────────────────────────────────────────────────────────────

export async function updateAlert(db: Db, orgId: string, id: string, actor: string, patch: { status?: AlertStatus; assigned_to?: string | null; note?: string }): Promise<EmailAlert | null> {
    const [a] = await db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', orgId), f.eq('id', id)], limit: 1 });
    if (!a) return null;
    const now = new Date().toISOString();
    const timeline = [...a.timeline];
    const upd: Record<string, unknown> = { updated_at: now };
    if (patch.status && patch.status !== a.status) { upd.status = patch.status; timeline.push({ at: now, actor, action: `Status → ${patch.status.replace('_', ' ')}` }); }
    if (patch.assigned_to !== undefined && patch.assigned_to !== a.assigned_to) { upd.assigned_to = patch.assigned_to; timeline.push({ at: now, actor, action: patch.assigned_to ? `Assigned to ${patch.assigned_to}` : 'Unassigned' }); }
    if (patch.note) timeline.push({ at: now, actor, action: 'Note', detail: patch.note.slice(0, 4000) });
    upd.timeline = cap(timeline, 200);
    const [updated] = await db.update<EmailAlert>('email_alerts', [f.eq('id', a.id)], upd);
    if (a.case_id && isUuid(a.case_id) && (patch.status || patch.note)) {
        await caseApi.addTimeline(a.case_id, actor, patch.note ? 'Email Security note' : `Email alert status → ${patch.status}`, { details: patch.note });
    }
    return updated ?? null;
}

const CASE_SEV: Record<AlertSeverity, CaseSeverity> = { informational: 'low', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };

/** Open a SOC case for the alert (or attach it to an existing case when `caseId` is given). */
export async function escalateToCase(db: Db, orgId: string, id: string, actor: string, caseId?: string): Promise<{ ok: true; case_id: string; case_number: string; created: boolean } | { ok: false; status: number; error: string }> {
    const [a] = await db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', orgId), f.eq('id', id)], limit: 1 });
    if (!a) return { ok: false, status: 404, error: 'Alert not found' };
    const evidenceText = a.evidence.slice(-10).map((e) => `• [${e.module}] ${e.summary}`).join('\n');
    const indicatorsText = a.indicators.slice(0, 30).map((i) => `${i.type}: ${i.value}`).join(', ');
    let caseRow: { id: string; case_number: string };
    let created = false;

    if (caseId) {
        if (!isUuid(caseId)) return { ok: false, status: 400, error: 'case_id must be a case UUID' };
        const sb = getSupabase();
        const { data } = sb ? await sb.from('cases').select('id, case_number').eq('id', caseId).maybeSingle() : { data: null };
        if (!data) return { ok: false, status: 404, error: 'Case not found' };
        caseRow = data as { id: string; case_number: string };
        await caseApi.addTimeline(caseRow.id, actor, `Linked Email Security alert: ${a.title}`, { details: `${evidenceText}\nIndicators: ${indicatorsText}` });
    } else {
        const r = await caseApi.createCase({
            title: `[Email] ${a.title}`.slice(0, 200),
            description: `${a.description ?? ''}\n\nEvidence:\n${evidenceText}\n\nIndicators: ${indicatorsText}`.trim(),
            severity: CASE_SEV[a.severity],
            source: 'email_security',
            source_id: a.id,
            org_id: orgId,
            tags: ['email-security', ...a.modules],
        }, actor);
        if (!r.ok) return { ok: false, status: r.status, error: r.error };
        caseRow = r.case;
        created = r.created;
    }
    const now = new Date().toISOString();
    await db.update('email_alerts', [f.eq('id', a.id)], {
        case_id: caseRow.id, case_number: caseRow.case_number, status: a.status === 'new' ? 'investigating' : a.status, updated_at: now,
        timeline: cap([...a.timeline, { at: now, actor, action: created ? `Case ${caseRow.case_number} opened` : `Linked to case ${caseRow.case_number}` }], 200),
    });
    return { ok: true, case_id: caseRow.id, case_number: caseRow.case_number, created };
}
