// Shape of one event in the vendor export (phase X1, schema_version "1"). Built only from what is
// stored in the `alerts` row; anything missing is null — nothing is invented or inferred.
//
// network { src_ip, src_port, dst_ip, dst_port, protocol } comes from the stored raw alert:
//   Wazuh decoder fields   data.srcip, data.srcport, data.dstip, data.dstport, data.protocol
//   Sysmon (Windows)       data.win.eventdata.sourceIp / sourcePort / destinationIp /
//                          destinationPort / protocol  — used per field when the Wazuh one is absent
// An IP that isn't a valid address and a port that isn't an integer 0-65535 become null. When the
// stored raw was truncated at ingest (raw_truncated), its fields aren't available, so all are null.
//
// raw is included only when the client's redaction profile allows it, and only after
// lib/redact.ts; if redaction fails, raw is omitted. Free-text fields that can carry log content
// (rule.description, location) are redacted too.

import { isIP } from 'net';
import { redactString, redactValue, profileIncludesRaw } from './redact';

export const EXPORT_SCHEMA_VERSION = '1';

export interface AlertRowForExport {
    id: string;
    org_id: string;
    event_time: string;
    received_at: string | null;
    severity: string;
    rule_id: string | null;
    rule_level: number | null;
    rule_description: string | null;
    agent_id: string | null;
    agent_name: string | null;
    agent_ip: string | null;
    mitre_ids: string[] | null;
    location: string | null;
    raw: unknown;
    raw_truncated: boolean | null;
    // Normalized network columns (phase P24, sql/2026-10-29_p24_wazuh_sources.sql), filled at
    // ingest by lib/alertNetwork.ts from the same extraction this file does — but durably, once,
    // before any later raw truncation. Optional so a caller that hasn't added them to its SELECT
    // yet still compiles and still gets the raw-JSON-derived tuple exactly as before.
    src_ip?: string | null;
    src_port?: number | null;
    dst_ip?: string | null;
    dst_port?: number | null;
    protocol?: string | null;
}

export interface NetworkTuple {
    src_ip: string | null;
    src_port: number | null;
    dst_ip: string | null;
    dst_port: number | null;
    protocol: string | null;
}

const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

function ip(v: unknown): string | null {
    if (typeof v !== 'string') return null;
    const s = v.trim();
    return s && isIP(s) ? s : null;
}

function port(v: unknown): number | null {
    const s = typeof v === 'number' ? String(v) : typeof v === 'string' ? v.trim() : '';
    if (!/^\d{1,5}$/.test(s)) return null;
    const n = Number(s);
    return n <= 65535 ? n : null;
}

function protocol(v: unknown): string | null {
    if (typeof v !== 'string') return null;
    const s = v.trim();
    return s && s.length <= 32 && /^[A-Za-z0-9._-]+$/.test(s) ? s : null;
}

/** First non-null of the candidates, each already validated. */
const pick = <T>(...vals: (T | null)[]): T | null => vals.find((v) => v !== null) ?? null;

export function extractNetwork(raw: unknown, rawTruncated: boolean | null): NetworkTuple {
    const none: NetworkTuple = { src_ip: null, src_port: null, dst_ip: null, dst_port: null, protocol: null };
    if (rawTruncated) return none;
    const data = obj(obj(raw)?.data);
    if (!data) return none;
    const sysmon = obj(obj(obj(data.win)?.eventdata));
    return {
        src_ip: pick(ip(data.srcip), ip(sysmon?.sourceIp)),
        src_port: pick(port(data.srcport), port(sysmon?.sourcePort)),
        dst_ip: pick(ip(data.dstip), ip(sysmon?.destinationIp)),
        dst_port: pick(port(data.dstport), port(sysmon?.destinationPort)),
        protocol: pick(protocol(data.protocol), protocol(sysmon?.protocol)),
    };
}

const text = (v: string | null) => (v === null ? null : redactString(v));

/** The row's own stored network columns (P24) take priority, field by field, over re-deriving
 * from raw JSON — they survive raw being truncated later, and a caller that selects them gets
 * the canonical values the rest of the app already uses for this alert, not a second, separately
 * re-parsed guess. A caller that hasn't added the columns to its SELECT (row.src_ip etc. simply
 * absent, not null) falls through to exactly the old raw-JSON-derived behaviour, field by field. */
export function networkForExport(row: AlertRowForExport): NetworkTuple {
    const derived = extractNetwork(row.raw, row.raw_truncated);
    return {
        src_ip: pick(ip(row.src_ip ?? null), derived.src_ip),
        src_port: pick(port(row.src_port ?? null), derived.src_port),
        dst_ip: pick(ip(row.dst_ip ?? null), derived.dst_ip),
        dst_port: pick(port(row.dst_port ?? null), derived.dst_port),
        protocol: pick(protocol(row.protocol ?? null), derived.protocol),
    };
}

export function toExportEvent(row: AlertRowForExport, profile: string | null) {
    const event: Record<string, unknown> = {
        id: row.id,
        org_id: row.org_id,
        event_time: row.event_time,
        received_at: row.received_at ?? null,
        severity: row.severity,
        rule: { id: row.rule_id ?? null, level: row.rule_level ?? null, description: text(row.rule_description ?? null) },
        agent: { id: row.agent_id ?? null, name: row.agent_name ?? null, ip: row.agent_ip ?? null },
        mitre_ids: row.mitre_ids ?? null,
        location: text(row.location ?? null),
        network: networkForExport(row),
    };
    if (profileIncludesRaw(profile) && row.raw !== null && row.raw !== undefined) {
        const redacted = redactValue(row.raw);
        if (redacted !== undefined) {
            event.raw = redacted;
            event.raw_truncated = !!row.raw_truncated;
        }
    }
    return event;
}
