// One alert as pushed to Stellar Cyber's webhook ingest (phase X3, jobs/stellarPush.ts).
//
// Built on the export event (lib/exportEvent.ts) so both outbound paths share one 5-tuple
// extraction and one redaction. On top of it:
//   • the 5-tuple again as flat top-level fields — srcip, dstip, srcport, dstport, proto — the
//     names Stellar's normaliser reads for its network tuple (`aella_tuples`); the nested
//     `network` object stays for anything reading the export shape
//   • security context from the stored Wazuh alert: rule groups, MITRE tactics/techniques,
//     decoder, action, users, process (Sysmon), file integrity (syscheck), URL, manager
//   • full_log, redacted and capped
// Every value comes from the stored alert; anything missing or malformed is null — nothing is
// invented. Free text (command lines, URLs, full_log, descriptions) goes through redactString(),
// and a value whose redaction fails is dropped. raw is included only for the 'standard' profile.

import { toExportEvent, type AlertRowForExport, type NetworkTuple } from './exportEvent';
import { redactString } from './redact';

export const STELLAR_EVENT_TYPE = 'security.alert';
export const FULL_LOG_MAX = 8 * 1024;
const TEXT_MAX = 2048;

const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

/** A trimmed, redacted, length-capped string, or null. */
function str(v: unknown, max = TEXT_MAX): string | null {
    if (typeof v !== 'string' && typeof v !== 'number') return null;
    const s = String(v).trim();
    if (!s) return null;
    const r = redactString(s.length > max ? s.slice(0, max) : s);
    return r === null || r === '' ? null : r;
}

/** Up to 50 non-empty, capped strings from an array (or a single string), or null. */
function strList(v: unknown, max = 256): string[] | null {
    const arr = Array.isArray(v) ? v : typeof v === 'string' ? [v] : [];
    const out = arr.map((x) => str(x, max)).filter((x): x is string => x !== null).slice(0, 50);
    return out.length ? [...new Set(out)] : null;
}

function hex(v: unknown, len: number): string | null {
    return typeof v === 'string' && new RegExp(`^[0-9a-fA-F]{${len}}$`).test(v.trim()) ? v.trim().toLowerCase() : null;
}

/** Sysmon's "SHA1=…,MD5=…,SHA256=…,IMPHASH=…" hashes string. */
function sysmonHashes(v: unknown): { md5: string | null; sha1: string | null; sha256: string | null } {
    const out = { md5: null as string | null, sha1: null as string | null, sha256: null as string | null };
    if (typeof v !== 'string') return out;
    for (const part of v.split(',')) {
        const [k, val] = part.split('=');
        const key = (k ?? '').trim().toUpperCase();
        if (key === 'MD5') out.md5 = hex(val, 32);
        if (key === 'SHA1') out.sha1 = hex(val, 40);
        if (key === 'SHA256') out.sha256 = hex(val, 64);
    }
    return out;
}

const PROTO_NUM: Record<string, number> = { icmp: 1, tcp: 6, udp: 17, gre: 47, esp: 50, icmpv6: 58, sctp: 132 };

/** Security context from the stored raw Wazuh alert. All null when raw is missing or was truncated. */
export function extractSecurityContext(raw: unknown, rawTruncated: boolean | null) {
    const r = rawTruncated ? null : obj(raw);
    const rule = obj(r?.rule);
    const mitre = obj(rule?.mitre);
    const data = obj(r?.data);
    const win = obj(obj(data?.win)?.eventdata);
    const syscheck = obj(r?.syscheck);
    const hashes = sysmonHashes(win?.hashes);
    return {
        rule_groups: strList(rule?.groups),
        mitre_tactics: strList(mitre?.tactic),
        mitre_techniques: strList(mitre?.technique),
        decoder: str(obj(r?.decoder)?.name, 128),
        manager: str(obj(r?.manager)?.name, 256),
        action: str(data?.action, 128),
        user: {
            src: str(data?.srcuser ?? win?.subjectUserName, 256),
            dst: str(data?.dstuser ?? win?.targetUserName ?? win?.user, 256),
        },
        process: {
            name: str(win?.image, 1024),
            command_line: str(win?.commandLine),
            parent_name: str(win?.parentImage, 1024),
            parent_command_line: str(win?.parentCommandLine),
            pid: str(win?.processId, 16),
            md5: hashes.md5,
            sha1: hashes.sha1,
            sha256: hashes.sha256,
        },
        file: {
            path: str(syscheck?.path, 1024),
            change: str(syscheck?.event, 32),
            md5: hex(syscheck?.md5_after, 32),
            sha1: hex(syscheck?.sha1_after, 40),
            sha256: hex(syscheck?.sha256_after, 64),
        },
        url: str(data?.url),
        full_log: str(r?.full_log, FULL_LOG_MAX),
    };
}

export function toStellarEvent(row: AlertRowForExport, profile: string | null) {
    const ev = toExportEvent(row, profile);
    const net = ev.network as NetworkTuple;
    const proto = net.protocol ? net.protocol.toLowerCase() : null;
    const { id, received_at, event_time, org_id, ...rest } = ev;
    return {
        event_id: id,
        event_type: STELLAR_EVENT_TYPE,
        occurred_at: event_time,
        received_at,
        source: 'NovrSOC',
        sensor: 'wazuh',
        schema_version: '1',
        tenant_ref: org_id,
        srcip: net.src_ip,
        dstip: net.dst_ip,
        srcport: net.src_port,
        dstport: net.dst_port,
        proto,
        proto_num: proto ? (PROTO_NUM[proto] ?? null) : null,
        ...rest,
        network: net,
        ...extractSecurityContext(row.raw, row.raw_truncated),
    };
}
