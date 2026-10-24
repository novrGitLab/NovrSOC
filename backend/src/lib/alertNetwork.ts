// Network and firewall fields of one Wazuh alert (P22), read from the alert itself — the stored
// `raw` or an indexer `_source`. Anything absent or malformed is null; nothing is inferred.
//
//   5-tuple      lib/exportEvent.ts extractNetwork(): data.srcip/srcport/dstip/dstport/protocol,
//                with Sysmon's data.win.eventdata.* per field when the Wazuh one is absent;
//                protocol also from data.proto (pf / OPNsense filterlog decoders use it)
//   action       data.action — pass / block / reject from the OPNsense filterlog decoder (lowercased)
//   direction    data.direction, else data.dir — in / out
//   interface    data.interface, else data.iface, data.ifname, data.real_interface
//   decoder      decoder.name (which Wazuh decoder produced the alert)
//   device       predecoder.hostname (the syslog header's host; agents are named by agent.name)
//
// The custom OPNsense decoder's field names must be confirmed against one real alert
// (`wazuh-logtest` / the indexer): add a name to the candidate lists below if it differs.

import { extractNetwork } from './exportEvent';

export interface AlertNetwork {
    src_ip: string | null;
    src_port: number | null;
    dst_ip: string | null;
    dst_port: number | null;
    protocol: string | null;
    net_action: string | null;
    net_direction: string | null;
    net_interface: string | null;
    decoder_name: string | null;
    device_hostname: string | null;
}

/** The stored-alert columns this module fills (sql/2026-10-28_p22_wazuh_sources.sql). */
export const NETWORK_COLUMNS = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'net_action', 'net_direction', 'net_interface', 'decoder_name', 'device_hostname'] as const;

export const NONE: AlertNetwork = {
    src_ip: null, src_port: null, dst_ip: null, dst_port: null, protocol: null,
    net_action: null, net_direction: null, net_interface: null, decoder_name: null, device_hostname: null,
};

const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

/** A short identifier-like token (lowercased when `lower`), else null. */
function token(v: unknown, max: number, lower: boolean): string | null {
    if (typeof v !== 'string' && typeof v !== 'number') return null;
    const s = String(v).trim();
    if (!s || s.length > max || !/^[A-Za-z0-9._:/@-]+$/.test(s)) return null;
    return lower ? s.toLowerCase() : s;
}

const first = (data: Record<string, unknown>, keys: string[], max: number, lower: boolean): string | null => {
    for (const k of keys) {
        const t = token(data[k], max, lower);
        if (t) return t;
    }
    return null;
};

export function alertNetwork(alert: unknown): AlertNetwork {
    const a = obj(alert);
    if (!a) return { ...NONE };
    const data = obj(a.data) ?? {};
    const net = extractNetwork(a, false);
    const decoder = token(obj(a.decoder)?.name, 128, false);
    const host = token(obj(a.predecoder)?.hostname, 255, false);
    return {
        ...net,
        protocol: net.protocol ? net.protocol.toLowerCase() : first(data, ['proto', 'protoname'], 32, true),
        net_action: first(data, ['action'], 32, true),
        net_direction: first(data, ['direction', 'dir'], 16, true),
        net_interface: first(data, ['interface', 'iface', 'ifname', 'real_interface'], 64, false),
        decoder_name: decoder,
        device_hostname: host,
    };
}

/** Stored columns for an alert: none at all when raw was truncated (its fields are not available). */
export function networkColumns(raw: unknown, rawTruncated: boolean): AlertNetwork {
    return rawTruncated ? { ...NONE } : alertNetwork(raw);
}

/** A write failed because the P22 columns aren't there yet (migration not applied). */
export const missingNetworkColumns = (e: { message?: string } | null | undefined): boolean =>
    !!e && new RegExp(NETWORK_COLUMNS.join('|')).test(e.message ?? '');

/** `row` without the P22 columns, for a store that doesn't have them yet. */
export function withoutNetworkColumns<T extends Record<string, unknown>>(row: T): T {
    const out = { ...row };
    for (const c of NETWORK_COLUMNS) delete out[c];
    return out;
}

export const FIREWALL_ACTIONS = ['pass', 'block', 'reject'] as const;
