// Client for the stored, org-scoped alert API (backend routes/alertStore.ts, phase R2).
// Alerts reach that store through the SOAR forwarder -> POST /api/ingest/alerts.
import { apiUrl, apiFetch } from './api';
import type { Severity } from './severity';

export type StoredAlertStatus = 'new' | 'triaged' | 'escalated' | 'closed' | 'false_positive';
export const STORED_ALERT_STATUSES: StoredAlertStatus[] = ['new', 'triaged', 'escalated', 'closed', 'false_positive'];
export const STATUS_LABEL: Record<StoredAlertStatus, string> = {
    new: 'New', triaged: 'Triaged', escalated: 'Escalated', closed: 'Closed', false_positive: 'False positive',
};

export interface StoredAlert {
    id: string;
    wazuh_alert_id: string;
    rule_id: string | null;
    rule_level: number | null;
    rule_description: string | null;
    agent_id: string | null;
    agent_name: string | null;
    agent_ip: string | null;
    severity: Severity;
    mitre_ids: string[] | null;
    wazuh_groups: string[] | null;
    location: string | null;
    raw?: unknown;
    raw_truncated: boolean;
    event_time: string;
    received_at: string;
    status: StoredAlertStatus;
    case_id: string | null;
    // Network and firewall fields (phase P24); absent until the P24 SQL has run, null when the
    // alert carries none.
    src_ip?: string | null;
    src_port?: number | null;
    dst_ip?: string | null;
    dst_port?: number | null;
    protocol?: string | null;
    net_action?: string | null;
    net_direction?: string | null;
    net_interface?: string | null;
    decoder_name?: string | null;
    device_hostname?: string | null;
    // Triage fields (phase P3); absent until the P3 SQL has run.
    assigned_to?: string | null;
    acknowledged_at?: string | null;
    acknowledged_by?: string | null;
    triage_note?: string | null;
}

export interface AlertStats {
    range: string;
    since: string;
    total: number;
    by_severity: Record<Severity, number>;
    by_status: Record<StoredAlertStatus, number>;
    last_received_at: string | null;
    last_event_time: string | null;
    /** The backend's threshold (ALERT_STALE_MINUTES), shared with Platform Health. */
    stale_after_minutes?: number;
}

export const FIREWALL_ACTIONS = ['block', 'reject', 'pass'] as const;
export type FirewallAction = (typeof FIREWALL_ACTIONS)[number];

/** "203.0.113.10:22" / "[2001:db8::1]:443" / the address alone; '—' when there is none. */
export function endpoint(ip: string | null | undefined, port: number | null | undefined): string {
    if (!ip) return '—';
    if (port === null || port === undefined) return ip;
    return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/** Fallback when the backend doesn't say: its default ALERT_STALE_MINUTES. */
export const STALE_AFTER_MINUTES = 60;

export function isStale(lastReceivedAt: string | null, now = Date.now(), minutes = STALE_AFTER_MINUTES): boolean {
    return lastReceivedAt !== null && now - Date.parse(lastReceivedAt) > minutes * 60_000;
}

/**
 * The outcome of a load: data, or why there is none. `notConnected` = the store or the backend
 * is unavailable (503 / network); `error` = it answered with a failure.
 */
export type Loaded<T> = { ok: true; data: T } | { ok: false; notConnected: boolean; error: string; status?: number };

export async function loadJson<T>(path: string, init: RequestInit = {}): Promise<Loaded<T>> {
    try {
        const r = await apiFetch(apiUrl(path), { cache: 'no-store', signal: AbortSignal.timeout(15000), ...init });
        const body = await r.json().catch(() => null);
        if (r.ok && body) return { ok: true, data: body as T };
        return { ok: false, notConnected: r.status === 503, status: r.status, error: body?.error ?? `HTTP ${r.status}` };
    } catch {
        return { ok: false, notConnected: true, error: 'Could not reach the backend' };
    }
}

export const fetchAlertStats = (range: '24h' | '7d' | '30d' = '24h') => loadJson<AlertStats>(`/api/alerts/stats?range=${range}`);

export const watTime = (iso: string) =>
    new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(iso)) + ' WAT';
