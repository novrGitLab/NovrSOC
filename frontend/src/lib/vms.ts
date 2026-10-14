// Shared types and helpers for the VMS pages (phase P4). Every value shown comes from /api/vms.

export interface VmsScope {
    id: string; kind: 'domain' | 'ip' | 'cidr'; value: string; include_subdomains: boolean; allow_port_scan: boolean; allow_vuln_scan: boolean;
    authorization_reference: string; notes: string | null; status: 'active' | 'revoked'; approved_by: string; approved_at: string; expires_at: string;
    revoked_by: string | null; revoked_at: string | null;
}
export interface VmsScan {
    id: string; scope_id: string; kind: 'discovery' | 'ports' | 'vuln_nuclei' | 'vuln_openvas'; targets: string[]; options: { ports?: string };
    status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'; requested_by: string; requested_at: string; started_at: string | null; finished_at: string | null;
    progress: { phase?: string; done?: number; total?: number; message?: string }; error: string | null; summary: Record<string, unknown> | null;
    worker_id: string | null; heartbeat_at: string | null; cancel_requested: boolean; purpose?: string;
}
export interface VmsAsset {
    id: string; asset_type: 'domain' | 'host' | 'ip' | 'endpoint'; value: string; hostnames: string[]; ips: string[];
    dns: { a?: string[]; aaaa?: string[]; cname?: string[] }; http: { url?: string; status?: number | null; title?: string | null; webserver?: string | null; cdn?: string | null } | null;
    exposure: 'internet' | 'internal' | 'unknown'; alive: boolean | null; owner: string | null; criticality: 'low' | 'medium' | 'high' | 'critical';
    wazuh_agent_id: string | null; discovery_sources: string[]; first_seen: string; last_seen: string; status: 'active' | 'gone';
}
export interface VmsService { id: string; port: number; protocol: string; service: string | null; product: string | null; version: string | null; source: string; first_seen: string; last_seen: string; status: string }
export interface VmsTech { id: string; name: string; version: string; source: string; first_seen: string; last_seen: string }
export interface VmsEvent { id: string; at: string; event: string; details: Record<string, unknown>; asset_id: string | null; vms_assets?: { value: string; asset_type: string } | null }

export const fmtWat = (iso: string | null | undefined) =>
    iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT' : '—';

export const SCAN_STATUS_STYLE: Record<VmsScan['status'], string> = {
    queued: 'bg-card-muted text-foreground-muted', running: 'bg-blue/10 text-blue', succeeded: 'bg-green/10 text-green',
    failed: 'bg-red/10 text-red', cancelled: 'bg-card-muted text-foreground-muted',
};
export const SCAN_KIND_LABEL: Record<VmsScan['kind'], string> = {
    discovery: 'Discovery (subdomains, DNS, HTTP)', ports: 'Ports & services (Nmap)', vuln_nuclei: 'Vulnerabilities (Nuclei)', vuln_openvas: 'Vulnerabilities (OpenVAS)',
};
export const EVENT_LABEL: Record<string, string> = {
    asset_new: 'New asset', asset_changed: 'Asset changed', asset_gone: 'Asset gone', service_new: 'New service',
    service_changed: 'Service changed', service_gone: 'Service gone', technology_new: 'New technology',
};
export const CRIT_STYLE: Record<VmsAsset['criticality'], string> = {
    critical: 'bg-red-500/10 text-red-500', high: 'bg-orange/10 text-orange', medium: 'bg-amber/10 text-amber', low: 'bg-card-muted text-foreground-muted',
};

/** Human summary of what an asset event changed. */
export function describeEvent(e: VmsEvent): string {
    const d = e.details ?? {};
    const port = d.port !== undefined ? `${d.port}/${d.protocol ?? 'tcp'}` : '';
    switch (e.event) {
        case 'service_new': return `${port} ${[d.service, d.product, d.version].filter(Boolean).join(' ')}`.trim();
        case 'service_gone': return `${port} no longer open`;
        case 'service_changed': return `${port} changed${d.reappeared ? ' (reappeared)' : ''}`;
        case 'technology_new': return `${d.name}${d.version ? ` ${d.version}` : ''}`;
        case 'asset_changed': return Object.keys(d).join(', ') + ' changed';
        default: return String(d.value ?? '');
    }
}
