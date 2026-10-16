// Shared types and helpers for the VMS pages (phase P4). Every value shown comes from /api/vms.

export interface VmsScope {
    id: string; kind: 'domain' | 'ip' | 'cidr'; value: string; include_subdomains: boolean; allow_port_scan: boolean; allow_vuln_scan: boolean;
    authorization_reference: string; notes: string | null; status: 'active' | 'revoked'; approved_by: string; approved_at: string; expires_at: string;
    /** Hosts, .subdomains, IPs or CIDRs never touched (P13). */
    exclusions?: string[];
    revoked_by: string | null; revoked_at: string | null;
}
export interface VmsScan {
    id: string; scope_id: string; kind: 'discovery' | 'ports' | 'vuln_nuclei' | 'vuln_openvas'; targets: string[]; options: { ports?: string };
    status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'; requested_by: string; requested_at: string; started_at: string | null; finished_at: string | null;
    progress: { phase?: string; done?: number; total?: number; message?: string }; error: string | null; summary: Record<string, unknown> | null;
    worker_id: string | null; heartbeat_at: string | null; cancel_requested: boolean; purpose?: string;
    /** Why a queued scan cannot run as things stand (P12); null when nothing stands in its way. */
    attention?: string | null;
}
export interface VmsAsset {
    id: string; asset_type: 'domain' | 'host' | 'ip' | 'endpoint'; value: string; hostnames: string[]; ips: string[];
    dns: { a?: string[]; aaaa?: string[]; cname?: string[] }; http: { url?: string; status?: number | null; title?: string | null; webserver?: string | null; cdn?: string | null } | null;
    exposure: 'internet' | 'internal' | 'unknown'; alive: boolean | null; owner: string | null; criticality: 'low' | 'medium' | 'high' | 'critical';
    wazuh_agent_id: string | null; discovery_sources: string[]; first_seen: string; last_seen: string; status: 'active' | 'gone';
    /** What the last scan learned about reaching this host (P12; absent before that SQL). */
    last_assessment?: VmsAssessment | null; last_assessed_at?: string | null;
}
export type AssessmentOutcome = 'reachable_open' | 'reachable_no_open' | 'unreachable' | 'no_route' | 'insufficient_evidence';
export interface VmsAssessment {
    outcome: AssessmentOutcome; reason: string; method: 'nmap' | 'httpx';
    host_status?: string | null; host_status_reason?: string | null; port_states?: Record<string, number>; ports_scanned?: number; job_id?: string;
}
export interface VmsEvidence { id: string; target: string; tool: string; content: string; truncated: boolean; bytes: number; sha256: string; created_at: string; expires_at: string }
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

/** Per-target and per-job scan outcomes (P12). "Unreachable" is from this scanner; never "offline". */
export const OUTCOME_LABEL: Record<string, string> = {
    reachable_open: 'Reachable — open ports found',
    reachable_no_open: 'Reachable — no open ports in the ports scanned',
    unreachable: 'Unreachable from this scanner',
    no_route: 'Not attempted — no route from this worker',
    insufficient_evidence: 'Insufficient evidence',
    assessed: 'Assessed',
    partial: 'Partly assessed',
    failed: 'Scan failed',
};
export const OUTCOME_STYLE: Record<string, string> = {
    reachable_open: 'bg-green/10 text-green', reachable_no_open: 'bg-green/10 text-green', assessed: 'bg-green/10 text-green',
    unreachable: 'bg-amber/10 text-amber', no_route: 'bg-amber/10 text-amber', insufficient_evidence: 'bg-amber/10 text-amber', partial: 'bg-amber/10 text-amber',
    failed: 'bg-red/10 text-red',
};
/** "997 filtered · 3 closed" from nmap port-state counts. */
export const portStates = (c: Record<string, number> | undefined) => Object.entries(c ?? {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${v} ${k}`).join(' · ');

/** Full Assessment (P13). Status is derived by the backend from the scan jobs. */
export type StepStatus = 'pending' | 'running' | 'completed' | 'findings_detected' | 'failed' | 'not_attempted' | 'unsupported';
export type AssessmentStatus = 'in_progress' | 'completed' | 'partial' | 'failed' | 'not_attempted' | 'cancelled';
export interface VmsAssessmentStep {
    kind: string; label: string; decision: 'queued' | 'not_attempted' | 'unsupported'; reason: string; status: StepStatus; detail: string;
    job_id: string | null; previous_job_ids: string[]; finding_ids: string[];
    job: { id: string; status: string; started_at: string | null; finished_at: string | null; outcome: string | null; target_outcomes: Record<string, { outcome: string; reason: string }> | null } | null;
}
export interface VmsAssessment {
    id: string; asset_id: string | null; scope_id: string; target: string; profile: string; requested_by: string; requested_at: string;
    retried_at: string | null; cancelled_at: string | null; status: AssessmentStatus; steps: VmsAssessmentStep[];
    step_counts: Record<string, number>; progress: { finished: number; total: number };
}
export const STEP_STATUS_LABEL: Record<StepStatus, string> = {
    pending: 'Pending', running: 'Running', completed: 'Completed', findings_detected: 'Findings detected',
    failed: 'Failed', not_attempted: 'Not attempted', unsupported: 'Unsupported',
};
export const STEP_STATUS_STYLE: Record<StepStatus, string> = {
    pending: 'bg-card-muted text-foreground-muted', running: 'bg-blue/10 text-blue', completed: 'bg-green/10 text-green',
    findings_detected: 'bg-orange/10 text-orange', failed: 'bg-red/10 text-red', not_attempted: 'bg-amber/10 text-amber', unsupported: 'bg-amber/10 text-amber',
};
export const ASSESSMENT_STATUS_LABEL: Record<AssessmentStatus, string> = {
    in_progress: 'In progress', completed: 'Completed', partial: 'Partly completed', failed: 'Failed', not_attempted: 'Not attempted', cancelled: 'Cancelled',
};
export const ASSESSMENT_STATUS_STYLE: Record<AssessmentStatus, string> = {
    in_progress: 'bg-blue/10 text-blue', completed: 'bg-green/10 text-green', partial: 'bg-amber/10 text-amber',
    failed: 'bg-red/10 text-red', not_attempted: 'bg-amber/10 text-amber', cancelled: 'bg-card-muted text-foreground-muted',
};
