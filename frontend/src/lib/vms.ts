// Shared types and helpers for the VMS pages (phase P4). Every value shown comes from /api/vms.

export interface VmsScope {
    id: string; kind: 'domain' | 'ip' | 'cidr' | 'asn'; value: string; include_subdomains: boolean; allow_port_scan: boolean; allow_vuln_scan: boolean;
    /** P27: entries that permit active scanning are 'pending' until the organisation approves them. */
    authorization_reference: string; notes: string | null; status: 'active' | 'revoked' | 'pending' | 'rejected'; approved_by: string | null; approved_at: string | null; expires_at: string;
    /** Scan authorisation (P27; absent before that SQL). */
    request_group_id?: string | null; requested_by?: string | null; requested_at?: string | null;
    approval_method?: 'in_platform' | 'offline_document' | 'passive_registration' | 'legacy' | 'cnii' | null; approval_id?: string | null;
    scan_windows?: VmsScanWindows | null; max_active_jobs?: number | null; rejected_by?: string | null; rejection_reason?: string | null; origin?: string | null;
    /** Hosts, .subdomains, IPs or CIDRs never touched (P13). */
    exclusions?: string[];
    /** false = passive-only scope (P15): no active discovery. Absent before that SQL. */
    allow_discovery?: boolean;
    revoked_by: string | null; revoked_at: string | null;
}
/** When active scans may run under a scope (P27): ISO weekdays 1..7, local HH:MM in `tz`. */
export interface VmsScanWindows { tz: string; windows: { days: number[]; start: string; end: string }[] }
/** Whether an asset's scan target is inside approved scope (P27). */
export interface VmsAuthorisation { status: 'authorised' | 'pending_approval' | 'not_authorised' | 'not_applicable'; activities: ('discovery' | 'ports' | 'vuln')[]; scope_id: string | null; expires_at: string | null }
export interface VmsScan {
    id: string; scope_id: string; kind: 'passive_osint' | 'discovery' | 'ports' | 'vuln_nuclei' | 'vuln_openvas'; targets: string[]; options: { ports?: string };
    status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'; requested_by: string; requested_at: string; started_at: string | null; finished_at: string | null;
    progress: { phase?: string; done?: number; total?: number; message?: string }; error: string | null; summary: Record<string, unknown> | null;
    worker_id: string | null; heartbeat_at: string | null; cancel_requested: boolean; purpose?: string;
    /** Why a queued scan cannot run as things stand (P12); null when nothing stands in its way. */
    attention?: string | null;
}
export interface VmsAsset {
    id: string; asset_type: 'domain' | 'host' | 'ip' | 'endpoint' | 'asn' | 'cidr'; value: string; hostnames: string[]; ips: string[];
    dns: { a?: string[]; aaaa?: string[]; cname?: string[] }; http: { url?: string; status?: number | null; title?: string | null; webserver?: string | null; cdn?: string | null } | null;
    exposure: 'internet' | 'internal' | 'unknown'; alive: boolean | null; owner: string | null; criticality: 'low' | 'medium' | 'high' | 'critical';
    wazuh_agent_id: string | null; discovery_sources: string[]; first_seen: string; last_seen: string; status: 'active' | 'gone';
    /** What the last scan learned about reaching this host (P12; absent before that SQL). */
    last_assessment?: VmsReachAssessment | null; last_assessed_at?: string | null;
    /** Wazuh endpoints (P19; absent before that SQL): what the agent reports, eligibility, next scan. */
    os?: string | null; agent_status?: string | null; agent_last_keepalive?: string | null; agent_groups?: string[];
    scan_eligibility?: VmsEligibility | null; next_scan_at?: string | null;
    /** P27: where the asset came from, and whether it may be scanned under today's scope. */
    sources?: string[]; authorization?: VmsAuthorisation;
}
export type AssessmentOutcome = 'reachable_open' | 'reachable_no_open' | 'unreachable' | 'no_route' | 'insufficient_evidence';
/** What one scan learned about reaching a host (P12). Not the Full Assessment (VmsAssessment, P13). */
export interface VmsReachAssessment {
    outcome: AssessmentOutcome; reason: string; method: 'nmap' | 'httpx';
    host_status?: string | null; host_status_reason?: string | null; port_states?: Record<string, number>; ports_scanned?: number; job_id?: string;
}
export interface VmsEvidence { id: string; target: string; tool: string; content: string; truncated: boolean; bytes: number; sha256: string; created_at: string; expires_at: string }
export interface VmsService { id: string; port: number; protocol: string; service: string | null; product: string | null; version: string | null; source: string; first_seen: string; last_seen: string; status: string }
export interface VmsTech { id: string; name: string; version: string; source: string; first_seen: string; last_seen: string }
export interface VmsEvent { id: string; at: string; event: string; details: Record<string, unknown>; asset_id: string | null; vms_assets?: { value: string; asset_type: string; exposure?: string } | null }

export const fmtWat = (iso: string | null | undefined) =>
    iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT' : '—';

export const SCAN_STATUS_STYLE: Record<VmsScan['status'], string> = {
    queued: 'bg-card-muted text-foreground-muted', running: 'bg-blue/10 text-blue', succeeded: 'bg-green/10 text-green',
    failed: 'bg-red/10 text-red', cancelled: 'bg-card-muted text-foreground-muted',
};
export const SCAN_KIND_LABEL: Record<VmsScan['kind'], string> = {
    passive_osint: 'Passive lookup (no traffic to target)', discovery: 'Discovery (subdomains, DNS, HTTP)', ports: 'Ports & services (Nmap)', vuln_nuclei: 'Vulnerabilities (Nuclei)', vuln_openvas: 'Vulnerabilities (OpenVAS)',
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
export type StepStatus = 'pending' | 'running' | 'completed' | 'findings_detected' | 'inconclusive' | 'failed' | 'not_attempted' | 'unsupported';
/** Steps a retry re-plans (same set as the backend's RETRYABLE). */
export const RETRYABLE_STEPS: StepStatus[] = ['inconclusive', 'failed', 'not_attempted', 'unsupported'];
export type AssessmentStatus = 'in_progress' | 'completed' | 'partial' | 'inconclusive' | 'failed' | 'not_attempted' | 'cancelled';
export interface VmsAssessmentStep {
    kind: string; label: string; decision: 'queued' | 'not_attempted' | 'unsupported'; reason: string; status: StepStatus; detail: string;
    job_id: string | null; previous_job_ids: string[]; finding_ids: string[];
    job: { id: string; status: string; started_at: string | null; finished_at: string | null; outcome: string | null; target_outcomes: Record<string, { outcome: string; reason: string }> | null } | null;
}
export interface VmsAssessment {
    id: string; asset_id: string | null; scope_id: string; target: string; profile: string; requested_by: string; requested_at: string;
    retried_at: string | null; cancelled_at: string | null; status: AssessmentStatus; steps: VmsAssessmentStep[];
    /** What started it (P14/P19): manual, policy, schedule, or event (a managed endpoint's address changed). */
    trigger?: string;
    step_counts: Record<string, number>; progress: { finished: number; total: number };
}
export const STEP_STATUS_LABEL: Record<StepStatus, string> = {
    pending: 'Pending', running: 'Running', completed: 'Completed', findings_detected: 'Findings detected', inconclusive: 'Inconclusive',
    failed: 'Failed', not_attempted: 'Not attempted', unsupported: 'Unsupported',
};
export const STEP_STATUS_STYLE: Record<StepStatus, string> = {
    pending: 'bg-card-muted text-foreground-muted', running: 'bg-blue/10 text-blue', completed: 'bg-green/10 text-green',
    findings_detected: 'bg-orange/10 text-orange', inconclusive: 'bg-amber/10 text-amber', failed: 'bg-red/10 text-red', not_attempted: 'bg-amber/10 text-amber', unsupported: 'bg-amber/10 text-amber',
};
export const ASSESSMENT_STATUS_LABEL: Record<AssessmentStatus, string> = {
    in_progress: 'In progress', completed: 'Completed', partial: 'Partly completed', inconclusive: 'Inconclusive', failed: 'Failed', not_attempted: 'Not attempted', cancelled: 'Cancelled',
};
export const ASSESSMENT_STATUS_STYLE: Record<AssessmentStatus, string> = {
    in_progress: 'bg-blue/10 text-blue', completed: 'bg-green/10 text-green', partial: 'bg-amber/10 text-amber', inconclusive: 'bg-amber/10 text-amber',
    failed: 'bg-red/10 text-red', not_attempted: 'bg-amber/10 text-amber', cancelled: 'bg-card-muted text-foreground-muted',
};

// ── Phase P19: profiles, eligibility, scanner operations, managed endpoints ───────────────────
export const PROFILE_LABEL: Record<string, string> = { discovery: 'Discovery', standard: 'Standard', full: 'Full Assessment', authenticated: 'Authenticated', verification: 'Verification' };
export const TRIGGER_LABEL: Record<string, string> = { manual: 'Manual', policy: 'Automatic (policy)', schedule: 'Scheduled', event: 'Automatic (address changed)' };

export interface VmsProfile {
    id: string; label: string; description: string; steps: string[]; ports: string; engines: string[]; not_covered: string[];
    runnable: boolean; available: boolean | null; availability_note: string | null;
}

export type EligibilityStatus = 'eligible' | 'not_covered' | 'private_no_route' | 'offline' | 'no_address' | 'duplicate_address';
export interface VmsEligibility { status: EligibilityStatus; reason: string; target: string | null; scope_id: string | null; evaluated_at: string }
export const ELIGIBILITY_LABEL: Record<EligibilityStatus, string> = {
    eligible: 'Eligible', not_covered: 'Not in agreed coverage', private_no_route: 'Private — no scanner route', offline: 'Agent offline',
    no_address: 'No address', duplicate_address: 'Shared address (DHCP/NAT)',
};
export const ELIGIBILITY_STYLE: Record<EligibilityStatus, string> = {
    eligible: 'bg-green/10 text-green', not_covered: 'bg-amber/10 text-amber', private_no_route: 'bg-amber/10 text-amber', offline: 'bg-card-muted text-foreground-muted',
    no_address: 'bg-card-muted text-foreground-muted', duplicate_address: 'bg-amber/10 text-amber',
};

export interface VmsEndpoint {
    id: string; name: string; wazuh_agent_id: string | null; ips: string[]; os: string | null; agent_status: string | null; agent_last_keepalive: string | null;
    agent_groups: string[]; status: 'active' | 'gone'; criticality: VmsAsset['criticality']; owner: string | null; last_seen: string;
    eligibility: VmsEligibility | null; last_assessment: { id: string; target: string; profile: string; requested_at: string; cancelled_at: string | null } | null;
    last_assessed_at: string | null; assessed_recently: boolean; next_scan_at: string | null; open_findings: Record<string, number>;
}
export interface VmsEndpointsResponse {
    endpoints: VmsEndpoint[]; eligibility_stored: boolean;
    coverage: { active: number; eligible: number; assessed_last_30_days: number; awaiting_assessment: number; not_eligible: Record<string, number> };
}

export type EngineState = 'available' | 'offline' | 'not_enabled' | 'not_installed' | 'no_worker';
export const ENGINE_STATE_LABEL: Record<EngineState, string> = { available: 'Available', offline: 'Worker offline', not_enabled: 'Installed, not enabled', not_installed: 'Not installed', no_worker: 'No worker' };
export const ENGINE_STATE_STYLE: Record<EngineState, string> = {
    available: 'bg-green/10 text-green', offline: 'bg-amber/10 text-amber', not_enabled: 'bg-card-muted text-foreground-muted', not_installed: 'bg-red/10 text-red', no_worker: 'bg-red/10 text-red',
};
export interface VmsOperations {
    engines: { id: string; label: string; kind: string; state: EngineState; note: string; versions: string[] }[];
    worker_presence: { state: 'online' | 'offline' | 'never'; source: string; online_workers: number; last_seen_at: string | null };
    workers?: { worker_id: string; online: boolean; version: string | null; kinds: string[]; tools: Record<string, boolean>; tool_versions: Record<string, string>; networks: string[]; last_seen_at: string; last_job_at: string | null }[];
    queue: { queued: number; running: number; oldest_queued_at: string | null };
    last_7_days: Record<string, { queued: number; running: number; succeeded: number; inconclusive: number; failed: number; cancelled: number; median_duration_s: number | null }>;
    active: (VmsScan & { assessment_id?: string | null; priority?: number })[];
    recent_failures: (VmsScan & { assessment_id?: string | null; attempts?: number })[];
    wazuh_sync: { last_attempt_at: string | null; last_complete_at: string | null; complete: boolean | null; problem: string | null };
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export const SEVERITY_STYLE: Record<string, string> = {
    critical: 'bg-red/10 text-red', high: 'bg-orange/10 text-orange', medium: 'bg-amber/10 text-amber', low: 'bg-blue/10 text-blue', info: 'bg-card-muted text-foreground-muted',
};
/** "4m 10s" from seconds. */
export const fmtDuration = (s: number | null | undefined) => (s === null || s === undefined ? '—' : s < 60 ? `${Math.round(s)}s` : s < 3600 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`);
/** Progress text from what the worker reported — a percentage only when it reported done/total. */
export function scanProgress(p: VmsScan['progress'] | null | undefined): string {
    if (!p) return '';
    const pct = typeof p.done === 'number' && typeof p.total === 'number' && p.total > 0 ? ` ${p.done}/${p.total}` : '';
    return [p.phase, p.message].filter(Boolean).join(' · ') + pct;
}
