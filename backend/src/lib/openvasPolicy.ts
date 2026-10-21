// OpenVAS execution policy (phase P22). Greenbone runs intrusive, long scans, so the backend allows
// them only when an operator has switched them on AND named the scopes whose authorisation is
// confirmed for OpenVAS — independently of what a worker advertises and of a scope's own
// allow_vuln_scan flag. Both settings default to off (fail closed).
//
//   VMS_OPENVAS_ENABLED=true                     OpenVAS may run at all on this server
//   VMS_OPENVAS_SCOPE_IDS=<uuid>,<uuid>          the only scopes OpenVAS may run against
//
// Enforced where every scan is queued (routes/vms.ts queueScan: manual scans, assessments,
// schedules, policies, verification rescans, retries) and again when a worker claims a job
// (routes/vmsWorker.ts), so a job queued before the policy changed is never handed out.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const openvasEnabled = () => process.env.VMS_OPENVAS_ENABLED === 'true';
export const openvasScopeIds = () => (process.env.VMS_OPENVAS_SCOPE_IDS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter((s) => UUID.test(s));

export const OPENVAS_DISABLED = 'OpenVAS scanning is switched off on this server (VMS_OPENVAS_ENABLED). It is switched on only once the scanner host and the target are authorised.';
export const OPENVAS_SCOPE_NOT_APPROVED = 'This scope is not approved for OpenVAS scanning (VMS_OPENVAS_SCOPE_IDS): its authorisation for Greenbone scans has not been confirmed.';

/** Whether an OpenVAS scan may run against a scope; the reason when not. */
export function openvasAllowed(scopeId: string | null | undefined): { allowed: true } | { allowed: false; reason: string } {
    if (!openvasEnabled()) return { allowed: false, reason: OPENVAS_DISABLED };
    if (!scopeId || !openvasScopeIds().includes(scopeId.toLowerCase())) return { allowed: false, reason: OPENVAS_SCOPE_NOT_APPROVED };
    return { allowed: true };
}
