// TheHive — SOAR case management (VPS 6, Phase 2 per NovrSOC_WazuhMigration_ContaboSQL.md).
// Basic Auth (THEHIVE_USER/THEHIVE_PASSWORD), not an API key or a login-then-Bearer flow.
//
// Worth knowing: TheHive 5's published OpenAPI spec (github.com/TheHive-Project/api-docs)
// documents Bearer Token as the security scheme for most endpoints including /api/v1/query,
// obtained via POST /api/v1/login — not Basic Auth directly. Self-hosted instances using a
// Basic-Auth-capable realm (e.g. LocalAuth) commonly also accept `Authorization: Basic` inline
// on API calls, which is what this assumes VPS 6 is configured for. If a live call comes back
// with AuthenticationError, the fallback is a login step: POST /api/v1/login with these same
// credentials to get a session token, then use that as a Bearer token instead — not implemented
// here since Basic Auth was the explicit ask and this hasn't been verified against a live
// TheHive instance (VPS 6 isn't reachable from this dev environment).
//
// Only this module — auth + a connectivity check — is built for now. The in-memory incident
// store in routes/incidentResponse.ts is NOT wired to this yet; that migration (case CRUD,
// replacing the demo data there) is separate, larger scope than the auth mechanism fixed here.

const THEHIVE_URL = process.env.THEHIVE_URL || '';

export function isTheHiveConfigured(): boolean {
    return !!(
        process.env.THEHIVE_URL &&
        process.env.THEHIVE_USER &&
        process.env.THEHIVE_PASSWORD
    );
}

function headers(): Record<string, string> {
    const credentials = Buffer.from(
        `${process.env.THEHIVE_USER}:${process.env.THEHIVE_PASSWORD}`
    ).toString('base64');
    return {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/json',
        'X-Organisation': process.env.THEHIVE_ORG || 'Cybernovr',
    };
}

interface TheHiveResponse<T> {
    status: number;
    json: T | null;
}

async function request<T = unknown>(path: string, method: 'GET' | 'POST' | 'PATCH' = 'GET', body?: unknown): Promise<TheHiveResponse<T>> {
    if (!THEHIVE_URL) throw new Error('THEHIVE_URL environment variable is not set');
    const res = await fetch(`${THEHIVE_URL}${path}`, {
        method,
        headers: headers(),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(10000),
    });
    let json: T | null = null;
    try {
        json = await res.json();
    } catch {
        // empty or non-JSON body — leave json as null rather than throwing
    }
    return { status: res.status, json };
}

/**
 * POST /api/v1/query with a bare `listCase` — the simplest real call that both confirms
 * connectivity and confirms the credentials authenticate. An empty case list ([]) is success,
 * not a "nothing configured" signal; a 401/403 means the Basic Auth credentials were rejected.
 */
export async function testConnection(): Promise<{ ok: boolean; status: number; error?: string }> {
    if (!isTheHiveConfigured()) {
        return { ok: false, status: 0, error: 'THEHIVE_URL/THEHIVE_USER/THEHIVE_PASSWORD not configured' };
    }
    try {
        const { status, json } = await request('/api/v1/query', 'POST', { query: [{ _name: 'listCase' }] });
        if (status === 401 || status === 403) {
            return { ok: false, status, error: 'AuthenticationError — check THEHIVE_USER/THEHIVE_PASSWORD' };
        }
        return {
            ok: status >= 200 && status < 300,
            status,
            error: status >= 400 ? JSON.stringify(json) : undefined,
        };
    } catch (err) {
        return { ok: false, status: 0, error: err instanceof Error ? err.message : String(err) };
    }
}

// ─── Case + task + comment read/write (added for routes/incidentResponse.ts) ──────────────
//
// Covers list/get/create/update on cases, plus tasks and comments (the two primitives the
// NovrSOC incident workbench needs — "Response Tasks" and "Investigation Notes"). Observables
// and stats still aren't called from anywhere in this codebase. Shapes below follow TheHive 5's
// documented REST API (github.com/TheHive-Project/api-docs): reads go through the /api/v1/query
// DSL (same endpoint testConnection() above already uses), writes go through the plain
// /api/v1/case (and /task, /comment) resource endpoints.

export interface TheHiveCase {
    _id: string;
    title: string;
    description?: string;
    severity: 1 | 2 | 3 | 4; // TheHive encodes severity as 1=low..4=critical, not a string
    status?: string;
    stage?: string;
    summary?: string;
    assignee?: string;
    tags?: string[];
    _createdAt?: number;
    _updatedAt?: number;
}

// TheHive's real `status` enum, confirmed live against this org's instance (VPS 6) via
// /api/v1/describe/case — NOT the free-text guess an earlier draft of this file made.
// `status` is the only writable lifecycle field; `stage` (New/InProgress/Closed) is
// server-computed FROM status, not independently settable — confirmed by PATCHing `stage`
// directly (204 success, value silently didn't change) vs. PATCHing `status` to a terminal
// value (stage flipped to Closed as a side effect). There is no "Resolved" status — TheHive's
// terminal values are a real triage classification (true/false positive, duplicate, etc.), not
// a generic "done" flag; PATCHing status:"Resolved" 404s with "CaseStatus Resolved not found".
export type TheHiveStatus = 'New' | 'InProgress' | 'TruePositive' | 'FalsePositive' | 'Indeterminate' | 'Duplicated' | 'Other';

// NovrSOC's simpler 4-state UI (open/investigating/contained/resolved) collapses onto TheHive's
// real fields as follows. "contained" has no TheHive equivalent (it has no concept between
// "being worked" and "closed with a classification") — mapped to InProgress, same as
// investigating; the distinction only lives in NovrSOC's own UI/tags, not in TheHive. Resolving
// defaults to the neutral "Other" classification since the generic "Resolve" action in this UI
// doesn't ask the analyst to pick true/false positive — a future refinement could expose that
// choice properly instead of defaulting it.
// 'escalated' collapses onto InProgress too, same as investigating/contained — it must NOT fall
// through to the ?? 'New' default below, which would silently downgrade an already-open case
// back to New the moment an analyst hits "Escalate" in the workbench UI.
const NOVRSOC_STATUS_TO_THEHIVE: Record<string, TheHiveStatus> = {
    open: 'New', new: 'New',
    investigating: 'InProgress',
    contained: 'InProgress',
    escalated: 'InProgress',
    resolved: 'Other',
};

export function mapNovrSOCStatusToTheHive(status: string): TheHiveStatus {
    return NOVRSOC_STATUS_TO_THEHIVE[status.toLowerCase()] ?? 'New';
}

// Reverse direction: any of TheHive's 5 terminal classifications all read as "resolved" in
// NovrSOC's simpler UI — it doesn't have (and doesn't need) TheHive's finer-grained taxonomy.
const THEHIVE_TERMINAL_STATUSES = new Set(['TruePositive', 'FalsePositive', 'Indeterminate', 'Duplicated', 'Other']);

export function mapTheHiveStatusToNovrSOC(status: string | undefined): 'open' | 'investigating' | 'resolved' {
    if (status === 'InProgress') return 'investigating';
    if (status && THEHIVE_TERMINAL_STATUSES.has(status)) return 'resolved';
    return 'open';
}

// "Contained" is a NovrSOC-only lifecycle step with no TheHive counterpart — both it and
// "investigating" store as InProgress (see NOVRSOC_STATUS_TO_THEHIVE above). Without somewhere
// to keep the distinction, a case marked contained reads back as investigating on the very next
// fetch and the workbench's status bar visibly jumps backwards a step.
//
// It's carried as a tag, which is the mechanism the mapping comment above always pointed at.
// Tags survive status changes, come back on every case read (getCases/getCase both return
// `tags`), and are ignored by TheHive's own workflow, so nothing downstream misreads a contained
// case as something TheHive understands differently.
//
// The tag is only meaningful while a case is still open: resolving supersedes it, so
// resolveNovrSOCStatus checks the real status first and never reports a closed case as
// contained even if the tag was left behind.
export const CONTAINED_TAG = 'novrsoc:contained';

// Marks a case an analyst escalated by hand. Same reasoning as CONTAINED_TAG: TheHive has no
// "escalated" concept, and the escalation is otherwise recorded only as a comment, which can't
// be counted without one extra API call per case. The tag makes escalations both visible on the
// case in TheHive's own UI and countable in a single listCase query.
export const ESCALATED_TAG = 'novrsoc:escalated';

/**
 * The status NovrSOC's UI should show for a case — the four-state lifecycle
 * (open → investigating → contained → resolved), resolving the contained tag against the real
 * TheHive status. Prefer this over mapTheHiveStatusToNovrSOC() anywhere a case is rendered.
 */
export function resolveNovrSOCStatus(c: Pick<TheHiveCase, 'status' | 'tags'>): 'open' | 'investigating' | 'contained' | 'resolved' {
    const base = mapTheHiveStatusToNovrSOC(c.status);
    if (base === 'investigating' && (c.tags ?? []).includes(CONTAINED_TAG)) return 'contained';
    return base;
}

/**
 * The tag list a case should carry after moving to `novrSOCStatus`, given its current tags.
 * Adds the contained marker when moving to contained and strips it on every other transition, so
 * a case that moves contained → investigating doesn't stay stuck showing contained.
 */
export function tagsForStatusChange(currentTags: string[] | undefined, novrSOCStatus: string): string[] {
    const withoutMarker = (currentTags ?? []).filter((t) => t !== CONTAINED_TAG);
    return novrSOCStatus.toLowerCase() === 'contained' ? [...withoutMarker, CONTAINED_TAG] : withoutMarker;
}

/** Exposed for jobs/autoClose.ts — true for any of TheHive's terminal triage classifications. */
export function isTheHiveStatusTerminal(status: string | undefined): boolean {
    return !!status && THEHIVE_TERMINAL_STATUSES.has(status);
}

/**
 * Lists the most recent cases via the query DSL: listCase, newest first, capped at `limit`.
 */
export async function getCases(limit = 50): Promise<TheHiveCase[]> {
    const { status, json } = await request<TheHiveCase[]>('/api/v1/query', 'POST', {
        query: [
            { _name: 'listCase' },
            { _name: 'sort', _fields: [{ _createdAt: 'desc' }] },
            { _name: 'page', from: 0, to: limit },
        ],
    });
    if (status < 200 || status >= 300 || !Array.isArray(json)) {
        throw new Error(`TheHive listCase failed (status ${status}): ${JSON.stringify(json)}`);
    }
    return json;
}

const SEVERITY_TO_THEHIVE: Record<string, 1 | 2 | 3 | 4> = { low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Creates a new case. `severity` accepts NovrSOC's own low/medium/high/critical strings and maps
 * them to TheHive's 1-4 scale. Returns null (rather than throwing) on failure so callers can
 * decide whether to fall back to the in-memory/Wazuh-derived path instead of hard-failing the
 * request.
 */
export async function createCase(params: {
    title: string;
    description?: string;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    tags?: string[];
}): Promise<TheHiveCase | null> {
    try {
        const { status, json } = await request<TheHiveCase>('/api/v1/case', 'POST', {
            title: params.title,
            description: params.description || 'Created via NovrSOC',
            severity: SEVERITY_TO_THEHIVE[params.severity ?? 'high'],
            tags: params.tags ?? ['novrsoc'],
        });
        if (status < 200 || status >= 300 || !json) {
            console.error(`TheHive createCase failed (status ${status}):`, json);
            return null;
        }
        return json;
    } catch (err) {
        console.error('TheHive createCase error:', err);
        return null;
    }
}

// A NovrSOC-shaped display id (INC-{year}-{n}) — the real TheHive `_id` (a raw `~1234567`)
// never gets shown to an analyst anywhere; see routes/incidentResponse.ts's Incident.
// incident_number field comment for why. Shared here so every caller that needs a
// display-friendly id (the workbench list/detail, escalation emails, …) derives the exact same
// value for the same case instead of each inventing its own formatting.
export function deriveIncidentNumber(c: TheHiveCase): string {
    const createdYear = c._createdAt ? new Date(c._createdAt).getFullYear() : new Date().getFullYear();
    const idDigits = (c._id.match(/\d+/g)?.join('') || '0').slice(-4).padStart(4, '0');
    return `INC-${createdYear}-${idDigits}`;
}

/** Maps a TheHive case onto the shape routes/incidentResponse.ts's GET / already returns. */
export function formatCaseForNovrSOC(c: TheHiveCase) {
    const severityMap: Record<number, 'low' | 'medium' | 'high' | 'critical'> = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
    return {
        id: c._id,
        incident_number: deriveIncidentNumber(c),
        title: c.title,
        severity: severityMap[c.severity] ?? 'medium',
        // resolveNovrSOCStatus, not mapTheHiveStatusToNovrSOC — the latter can't return
        // 'contained', so a contained case would render as investigating.
        status: resolveNovrSOCStatus(c),
        thehive_status: c.status ?? 'New', // the real classification, for anyone who wants it verbatim
        summary: c.description ?? c.summary ?? '',
        assignee: c.assignee ?? null,
        opened_at: c._createdAt ? new Date(c._createdAt).toLocaleString() : new Date().toLocaleString(),
        updated_at: c._updatedAt ? new Date(c._updatedAt).toLocaleString() : new Date().toLocaleString(),
        source: 'thehive' as const,
        tags: c.tags ?? [],
    };
}

/** Fetches one case by its TheHive `_id` (the `~1234567` form). Returns null on any failure. */
export async function getCase(id: string): Promise<TheHiveCase | null> {
    try {
        const { status, json } = await request<TheHiveCase>(`/api/v1/case/${encodeURIComponent(id)}`, 'GET');
        if (status < 200 || status >= 300 || !json) return null;
        return json;
    } catch (err) {
        console.error('TheHive getCase error:', err);
        return null;
    }
}

/**
 * Updates a case's status/summary/assignee. Only `status` (the real TheHive enum — see
 * mapNovrSOCStatusToTheHive above) actually changes the case's lifecycle; `stage` is NOT sent
 * here because it isn't independently writable — confirmed live, PATCHing it directly is
 * silently ignored. Returns null on failure rather than throwing, matching createCase's
 * fall-back-friendly convention.
 */
export async function updateCase(id: string, params: { status?: TheHiveStatus; summary?: string; assignee?: string; tags?: string[] }): Promise<TheHiveCase | null> {
    try {
        const body: Record<string, unknown> = {};
        if (params.status) body.status = params.status;
        if (params.summary !== undefined) body.summary = params.summary;
        if (params.assignee) body.assignee = params.assignee;
        // Replaces the whole tag list — TheHive has no add/remove-one operation for tags, so
        // callers must pass the full desired set (see tagsForStatusChange).
        if (params.tags) body.tags = params.tags;

        const { status, json } = await request<TheHiveCase>(`/api/v1/case/${encodeURIComponent(id)}`, 'PATCH', body);
        // TheHive's PATCH returns 204 No Content on success, not the updated object — fetch it
        // separately so callers get a real, current case back either way.
        if (status < 200 || status >= 300) {
            console.error(`TheHive updateCase failed (status ${status}):`, json);
            return null;
        }
        return json ?? getCase(id);
    } catch (err) {
        console.error('TheHive updateCase error:', err);
        return null;
    }
}

export interface TheHiveTask {
    _id: string;
    title: string;
    description?: string;
    status: 'Waiting' | 'InProgress' | 'Completed' | 'Cancel';
    _createdAt?: number;
}

/** Lists a case's tasks via the query DSL — there's no plain GET list endpoint for these. */
export async function getCaseTasks(caseId: string): Promise<TheHiveTask[]> {
    try {
        const { status, json } = await request<TheHiveTask[]>('/api/v1/query', 'POST', {
            query: [{ _name: 'getCase', idOrName: caseId }, { _name: 'tasks' }],
        });
        if (status < 200 || status >= 300 || !Array.isArray(json)) return [];
        return json;
    } catch (err) {
        console.error('TheHive getCaseTasks error:', err);
        return [];
    }
}

export async function createTask(caseId: string, params: { title: string; description?: string }): Promise<TheHiveTask | null> {
    try {
        const { status, json } = await request<TheHiveTask>(`/api/v1/case/${encodeURIComponent(caseId)}/task`, 'POST', {
            title: params.title,
            description: params.description,
        });
        if (status < 200 || status >= 300 || !json) return null;
        return json;
    } catch (err) {
        console.error('TheHive createTask error:', err);
        return null;
    }
}

export interface TheHiveComment {
    _id: string;
    message: string;
    createdBy?: string;
    createdAt?: number;
}

/**
 * Lists a case's comments — the real primitive for "investigation notes." An earlier draft of
 * the incident-notes feature stuffed notes into fake tasks (`addTask(id, { note: content })`);
 * TheHive has a dedicated comment resource, confirmed live (POST /case/{id}/comment,
 * listed via the same tasks-style query-DSL pivot), so notes use that instead.
 */
export async function getCaseComments(caseId: string): Promise<TheHiveComment[]> {
    try {
        const { status, json } = await request<TheHiveComment[]>('/api/v1/query', 'POST', {
            query: [{ _name: 'getCase', idOrName: caseId }, { _name: 'comments' }],
        });
        if (status < 200 || status >= 300 || !Array.isArray(json)) return [];
        return json;
    } catch (err) {
        console.error('TheHive getCaseComments error:', err);
        return [];
    }
}

export async function addComment(caseId: string, message: string): Promise<TheHiveComment | null> {
    try {
        const { status, json } = await request<TheHiveComment>(`/api/v1/case/${encodeURIComponent(caseId)}/comment`, 'POST', { message });
        if (status < 200 || status >= 300 || !json) return null;
        return json;
    } catch (err) {
        console.error('TheHive addComment error:', err);
        return null;
    }
}
