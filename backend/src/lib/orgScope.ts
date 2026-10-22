// Organisation scope for Wazuh data read straight from the indexer or the Manager API (P22).
//
// Stored alerts (routes/alertStore.ts) carry an org_id. The indexer and the Manager API do not:
// a wazuh-alerts document only names its agent and, for syslog the manager receives itself, the
// sender's address in `location`. Every route that reads them limits the query to what the
// request's organisation (lib/resolveOrg.ts) owns, by the same rules ingest uses:
//
//   • an agent belongs to an organisation when its Wazuh groups map (wazuh_group_org_map) to that
//     organisation and no other. An agent whose groups map to several organisations belongs to
//     none of them — never guessed. Agent 000 (the manager) has no group and is never owned.
//   • syslog the manager receives itself (OPNsense and other agentless senders) arrives as agent
//     000 with `location` = the sender's address. It belongs to the organisation that address is
//     mapped to in wazuh_source_org_map, and to nobody when it is not mapped.
//
// Nothing here falls back to "everything": with no owned agents or sources the filter matches
// nothing, and when ownership cannot be worked out (database, Manager API and indexer all
// unavailable) the caller gets a ScopeError, never an unfiltered query.
//
// The inventory (agents with groups, both maps) is cached for 60 s; the admin routes that change
// a map clear it.

import type { Request, Response } from 'express';
import { getSupabase } from '../services/geoEnrichment';
import { agentsAvailable, getAgents } from '../services/wazuh';
import { getAgentsForGroup } from './wazuh-group';
import { requestOrg } from './resolveOrg';

export interface ScopedAgent {
    id: string;
    name: string;
    ip: string | null;
    os: string | null;
    status: string;
    lastKeepAlive: string | null;
    version: string | null;
    group: string[];
}

export interface OrgScope {
    orgId: string;
    /** Wazuh groups mapped to this organisation. */
    groups: string[];
    /** Agents this organisation owns (narrowed to one group when one was asked for). */
    agents: ScopedAgent[];
    agentIds: string[];
    /** Syslog sender addresses (agent 000 `location`) this organisation owns. */
    locations: string[];
    /** Where the agent list came from. */
    agentSource: 'manager' | 'monitoring';
}

export class ScopeError extends Error {
    constructor(public status: 403 | 503, message: string) {
        super(message);
    }
}

interface Inventory {
    agents: ScopedAgent[];
    agentSource: 'manager' | 'monitoring';
    /** group -> organisations it is mapped to */
    groupOrgs: Map<string, Set<string>>;
    /** location -> organisation */
    sourceOrg: Map<string, string>;
    at: number;
}

const TTL_MS = 60_000;
let cache: Inventory | null = null;
let inflight: Promise<Inventory> | null = null;

/** Forget the cached inventory (after a map changes; and between tests). */
export function resetOrgScopeCache(): void {
    cache = null;
    inflight = null;
}

/** Wazuh agent ids are zero-padded to three digits in the indexer ('1' -> '001'). */
export const padAgentId = (id: string): string => (/^\d+$/.test(id) ? id.padStart(3, '0') : id);

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

async function loadAgents(): Promise<{ agents: ScopedAgent[]; source: 'manager' | 'monitoring' }> {
    let managerError: string | null = null;
    if (agentsAvailable()) {
        try {
            const list = await getAgents();
            return {
                source: 'manager',
                agents: list.map((a) => ({ id: padAgentId(a.id), name: a.name, ip: a.ip, os: a.os, status: a.status, lastKeepAlive: a.last_keepalive, version: a.version, group: a.group })),
            };
        } catch (e) {
            managerError = errText(e);
        }
    }
    // The indexer's wazuh-monitoring-* snapshot carries the same groups (the VMS sync uses it).
    try {
        const list = await getAgentsForGroup(null, { strict: true });
        return {
            source: 'monitoring',
            agents: list.map((a) => ({ id: padAgentId(a.id), name: a.name, ip: a.ip, os: a.os, status: a.status, lastKeepAlive: a.lastKeepAlive, version: null, group: a.group })),
        };
    } catch (e) {
        throw new ScopeError(503, `Cannot work out which Wazuh agents this organisation owns: ${managerError ? `Manager API: ${managerError}; ` : ''}indexer: ${errText(e)}`);
    }
}

async function loadInventory(): Promise<Inventory> {
    const supabase = getSupabase();
    if (!supabase) throw new ScopeError(503, 'Cannot work out organisation ownership of Wazuh data: database not configured');
    const [groupRes, sourceRes, agents] = await Promise.all([
        supabase.from('wazuh_group_org_map').select('wazuh_group, org_id'),
        supabase.from('wazuh_source_org_map').select('location, org_id'),
        loadAgents(),
    ]);
    if (groupRes.error) throw new ScopeError(503, `Wazuh group map unavailable: ${groupRes.error.message.slice(0, 120)}`);
    const groupOrgs = new Map<string, Set<string>>();
    for (const r of groupRes.data ?? []) {
        const g = String(r.wazuh_group);
        groupOrgs.set(g, (groupOrgs.get(g) ?? new Set<string>()).add(String(r.org_id)));
    }
    const sourceOrg = new Map<string, string>();
    if (sourceRes.error) {
        // Before sql/2026-10-28_p22_wazuh_sources.sql runs there are simply no source mappings.
        if (!/wazuh_source_org_map/.test(sourceRes.error.message ?? '')) throw new ScopeError(503, `Wazuh source map unavailable: ${sourceRes.error.message.slice(0, 120)}`);
    } else {
        for (const r of sourceRes.data ?? []) sourceOrg.set(String(r.location), String(r.org_id));
    }
    return { agents: agents.agents, agentSource: agents.source, groupOrgs, sourceOrg, at: Date.now() };
}

async function inventory(): Promise<Inventory> {
    if (cache && Date.now() - cache.at < TTL_MS) return cache;
    if (!inflight) {
        inflight = loadInventory().then((inv) => { cache = inv; return inv; }).finally(() => { inflight = null; });
    }
    return inflight;
}

/** The organisations an agent's groups resolve to (exactly one = owned; ingest's rule). */
export function orgsForGroups(groups: string[], groupOrgs: Map<string, Set<string>>): string[] {
    const orgs = new Set<string>();
    for (const g of groups) for (const o of groupOrgs.get(g) ?? []) orgs.add(o);
    return [...orgs];
}

/**
 * What `orgId` owns in Wazuh. `group` narrows to one of its own groups (a ScopeError 403 when the
 * group is not the organisation's — a client-chosen group never widens the scope).
 */
export async function orgScope(orgId: string, opts: { group?: string | null } = {}): Promise<OrgScope> {
    const inv = await inventory();
    const groups = [...inv.groupOrgs.entries()].filter(([, orgs]) => orgs.has(orgId)).map(([g]) => g).sort();
    let agents = inv.agents.filter((a) => {
        const orgs = orgsForGroups(a.group, inv.groupOrgs);
        return orgs.length === 1 && orgs[0] === orgId;
    });
    let locations = [...inv.sourceOrg.entries()].filter(([, o]) => o === orgId).map(([l]) => l).sort();
    const group = opts.group?.trim() || null;
    if (group) {
        if (!groups.includes(group)) throw new ScopeError(403, `Wazuh group "${group.slice(0, 128)}" does not belong to this organisation`);
        agents = agents.filter((a) => a.group.includes(group));
        locations = [];
    }
    return { orgId, groups, agents, agentIds: agents.map((a) => a.id), locations, agentSource: inv.agentSource };
}

// ── Query filters ────────────────────────────────────────────────────────────────────────────

/** Matches no document. */
export const MATCH_NONE = { bool: { must_not: [{ match_all: {} }] } } as const;

/** Filter for wazuh-alerts-*: the organisation's agents, plus agent 000 events from its senders. */
export function alertScopeFilter(scope: OrgScope): Record<string, unknown> {
    const should: Record<string, unknown>[] = [];
    if (scope.agentIds.length > 0) should.push({ terms: { 'agent.id': scope.agentIds } });
    if (scope.locations.length > 0) should.push({ bool: { filter: [{ term: { 'agent.id': '000' } }, { terms: { location: scope.locations } }] } });
    return should.length > 0 ? { bool: { should, minimum_should_match: 1 } } : MATCH_NONE;
}

/** Filter for per-agent state indices (vulnerabilities, packages): the organisation's agents only. */
export function agentStateFilter(scope: OrgScope): Record<string, unknown> {
    return scope.agentIds.length > 0 ? { terms: { 'agent.id': scope.agentIds } } : MATCH_NONE;
}

/** `query` limited by `filter` (query may be undefined: then everything the filter allows). */
export function scoped(query: unknown, filter: Record<string, unknown>): Record<string, unknown> {
    return { bool: { ...(query ? { must: [query] } : {}), filter: [filter] } };
}

export const ownsAgent = (scope: OrgScope, id: string): boolean => scope.agentIds.includes(padAgentId(id));

/**
 * The request's scope, or null after answering with the reason (403 for another organisation's
 * group, 503 when ownership cannot be resolved). Mount behind requirePermission.
 */
export async function requireScope(req: Request, res: Response, group?: string | null): Promise<OrgScope | null> {
    try {
        return await orgScope(requestOrg(req), { group });
    } catch (e) {
        const status = e instanceof ScopeError ? e.status : 503;
        res.status(status).json({ error: errText(e), scope_error: true });
        return null;
    }
}
