import { search, replyProblem } from './wazuh-indexer';

export interface WazuhAgent {
    id: string;
    name: string;
    status: string;
    os: string | null;
    ip: string | null;
    lastKeepAlive: string | null;
    group: string[];
}

interface MonitoringHit {
    _source: {
        id?: string;
        name?: string;
        status?: string;
        group?: string[];
        ip?: string;
        lastKeepAlive?: string;
        os?: { name?: string; version?: string };
    };
}

interface SearchResponse {
    aggregations?: { agents?: { buckets?: { key: string; latest?: { hits?: { hits?: MonitoringHit[] } } }[] } };
}

const MONITORING_INDEX = 'wazuh-monitoring-*';

/**
 * Wazuh alert/vulnerability documents only carry agent.name / agent.id — there is no
 * agent.groups field to filter on directly. Group membership only exists in the
 * wazuh-monitoring-* index, so filtering "by group" is a two-step process: resolve the
 * group's agent names here first, then filter other indices by those names.
 *
 * Agent id "000" (the manager) does not check in to itself, so it is not in wazuh-monitoring and
 * is not listed here. It used to be added with an invented status, OS and keep-alive; it is not
 * any organisation's endpoint, and syslog it receives is scoped by sender (lib/orgScope.ts).
 *
 * `strict`: an indexer error reply throws instead of reading as "no agents".
 */
export async function getAgentsForGroup(group: string | null, opts: { strict?: boolean } = {}): Promise<WazuhAgent[]> {
    const res = await search<SearchResponse>(MONITORING_INDEX, {
        size: 0,
        aggs: {
            agents: {
                terms: { field: 'id', size: 5000 },
                aggs: { latest: { top_hits: { size: 1, sort: [{ timestamp: { order: 'desc' } }] } } },
            },
        },
    });
    if (opts.strict) {
        const problem = replyProblem(res, MONITORING_INDEX);
        if (problem) throw new Error(problem);
    }

    const buckets = res?.aggregations?.agents?.buckets ?? [];
    let agents: WazuhAgent[] = buckets
        .map((b) => b.latest?.hits?.hits?.[0]?._source)
        .filter((a): a is NonNullable<typeof a> => Boolean(a))
        .map((a) => ({
            id: a.id ?? '',
            name: a.name ?? 'Unknown',
            status: a.status ?? 'unknown',
            os: a.os?.name ? `${a.os.name} ${a.os.version ?? ''}`.trim() : null,
            ip: a.ip ?? null,
            lastKeepAlive: a.lastKeepAlive ?? null,
            group: a.group ?? [],
        }));

    if (group) {
        agents = agents.filter((a) => a.group.includes(group));
    }
    return agents;
}

export async function getAgentNamesForGroup(group: string | null): Promise<string[]> {
    const agents = await getAgentsForGroup(group);
    return agents.map((a) => a.name);
}
