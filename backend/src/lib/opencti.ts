// OpenCTI GraphQL client: the shared query helper (also used by Email Security) and the CNII IP
// lookup. Checked against OpenCTI's GraphQL schema: Filter.key is [String!]!, and "value" is a
// valid filter key for observables but not for Indicators (OpenCTI 6 rejects unknown keys), so
// the lookup goes through the IP observable — its linked indicators and relationships — plus a
// full-text indicator search for indicators that exist without an observable.
import { severityFromScore } from './severity';

export const openctiConfigured = () => !!(process.env.OPENCTI_URL && process.env.OPENCTI_TOKEN);

export async function openctiQuery<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    let r: Response;
    try {
        r = await fetch(`${process.env.OPENCTI_URL!.replace(/\/$/, '')}/graphql`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.OPENCTI_TOKEN}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ query, variables }),
            signal: AbortSignal.timeout(15_000),
        });
    } catch (err) {
        throw new Error(`OpenCTI could not be reached: ${(err as Error).message}`);
    }
    const d = (await r.json().catch(() => null)) as { data?: T; errors?: { message: string }[] } | null;
    if (!r.ok || !d || d.errors?.length) throw new Error(d?.errors?.[0]?.message ?? `OpenCTI answered HTTP ${r.status}`);
    return d.data as T;
}

const RELATED = `
    ... on BasicObject { id entity_type }
    ... on ThreatActor { name }
    ... on IntrusionSet { name }
    ... on Campaign { name }
    ... on Malware { name }
    ... on Tool { name }
    ... on AttackPattern { name x_mitre_id }
    ... on Vulnerability { name }
    ... on Indicator { name }
    ... on StixCyberObservable { observable_value }
`;

export const LOOKUP_IP_QUERY = `
query CniiLookupIp($filters: FilterGroup, $search: String) {
  stixCyberObservables(types: ["IPv4-Addr", "IPv6-Addr"], filters: $filters, first: 5) {
    edges {
      node {
        id
        entity_type
        observable_value
        x_opencti_score
        indicators(first: 25) {
          edges { node { id name confidence indicator_types revoked x_opencti_score } }
        }
        stixCoreRelationships(first: 50) {
          edges {
            node {
              relationship_type
              confidence
              from { ${RELATED} }
              to { ${RELATED} }
            }
          }
        }
      }
    }
  }
  indicators(search: $search, first: 25) {
    edges { node { id name pattern confidence indicator_types revoked x_opencti_score } }
  }
}`;

export interface OpenCTIIntel { source: 'OpenCTI'; description: string; severity: 'critical' | 'high' | 'medium' | 'low' }
export interface OpenCTIResult { threatIntel: OpenCTIIntel[]; raw: unknown }

interface Related { id?: string; entity_type?: string; name?: string; x_mitre_id?: string; observable_value?: string }
interface IndicatorNode { id: string; name?: string; pattern?: string; confidence?: number | null; indicator_types?: string[] | null; revoked?: boolean }
interface LookupData {
    stixCyberObservables?: { edges: { node: {
        id: string;
        indicators?: { edges: { node: IndicatorNode }[] };
        stixCoreRelationships?: { edges: { node: { relationship_type: string; confidence?: number | null; from?: Related | null; to?: Related | null } }[] };
    } }[] };
    indicators?: { edges: { node: IndicatorNode }[] };
}

export function severityFromConfidence(c: number | null | undefined): OpenCTIIntel['severity'] {
    return severityFromScore(c ?? 0);
}

const describe = (r: Related) => {
    const name = r.name ?? r.observable_value ?? r.id ?? 'unknown';
    return `${r.x_mitre_id ? `${r.x_mitre_id} ` : ''}${name}${r.entity_type ? ` (${r.entity_type})` : ''}`;
};

export function parseLookup(ip: string, data: LookupData): OpenCTIIntel[] {
    const out: OpenCTIIntel[] = [];
    const seenIndicators = new Set<string>();
    const addIndicator = (i: IndicatorNode) => {
        if (i.revoked || seenIndicators.has(i.id)) return;
        seenIndicators.add(i.id);
        const types = i.indicator_types?.length ? ` [${i.indicator_types.join(', ')}]` : '';
        out.push({ source: 'OpenCTI', description: `Indicator: ${i.name ?? i.pattern ?? i.id}${types}`, severity: severityFromConfidence(i.confidence) });
    };

    for (const { node } of data.stixCyberObservables?.edges ?? []) {
        for (const { node: rel } of node.stixCoreRelationships?.edges ?? []) {
            // The IP can be either end of the relationship; describe the other end.
            const other = rel.from?.id === node.id ? rel.to : rel.from;
            if (!other) continue;
            out.push({ source: 'OpenCTI', description: `${rel.relationship_type} ${describe(other)}`, severity: severityFromConfidence(rel.confidence) });
        }
        for (const { node: ind } of node.indicators?.edges ?? []) addIndicator(ind);
    }
    // Full-text search is fuzzy; keep only indicators that are about this exact IP.
    const exact = new RegExp(`(^|[^0-9a-f.:])${ip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^0-9a-f.:])`, 'i');
    for (const { node: ind } of data.indicators?.edges ?? []) {
        if (ind.name === ip || exact.test(ind.pattern ?? '')) addIndicator(ind);
    }
    return out;
}

export async function lookupIP(ip: string): Promise<OpenCTIResult> {
    if (!openctiConfigured()) throw new Error('OpenCTI is not configured (OPENCTI_URL, OPENCTI_TOKEN).');
    const raw = await openctiQuery<LookupData>(LOOKUP_IP_QUERY, {
        filters: { mode: 'and', filters: [{ key: ['value'], values: [ip] }], filterGroups: [] },
        search: ip,
    });
    return { threatIntel: parseLookup(ip, raw), raw };
}
