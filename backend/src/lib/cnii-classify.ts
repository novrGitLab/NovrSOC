// Suggests a CNII sector + sub-entity for a scanned IP from its owner, organisation, ASN and
// hostname. It is a suggestion for the analyst, who confirms or changes it before the asset is
// saved. Matching is whole-word (inputs are split on anything that isn't a letter or digit), so
// short keywords like "glo", "nia" or "dam" don't fire inside "global", "california" or
// "amsterdam". When nothing matches the IP is reported as unclassified — never guessed.
import { SECTOR_BY_ID } from './cnii-sectors';

// Keyword groups per sector; `subfield` must be one of that sector's subfields, or '' when the
// keyword identifies the sector but no single sub-entity.
const RULES: Record<string, { keywords: string[]; subfield: string }[]> = {
    power: [
        { keywords: ['nnpc', 'nipco', 'oando', 'total nigeria', 'shell', 'chevron'], subfield: 'Oil & Gas' },
        { keywords: ['nerc', 'aedc', 'ekedc', 'ikedc', 'phed', 'bedc', 'kedco', 'jedc', 'disco', 'genco', 'ndphc', 'transcorp power'], subfield: 'Power Generation & Distribution' },
    ],
    finance: [
        { keywords: ['cbn'], subfield: 'Electronic Transactions / CBN' },
        { keywords: ['zenith', 'gtbank', 'access bank', 'uba', 'firstbank', 'stanbic', 'fidelity', 'polaris', 'keystone', 'nibss', 'interswitch'], subfield: 'Inter-Bank Payment Systems' },
        { keywords: ['ippis'], subfield: 'Federal Civil Service Payroll (IPPIS)' },
        { keywords: ['nhis'], subfield: 'NHIS' },
        { keywords: ['pencom', 'sec nigeria', 'nse', 'fmdq'], subfield: 'Financial Trading' },
    ],
    ict: [
        { keywords: ['ncc'], subfield: 'NCC' },
        { keywords: ['nimc'], subfield: 'NIMC' },
        { keywords: ['nigcomsat'], subfield: 'NigCOMSAT' },
        { keywords: ['galaxy backbone'], subfield: 'Galaxy Backbone' },
        { keywords: ['nira', 'ipnx', 'spectranet', 'swift networks'], subfield: 'ISPs / Exchange Points (NiRA)' },
        { keywords: ['mtn', 'airtel', 'glo', '9mobile', 'nitel'], subfield: 'Communications Companies' },
    ],
    transport: [
        { keywords: ['faan'], subfield: 'FAAN' }, { keywords: ['nama'], subfield: 'NAMA' },
        { keywords: ['npa', 'nigerian ports'], subfield: 'NPA' }, { keywords: ['nimasa'], subfield: 'NIMASA' },
        { keywords: ['nrc', 'nigerian railway'], subfield: 'NRC' }, { keywords: ['ncat'], subfield: 'NCAT' },
        { keywords: ['nimet'], subfield: 'NiMet' }, { keywords: ['aib'], subfield: 'AIB' },
    ],
    health: [
        { keywords: ['ncdc'], subfield: 'NCDC' }, { keywords: ['nafdac'], subfield: 'NAFDAC' },
        { keywords: ['nimr'], subfield: 'NIMR' }, { keywords: ['nphcda'], subfield: 'NPHCDA' },
        { keywords: ['fmoh', 'nnadi'], subfield: '' },
    ],
    defence: [
        { keywords: ['army'], subfield: 'Nigerian Army' }, { keywords: ['navy'], subfield: 'Nigerian Navy' },
        { keywords: ['naf', 'airforce'], subfield: 'NAF' }, { keywords: ['dss'], subfield: 'DSS' },
        { keywords: ['nia'], subfield: 'NIA' }, { keywords: ['efcc'], subfield: 'EFCC' },
        { keywords: ['ndlea'], subfield: 'NDLEA' }, { keywords: ['npf'], subfield: 'NPF' },
        { keywords: ['nscdc'], subfield: 'NSCDC' }, { keywords: ['onsa'], subfield: 'ONSA' },
        { keywords: ['dicon', 'nda', 'ndc'], subfield: 'DICON / NDA / NDC' },
    ],
    publicadmin: [
        { keywords: ['inec'], subfield: 'INEC' }, { keywords: ['firs'], subfield: 'FIRS' },
        { keywords: ['immigration'], subfield: 'Nigeria Immigration Service' },
        { keywords: ['correctional service'], subfield: 'Nigerian Correctional Service' },
        { keywords: ['mdas', 'national assembly', 'presidency', 'aso rock'], subfield: 'MDAs' },
    ],
    education: [
        { keywords: ['jamb'], subfield: 'JAMB' }, { keywords: ['waec'], subfield: 'WAEC' },
        { keywords: ['neco'], subfield: 'NECO' }, { keywords: ['tetfund'], subfield: 'TETFund' },
        { keywords: ['ubec'], subfield: 'UBEC' }, { keywords: ['noun', 'nuc'], subfield: '' },
    ],
    safety: [{ keywords: ['nema'], subfield: 'NEMA' }, { keywords: ['frsc'], subfield: 'FRSC' }],
    food: [{ keywords: ['nirsal'], subfield: 'NIRSAL' }, { keywords: ['fmard', 'adp'], subfield: '' }],
    water: [{ keywords: ['dam', 'water corporation', 'ruwasa', 'lswc'], subfield: 'Dams & Water Stations' }],
    industrial: [
        { keywords: ['textile'], subfield: 'Textile Industry' },
        { keywords: ['automobile'], subfield: 'Automobile Sector' },
        { keywords: ['manufacturing', 'nexim'], subfield: 'Other Critical Industrial Sectors' },
    ],
    mines: [
        { keywords: ['ajaokuta'], subfield: 'Ajaokuta Steel Company' },
        { keywords: ['steel'], subfield: 'Major Mines & Steel Entities' },
        { keywords: ['solid minerals', 'nimec'], subfield: 'Solid Minerals' },
    ],
};

// Fail fast if a rule names a subfield the sector doesn't have.
for (const [sector, rules] of Object.entries(RULES)) {
    for (const r of rules) {
        if (r.subfield && !SECTOR_BY_ID[sector]?.subfields.includes(r.subfield)) {
            throw new Error(`cnii-classify: "${r.subfield}" is not a subfield of ${sector}`);
        }
    }
}

const normalise = (s: string) => ` ${s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()} `;
const hasWord = (text: string, keyword: string) => text.includes(` ${keyword} `);

export interface Classification { sectorId: string; subfield: string; confidence: number }
export const UNCLASSIFIED: Classification = { sectorId: '', subfield: '', confidence: 0 };

export function classifySector(owner = '', org = '', asn = '', hostname = ''): Classification {
    const fields = [owner, org, asn, hostname].map(normalise);
    let best: { sectorId: string; subfield: string; fieldsMatched: number; hits: number } | null = null;

    for (const [sectorId, rules] of Object.entries(RULES)) {
        const matchedFields = new Set<number>();
        const subfieldHits = new Map<string, number>();
        let hits = 0;
        for (const rule of rules) {
            for (const kw of rule.keywords) {
                fields.forEach((f, i) => {
                    if (!hasWord(f, kw)) return;
                    matchedFields.add(i);
                    hits++;
                    subfieldHits.set(rule.subfield, (subfieldHits.get(rule.subfield) ?? 0) + 1);
                });
            }
        }
        if (!hits) continue;
        const better = !best || matchedFields.size > best.fieldsMatched || (matchedFields.size === best.fieldsMatched && hits > best.hits);
        if (better) {
            // Most-hit specific sub-entity wins; '' only if no specific one matched.
            const subfield = [...subfieldHits.entries()].filter(([s]) => s).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';
            best = { sectorId, subfield, fieldsMatched: matchedFields.size, hits };
        }
    }

    if (!best) return UNCLASSIFIED;
    return { sectorId: best.sectorId, subfield: best.subfield, confidence: Math.min(40 + 15 * (best.fieldsMatched - 1), 95) };
}

// ── CNII likelihood ─────────────────────────────────────────────────────────────────────────
// A matched sector means "this looks like it belongs to sector X" — not that the host is
// critical infrastructure. Not every MTN IP is CNII. This second layer weighs independent
// signals so an analyst sees how strong the case is before monitoring the asset.

// Nigerian critical-infrastructure operators by ASN. Each entry was checked against RIPE Stat
// (as-overview holder) on 2026-10-04 and only kept if it actually resolves to a Nigerian
// operator — add new ones the same way. Candidates that did NOT resolve to Nigeria and were
// deliberately excluded: AS20858 (EgyNet, Egypt), AS37705 (TOPNET, Tunisia), AS29614 (Ghana
// Telecom), AS328274 (Banco Int. de Moçambique), AS37558 (Libyan Int. Telecom), AS328088
// (NetOne, Zimbabwe), AS30999 (EMTEL, Mauritius). AS36922 is Nigerian but is United Bank for
// Africa, not ipNX; the real MainOne is AS37282. Verify holder before adding any of these.
export const CNII_OPERATOR_ASNS: Record<string, string> = {
    AS29465: 'MTN Nigeria',
    AS36873: 'Airtel Nigeria',
    AS37148: 'Globacom (Glo)',
    AS37076: '9mobile / EMTS',
    AS36923: 'Swift Networks',
};

const HOSTNAME_SIGNALS = ['core', 'gw', 'gateway', 'router', 'pe', 'border', 'exchange', 'ixp', 'noc', 'backbone', 'infra', 'critical'];
const ORG_SIGNALS = ['backbone', 'exchange', 'gateway', 'core network', 'internet exchange'];
// Ports that point at network core or industrial control systems.
const PORT_SIGNALS: Record<number, string> = {
    179: 'BGP (179)',
    102: 'SCADA / IEC 61850 (102)',
    502: 'Modbus (502)',
    20000: 'DNP3 SCADA (20000)',
};

export type CniiLikelihood = 'confirmed' | 'likely' | 'possible' | 'unlikely';

export interface CniiSignals {
    asn?: string;
    hostname?: string;
    org?: string;
    owner?: string;
    openPorts?: number[];
    maliciousFlags?: string[];
}

export interface CniiAssessment { likelihood: CniiLikelihood; signals: string[] }

const normAsn = (asn: string) => {
    const n = asn.match(/\d+/)?.[0];
    return n ? `AS${n}` : '';
};

/**
 * Rate how likely a scanned asset is CNII, given the matched sector and the scan's signals.
 *   confirmed — ASN is a known CNII operator AND a sector matched
 *   likely    — sector matched AND ≥1 independent signal (operator ASN, hostname, port, org, threat)
 *   possible  — sector matched, no other signal
 *   unlikely  — no sector matched
 * (The prompt's fourth rule overlapped "possible"; a matched sector is always at least
 * "possible", so "unlikely" is reserved for no sector match.)
 */
export function assessCnii(sectorMatched: boolean, s: CniiSignals): CniiAssessment {
    const signals: string[] = [];

    const asn = s.asn ? normAsn(s.asn) : '';
    const operator = asn && CNII_OPERATOR_ASNS[asn];
    if (operator) signals.push(`ASN ${asn} is a known CNII operator (${operator})`);

    const hostLabels = (s.hostname ?? '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    for (const kw of HOSTNAME_SIGNALS) {
        if (hostLabels.includes(kw)) signals.push(`Hostname contains "${kw}"`);
    }

    const ports = s.openPorts ?? [];
    for (const p of ports) {
        if (PORT_SIGNALS[p]) signals.push(`Open port ${PORT_SIGNALS[p]}`);
    }
    if (ports.includes(443) && ports.includes(8443)) signals.push('Open ports 443 + 8443 (management plane)');

    const orgText = `${s.org ?? ''} ${s.owner ?? ''}`.toLowerCase();
    for (const kw of ORG_SIGNALS) {
        if (orgText.includes(kw)) signals.push(`Org/owner mentions "${kw}"`);
    }

    if (s.maliciousFlags?.length) signals.push(`${s.maliciousFlags.length} threat-intel flag(s) on this IP`);

    if (!sectorMatched) return { likelihood: 'unlikely', signals };
    if (operator) return { likelihood: 'confirmed', signals };
    if (signals.length) return { likelihood: 'likely', signals };
    return { likelihood: 'possible', signals };
}
