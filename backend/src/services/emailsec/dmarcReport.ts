// DMARC aggregate (RUA) report parsing: raw attachment → XML → normalised report.
//
// Receivers send reports as .xml, .xml.gz or .zip. This unpacks all three with node's zlib (no
// archive dependency), then parses the XML with a small strict reader written for this format.
// It is deliberately NOT a general XML parser: DOCTYPE and entity declarations are refused
// outright (no XXE, no billion-laughs), and decompressed size is capped.
import { gunzipSync, inflateRawSync } from 'zlib';

const MAX_XML_BYTES = 20 * 1024 * 1024;
const MAX_RECORDS = 100_000;

// ── Unpacking ──────────────────────────────────────────────────────────────────────────────

/** Returns the report XML from a .xml, .gz or .zip attachment. Throws on anything else. */
export function unpackReport(buf: Buffer): string {
    if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
        return gunzipSync(buf, { maxOutputLength: MAX_XML_BYTES }).toString('utf8');
    }
    if (buf.length >= 4 && buf.readUInt32LE(0) === 0x04034b50) return unzipFirstXml(buf);
    const text = buf.toString('utf8').replace(/^﻿/, '');
    if (!/^\s*</.test(text)) throw new Error('Not a DMARC report: expected XML, gzip or zip.');
    if (text.length > MAX_XML_BYTES) throw new Error('Report is larger than the 20 MB limit.');
    return text;
}

// Reads the zip central directory and inflates the first .xml entry.
function unzipFirstXml(buf: Buffer): string {
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
        if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('Corrupt zip: end of central directory not found.');
    const entries = buf.readUInt16LE(eocd + 10);
    let p = buf.readUInt32LE(eocd + 16);
    for (let n = 0; n < entries; n++) {
        if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('Corrupt zip: bad central directory entry.');
        const method = buf.readUInt16LE(p + 10);
        const compSize = buf.readUInt32LE(p + 20);
        const size = buf.readUInt32LE(p + 24);
        const nameLen = buf.readUInt16LE(p + 28);
        const extraLen = buf.readUInt16LE(p + 30);
        const commentLen = buf.readUInt16LE(p + 32);
        const localOffset = buf.readUInt32LE(p + 42);
        const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
        p += 46 + nameLen + extraLen + commentLen;
        if (!/\.xml$/i.test(name)) continue;
        if (size > MAX_XML_BYTES) throw new Error('Report is larger than the 20 MB limit.');
        const lNameLen = buf.readUInt16LE(localOffset + 26);
        const lExtraLen = buf.readUInt16LE(localOffset + 28);
        const start = localOffset + 30 + lNameLen + lExtraLen;
        const data = buf.subarray(start, start + compSize);
        if (method === 0) return data.toString('utf8');
        if (method === 8) return inflateRawSync(data, { maxOutputLength: MAX_XML_BYTES }).toString('utf8');
        throw new Error(`Unsupported zip compression method ${method}.`);
    }
    throw new Error('The zip contains no .xml report.');
}

// ── Minimal strict XML reader ──────────────────────────────────────────────────────────────

export interface XmlNode { name: string; children: XmlNode[]; text: string }

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
function decode(s: string): string {
    return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
        if (e[0] === '#') {
            const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
            return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : m;
        }
        return ENTITIES[e.toLowerCase()] ?? m;
    });
}

export function parseXml(xml: string): XmlNode {
    if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('DOCTYPE / ENTITY declarations are not accepted in DMARC reports.');
    const root: XmlNode = { name: '#root', children: [], text: '' };
    const stack: XmlNode[] = [root];
    const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<\/\s*([^\s>]+)\s*>|<([^\s/>!?]+)[^>]*?(\/?)>|([^<]+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(xml))) {
        const top = stack[stack.length - 1];
        if (m[1] !== undefined) top.text += m[1];
        else if (m[2] !== undefined) {
            const name = m[2].replace(/^.*:/, '');
            if (stack.length === 1 || top.name !== name) throw new Error(`Malformed XML: unexpected </${m[2]}>.`);
            stack.pop();
        } else if (m[3] !== undefined) {
            const node: XmlNode = { name: m[3].replace(/^.*:/, ''), children: [], text: '' }; // namespace prefixes dropped
            top.children.push(node);
            if (m[4] !== '/') stack.push(node);
        } else if (m[5] !== undefined) {
            top.text += decode(m[5]);
        }
    }
    if (stack.length !== 1) throw new Error(`Malformed XML: <${stack[stack.length - 1].name}> is never closed.`);
    return root;
}

const child = (n: XmlNode | undefined, name: string) => n?.children.find((c) => c.name === name);
const children = (n: XmlNode | undefined, name: string) => n?.children.filter((c) => c.name === name) ?? [];
const text = (n: XmlNode | undefined, name: string) => child(n, name)?.text.trim() || null;

// ── Normalised report ──────────────────────────────────────────────────────────────────────

export interface DmarcReportRecord {
    source_ip: string;
    message_count: number;
    disposition: string | null;
    header_from: string | null;
    envelope_from: string | null;
    spf_result: string | null;
    spf_domain: string | null;
    spf_aligned: boolean;
    dkim_result: string | null;
    dkim_domain: string | null;
    dkim_aligned: boolean;
    dmarc_pass: boolean;
}
export interface DmarcReport {
    reporter: string;
    reporter_email: string | null;
    report_id: string;
    domain: string;
    date_begin: string;
    date_end: string;
    policy_published: { p: string | null; sp: string | null; pct: number | null; adkim: string | null; aspf: string | null };
    records: DmarcReportRecord[];
    message_count: number;
    pass_count: number;
}

const epoch = (s: string | null) => {
    const n = Number(s);
    if (!Number.isFinite(n) || n <= 0) throw new Error('Report date_range is missing or invalid.');
    return new Date(n * 1000).toISOString();
};

/** Parse a report from its XML text. Throws with a readable reason when it isn't one. */
export function parseDmarcReport(xml: string): DmarcReport {
    const feedback = child(parseXml(xml), 'feedback');
    if (!feedback) throw new Error('Not a DMARC aggregate report: no <feedback> element.');
    const meta = child(feedback, 'report_metadata');
    const policy = child(feedback, 'policy_published');
    const range = child(meta, 'date_range');
    const reporter = text(meta, 'org_name');
    const reportId = text(meta, 'report_id');
    const domain = text(policy, 'domain')?.toLowerCase();
    if (!reporter || !reportId || !domain) throw new Error('Report is missing org_name, report_id or the published domain.');

    const recordNodes = children(feedback, 'record');
    if (recordNodes.length > MAX_RECORDS) throw new Error(`Report has more than ${MAX_RECORDS} records.`);
    const records: DmarcReportRecord[] = recordNodes.map((rec) => {
        const row = child(rec, 'row');
        const evaluated = child(row, 'policy_evaluated');
        const ids = child(rec, 'identifiers');
        const auth = child(rec, 'auth_results');
        const spfEval = text(evaluated, 'spf');
        const dkimEval = text(evaluated, 'dkim');
        // The receiver's own evaluation (policy_evaluated) is authoritative for alignment;
        // auth_results carry the raw SPF / DKIM verdicts and the domains they were for.
        const dkimAuth = children(auth, 'dkim');
        const dkimPass = dkimAuth.find((d) => text(d, 'result') === 'pass') ?? dkimAuth[0];
        const spfAuth = children(auth, 'spf')[0];
        const spfAligned = spfEval === 'pass';
        const dkimAligned = dkimEval === 'pass';
        const ip = text(row, 'source_ip');
        if (!ip) throw new Error('A report record has no source_ip.');
        return {
            source_ip: ip,
            message_count: Math.max(0, Number(text(row, 'count')) || 0),
            disposition: text(evaluated, 'disposition'),
            header_from: text(ids, 'header_from')?.toLowerCase() ?? null,
            envelope_from: text(ids, 'envelope_from')?.toLowerCase() ?? null,
            spf_result: text(spfAuth, 'result'),
            spf_domain: text(spfAuth, 'domain')?.toLowerCase() ?? null,
            spf_aligned: spfAligned,
            dkim_result: dkimPass ? text(dkimPass, 'result') : null,
            dkim_domain: dkimPass ? text(dkimPass, 'domain')?.toLowerCase() ?? null : null,
            dkim_aligned: dkimAligned,
            dmarc_pass: spfAligned || dkimAligned,
        };
    });
    const pct = text(policy, 'pct');
    return {
        reporter,
        reporter_email: text(meta, 'email'),
        report_id: reportId,
        domain,
        date_begin: epoch(text(range, 'begin')),
        date_end: epoch(text(range, 'end')),
        policy_published: { p: text(policy, 'p'), sp: text(policy, 'sp'), pct: pct === null ? null : Number(pct), adkim: text(policy, 'adkim'), aspf: text(policy, 'aspf') },
        records,
        message_count: records.reduce((s, r) => s + r.message_count, 0),
        pass_count: records.reduce((s, r) => s + (r.dmarc_pass ? r.message_count : 0), 0),
    };
}
